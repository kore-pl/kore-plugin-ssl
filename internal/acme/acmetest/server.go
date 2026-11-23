package acmetest

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/acme"
)

// Options 控制 mock CA 的行为与故障注入。
type Options struct {
	// Webroot 是 challenge 校验读取 token 的站点根（为空时只按 token 名匹配，不校验内容）。
	Webroot string
	// RequireEAB 让 newAccount 强制要求 External Account Binding。
	RequireEAB bool
	EABKid     string
	EABHMACKey string // base64url
	// 故障注入（每次测试按需打开）。
	BadNonceOnce     bool
	ChallengeInvalid bool
	FinalizeReject   bool
	CertDownloadFail bool
	RateLimitOrder   bool
}

type account struct {
	JWK        acme.JWK
	Thumbprint string
}

type orderRec struct {
	ID               string
	Status           string
	Identifiers      []acme.Identifier
	AuthorizationIDs []string
	OwnerThumb       string
	CertPEM          []byte
}

type challengeRec struct {
	ID     string
	Token  string
	Status string
	Error  *acme.Problem
}

type authzRec struct {
	ID         string
	Domain     string
	Status     string
	Challenges []*challengeRec
}

// Server 是本地 ACME CA 替身。
type Server struct {
	*httptest.Server
	opts Options
	ca   *testCA
	t    testing.TB

	mu            sync.Mutex
	nonces        map[string]struct{}
	accounts      map[string]*account // kid(URL) → account
	orders        map[string]*orderRec
	authzs        map[string]*authzRec
	certs         map[string][]byte
	seq           int
	badNonceFired bool

	requests   int64
	challenges int64
}

// New 启动本地 ACME 替身并注册清理。
func New(t testing.TB, opts Options) *Server {
	t.Helper()
	s := &Server{
		opts:     opts,
		ca:       newTestCA(t),
		t:        t,
		nonces:   make(map[string]struct{}),
		accounts: make(map[string]*account),
		orders:   make(map[string]*orderRec),
		authzs:   make(map[string]*authzRec),
		certs:    make(map[string][]byte),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", s.handleDirectory)
	mux.HandleFunc("/new-nonce", s.handleNonce)
	mux.HandleFunc("/new-account", s.handleNewAccount)
	mux.HandleFunc("/new-order", s.handleNewOrder)
	mux.HandleFunc("/order/", s.handleOrder)
	mux.HandleFunc("/authz/", s.handleAuthz)
	mux.HandleFunc("/challenge/", s.handleChallenge)
	mux.HandleFunc("/finalize/", s.handleFinalize)
	mux.HandleFunc("/cert/", s.handleCert)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&s.requests, 1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// DirectoryURL 返回目录地址（供客户端/配置使用）。
func (s *Server) DirectoryURL() string { return s.URL + "/directory" }

// Requests 返回累计收到的 HTTP 请求数（"禁用自动续期时零联网"的断言依据）。
func (s *Server) Requests() int64 { return atomic.LoadInt64(&s.requests) }

// ChallengeAttempts 返回被触发的 challenge 次数。
func (s *Server) ChallengeAttempts() int64 { return atomic.LoadInt64(&s.challenges) }

// baseURL 用请求 Host 拼绝对地址（mock 只跑在回环 http 上）。
func baseURL(r *http.Request) string { return "http://" + r.Host }

// requestURL 是 JWS header.url 必须等于的可请求地址。
func requestURL(r *http.Request) string { return "http://" + r.Host + r.URL.Path }

// --- 目录与 nonce ---

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	base := baseURL(r)
	meta := map[string]any{"termsOfService": base + "/terms", "website": "https://example.test"}
	if s.opts.RequireEAB {
		meta["externalAccountRequired"] = true
	}
	body := map[string]any{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		"newOrder":   base + "/new-order",
		"revokeCert": base + "/revoke-cert",
		"keyChange":  base + "/key-change",
		"meta":       meta,
	}
	writeJSON(w, http.StatusOK, body, s.newNonce())
}

func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		writeProblem(w, http.StatusMethodNotAllowed, "malformed", "newNonce 只接受 HEAD/GET", s.newNonce())
		return
	}
	w.Header().Set("Replay-Nonce", s.newNonce())
	w.WriteHeader(http.StatusOK)
}

// --- JWS 校验 ---

type jwsBody struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type protectedHeader struct {
	Alg   string    `json:"alg"`
	Nonce string    `json:"nonce"`
	URL   string    `json:"url"`
	Kid   string    `json:"kid"`
	JWK   *acme.JWK `json:"jwk"`
}

// authenticate 完成 RFC 8555 §6.2 的校验：alg、url、nonce、签名。
// 返回 payload、protected header 与账号指纹；失败时已写好 problem 响应。
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) ([]byte, protectedHeader, string, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", "读请求体失败", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	var jws jwsBody
	if err := json.Unmarshal(body, &jws); err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", "请求体不是 JWS", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	headerRaw, err := b64decode(jws.Protected)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", "protected 不是 base64url", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	var header protectedHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", "protected 不是 JSON", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	if header.Alg != "ES256" {
		writeProblem(w, http.StatusBadRequest, "badSignatureAlgorithm", "只支持 ES256", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	if want := requestURL(r); header.URL != want {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", fmt.Sprintf("JWS url=%q 与请求 %q 不一致", header.URL, want), s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	if !s.consumeNonce(header.Nonce) {
		writeProblem(w, http.StatusBadRequest, "badNonce", "nonce 无效或已使用", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	var pub *ecdsa.PublicKey
	var thumb string
	switch {
	case header.JWK != nil:
		key, err := header.JWK.PublicKey()
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "malformed", "jwk 无法解析: "+err.Error(), s.newNonce())
			return nil, protectedHeader{}, "", false
		}
		pub = key
		thumb = header.JWK.Thumbprint()
	case header.Kid != "":
		s.mu.Lock()
		acct := s.accounts[header.Kid]
		s.mu.Unlock()
		if acct == nil {
			writeProblem(w, http.StatusBadRequest, "accountDoesNotExist", "kid 未注册", s.newNonce())
			return nil, protectedHeader{}, "", false
		}
		key, err := acct.JWK.PublicKey()
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "malformed", "账号公钥不可用", s.newNonce())
			return nil, protectedHeader{}, "", false
		}
		pub = key
		thumb = acct.Thumbprint
	default:
		writeProblem(w, http.StatusBadRequest, "malformed", "protected 必须带 jwk 或 kid", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	sig, err := b64decode(jws.Signature)
	if err != nil || !verifyES256(pub, []byte(jws.Protected+"."+jws.Payload), sig) {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "JWS 签名校验失败", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	payload, err := b64decode(jws.Payload)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", "payload 不是 base64url", s.newNonce())
		return nil, protectedHeader{}, "", false
	}
	return payload, header, thumb, true
}

// --- 账号 ---

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	payload, header, thumb, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
		TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
		Contact                []string        `json:"contact"`
		ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", "newAccount payload 非法", s.newNonce())
		return
	}
	lookupKID := func() string {
		s.mu.Lock()
		defer s.mu.Unlock()
		for kid, acct := range s.accounts {
			if acct.Thumbprint == thumb {
				return kid
			}
		}
		return ""
	}
	if kid := lookupKID(); kid != "" {
		w.Header().Set("Location", kid)
		writeJSON(w, http.StatusOK, map[string]string{"status": "valid"}, s.newNonce())
		return
	}
	if req.OnlyReturnExisting {
		writeProblem(w, http.StatusBadRequest, "accountDoesNotExist", "账号不存在", s.newNonce())
		return
	}
	if header.JWK == nil {
		writeProblem(w, http.StatusBadRequest, "malformed", "创建账号必须用 jwk 签名", s.newNonce())
		return
	}
	if s.opts.RequireEAB {
		if err := s.verifyEAB(req.ExternalAccountBinding, *header.JWK, requestURL(r)); err != nil {
			writeProblem(w, http.StatusUnauthorized, "externalAccountRequired", "EAB 校验失败: "+err.Error(), s.newNonce())
			return
		}
	}
	s.mu.Lock()
	s.seq++
	kid := baseURL(r) + "/account/" + strconv.Itoa(s.seq)
	s.accounts[kid] = &account{JWK: *header.JWK, Thumbprint: thumb}
	s.mu.Unlock()
	w.Header().Set("Location", kid)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "valid"}, s.newNonce())
}

// verifyEAB 校验外部账号绑定的 HMAC 签名与 JWK 一致性。
func (s *Server) verifyEAB(raw json.RawMessage, accountJWK acme.JWK, newAccountURL string) error {
	if len(raw) == 0 {
		return fmt.Errorf("缺少 externalAccountBinding")
	}
	var binding jwsBody
	if err := json.Unmarshal(raw, &binding); err != nil {
		return fmt.Errorf("externalAccountBinding 不是 JWS")
	}
	headerRaw, err := b64decode(binding.Protected)
	if err != nil {
		return fmt.Errorf("EAB protected 不是 base64url")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return fmt.Errorf("EAB protected 不是 JSON")
	}
	if header.Alg != "HS256" || header.Kid != s.opts.EABKid || header.URL != newAccountURL {
		return fmt.Errorf("EAB header 不匹配（alg/kid/url）")
	}
	key, err := b64decode(s.opts.EABHMACKey)
	if err != nil {
		return fmt.Errorf("mock EAB key 非法")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(binding.Protected + "." + binding.Payload))
	sig, err := b64decode(binding.Signature)
	if err != nil || !hmac.Equal(mac.Sum(nil), sig) {
		return fmt.Errorf("EAB 签名不匹配")
	}
	payloadJWK, err := b64decode(binding.Payload)
	if err != nil {
		return fmt.Errorf("EAB payload 不是 base64url")
	}
	var inner acme.JWK
	if err := json.Unmarshal(payloadJWK, &inner); err != nil {
		return fmt.Errorf("EAB payload 不是 JWK")
	}
	if inner.Thumbprint() != accountJWK.Thumbprint() {
		return fmt.Errorf("EAB 绑定的 JWK 与账号不一致")
	}
	return nil
}

// --- 订单 ---

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	if s.opts.BadNonceOnce {
		s.mu.Lock()
		fired := s.badNonceFired
		s.badNonceFired = true
		s.mu.Unlock()
		if !fired {
			writeProblem(w, http.StatusBadRequest, "badNonce", "注入的 badNonce", s.newNonce())
			return
		}
	}
	payload, _, thumb, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.opts.RateLimitOrder {
		writeProblem(w, http.StatusTooManyRequests, "rateLimited", "too many certificates already issued", s.newNonce())
		return
	}
	var req struct {
		Identifiers []acme.Identifier `json:"identifiers"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || len(req.Identifiers) == 0 {
		writeProblem(w, http.StatusBadRequest, "malformed", "newOrder 缺少 identifiers", s.newNonce())
		return
	}
	s.mu.Lock()
	s.seq++
	orderID := strconv.Itoa(s.seq)
	order := &orderRec{ID: orderID, Status: "pending", Identifiers: req.Identifiers, OwnerThumb: thumb}
	base := baseURL(r)
	for index, ident := range req.Identifiers {
		authzID := orderID + "-" + strconv.Itoa(index)
		challenge := &challengeRec{ID: authzID + "-c0", Token: "tok" + orderID + strconv.Itoa(index) + "abcdef", Status: "pending"}
		authz := &authzRec{ID: authzID, Domain: ident.Value, Status: "pending", Challenges: []*challengeRec{challenge}}
		s.authzs[authzID] = authz
		order.AuthorizationIDs = append(order.AuthorizationIDs, authzID)
	}
	s.orders[orderID] = order
	s.mu.Unlock()
	w.Header().Set("Location", base+"/order/"+orderID)
	writeJSON(w, http.StatusCreated, s.orderJSON(order, base), s.newNonce())
}

// orderJSON 渲染订单（URL 由 base 拼绝对地址）。
func (s *Server) orderJSON(order *orderRec, base string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	authzURLs := make([]string, 0, len(order.AuthorizationIDs))
	for _, id := range order.AuthorizationIDs {
		authzURLs = append(authzURLs, base+"/authz/"+id)
	}
	body := map[string]any{
		"status":         order.Status,
		"identifiers":    order.Identifiers,
		"authorizations": authzURLs,
		"finalize":       base + "/finalize/" + order.ID,
	}
	if order.Status == "valid" {
		body["certificate"] = base + "/cert/" + order.ID
	}
	return body
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := s.authenticate(w, r); !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/order/")
	s.mu.Lock()
	order := s.orders[id]
	s.mu.Unlock()
	if order == nil {
		writeProblem(w, http.StatusNotFound, "malformed", "订单不存在", s.newNonce())
		return
	}
	writeJSON(w, http.StatusOK, s.orderJSON(order, baseURL(r)), s.newNonce())
}

// --- 授权与 challenge ---

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := s.authenticate(w, r); !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	s.mu.Lock()
	authz := s.authzs[id]
	s.mu.Unlock()
	if authz == nil {
		writeProblem(w, http.StatusNotFound, "malformed", "授权不存在", s.newNonce())
		return
	}
	writeJSON(w, http.StatusOK, s.authzJSON(authz, baseURL(r)), s.newNonce())
}

// authzJSON 渲染授权：HTTP-01 挑战 + 当前状态。
func (s *Server) authzJSON(authz *authzRec, base string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	challenges := make([]map[string]any, 0, len(authz.Challenges))
	for _, ch := range authz.Challenges {
		item := map[string]any{
			"type":   "http-01",
			"url":    base + "/challenge/" + ch.ID,
			"token":  ch.Token,
			"status": ch.Status,
		}
		if ch.Error != nil {
			item["error"] = ch.Error
		}
		challenges = append(challenges, item)
	}
	return map[string]any{
		"status":     authz.Status,
		"identifier": acme.Identifier{Type: "dns", Value: authz.Domain},
		"challenges": challenges,
	}
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	_, _, thumb, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	atomic.AddInt64(&s.challenges, 1)
	id := strings.TrimPrefix(r.URL.Path, "/challenge/")
	s.mu.Lock()
	var target *authzRec
	var challenge *challengeRec
	for _, authz := range s.authzs {
		for _, ch := range authz.Challenges {
			if ch.ID == id {
				target = authz
				challenge = ch
			}
		}
	}
	s.mu.Unlock()
	if target == nil || challenge == nil {
		writeProblem(w, http.StatusNotFound, "malformed", "challenge 不存在", s.newNonce())
		return
	}
	if s.opts.ChallengeInvalid {
		s.invalidate(target, challenge, "mock 注入：challenge 校验失败")
		writeJSON(w, http.StatusOK, s.challengeJSON(challenge, baseURL(r)), s.newNonce())
		return
	}
	keyAuth, err := s.readKeyAuth(challenge.Token)
	if err != nil {
		s.invalidate(target, challenge, "读取 webroot token 失败: "+err.Error())
		writeJSON(w, http.StatusOK, s.challengeJSON(challenge, baseURL(r)), s.newNonce())
		return
	}
	want := challenge.Token + "." + thumb
	if keyAuth != want {
		s.invalidate(target, challenge, fmt.Sprintf("keyAuthorization 不匹配（期望 %s.*，实际 %q）", challenge.Token, keyAuth))
		writeJSON(w, http.StatusOK, s.challengeJSON(challenge, baseURL(r)), s.newNonce())
		return
	}
	s.mu.Lock()
	challenge.Status = "valid"
	target.Status = "valid"
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.challengeJSON(challenge, baseURL(r)), s.newNonce())
}

// readKeyAuth 从 webroot 读 token 文件（未配置 webroot 时退化为"只校验存在"）。
func (s *Server) readKeyAuth(token string) (string, error) {
	if s.opts.Webroot == "" {
		return token, nil
	}
	path := filepath.Join(s.opts.Webroot, ".well-known", "acme-challenge", token)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// invalidate 把 challenge 与授权置为 invalid。
func (s *Server) invalidate(authz *authzRec, challenge *challengeRec, detail string) {
	prob := &acme.Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: detail, Status: http.StatusForbidden}
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge.Status = "invalid"
	challenge.Error = prob
	authz.Status = "invalid"
}

func (s *Server) challengeJSON(challenge *challengeRec, base string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	body := map[string]any{
		"type":   "http-01",
		"url":    base + "/challenge/" + challenge.ID,
		"token":  challenge.Token,
		"status": challenge.Status,
	}
	if challenge.Error != nil {
		body["error"] = challenge.Error
	}
	return body
}

// --- finalize 与证书下载 ---

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	payload, _, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if s.opts.FinalizeReject {
		writeProblem(w, http.StatusForbidden, "badCSR", "mock 注入：CSR 被拒绝", s.newNonce())
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/finalize/")
	s.mu.Lock()
	order := s.orders[id]
	s.mu.Unlock()
	if order == nil {
		writeProblem(w, http.StatusNotFound, "malformed", "订单不存在", s.newNonce())
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.CSR == "" {
		writeProblem(w, http.StatusBadRequest, "badCSR", "缺少 csr", s.newNonce())
		return
	}
	der, err := b64decode(req.CSR)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "badCSR", "csr 不是 base64url", s.newNonce())
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		writeProblem(w, http.StatusBadRequest, "badCSR", "csr 解析或签名失败", s.newNonce())
		return
	}
	if len(csr.DNSNames) != len(order.Identifiers) {
		writeProblem(w, http.StatusBadRequest, "badCSR", "csr 域名数量与订单不一致", s.newNonce())
		return
	}
	certPEM := s.ca.issue(s.t, csr)
	s.mu.Lock()
	order.Status = "valid"
	order.CertPEM = certPEM
	s.certs[id] = certPEM
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.orderJSON(order, baseURL(r)), s.newNonce())
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if _, _, _, ok := s.authenticate(w, r); !ok {
		return
	}
	if s.opts.CertDownloadFail {
		writeProblem(w, http.StatusInternalServerError, "serverInternal", "mock 注入：证书下载失败", s.newNonce())
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/cert/")
	s.mu.Lock()
	certPEM := s.certs[id]
	s.mu.Unlock()
	if len(certPEM) == 0 {
		writeProblem(w, http.StatusNotFound, "malformed", "证书不存在", s.newNonce())
		return
	}
	w.Header().Set("Replay-Nonce", s.newNonce())
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(certPEM)
}

// --- nonce / 响应工具 ---

// newNonce 生成并登记一个 nonce。
func (s *Server) newNonce() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	nonce := "nonce-" + strconv.Itoa(s.seq)
	s.nonces[nonce] = struct{}{}
	return nonce
}

// consumeNonce 消费一个 nonce（一次性）。
func (s *Server) consumeNonce(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nonces[nonce]; !ok {
		return false
	}
	delete(s.nonces, nonce)
	return true
}

// writeJSON 写 JSON 响应并带 Replay-Nonce。
func writeJSON(w http.ResponseWriter, status int, body any, nonce string) {
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeProblem 写 RFC 8555 错误体（type 自动补 URN 前缀）并带 Replay-Nonce。
func writeProblem(w http.ResponseWriter, status int, kind, detail, nonce string) {
	body := acme.Problem{Type: "urn:ietf:params:acme:error:" + kind, Detail: detail, Status: status}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// verifyES256 校验 r||s 定长签名（mock 侧独立实现，不依赖被测代码）。
func verifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) bool {
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != size*2 {
		return false
	}
	digest := sha256.Sum256(signingInput)
	r := new(big.Int).SetBytes(sig[:size])
	sv := new(big.Int).SetBytes(sig[size:])
	return ecdsa.Verify(pub, digest[:], r, sv)
}

// b64decode 解码 base64url（无填充）。
func b64decode(raw string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(raw)
}

// 编译期使用 encoding/pem（证书链 PEM 在 ca.go / 最终响应里使用）。
var _ = pem.EncodeToMemory
