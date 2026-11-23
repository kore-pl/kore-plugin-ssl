package acme

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// 订单与授权（RFC 8555 §7.1.3 / §7.4 / §7.5）。
const (
	// authzPollInterval 是轮询授权状态的间隔；authzTimeout 是单次授权总预算。
	authzPollInterval = 2 * time.Second
	authzTimeout      = 60 * time.Second
	// orderPollInterval / orderTimeout 用于 finalize 之后等 CA 签出证书。
	orderPollInterval = 2 * time.Second
	orderTimeout      = 120 * time.Second
	// pemCertChainType 是证书链响应的 Content-Type（RFC 8555 §7.4.2）。
	pemCertChainType = "application/pem-certificate-chain"
)

// Identifier 是 ACME 标识符（只支持 dns）。
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Order 是订单资源；URL 是订单地址（从 Location 头取，不在 JSON 里）。
type Order struct {
	URL            string       `json:"-"`
	Status         string       `json:"status"`
	Expires        string       `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
	Error          *Problem     `json:"error,omitempty"`
}

// Authorization 是授权资源。
type Authorization struct {
	Status     string      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard"`
}

// Challenge 是单个挑战；HTTP-01 的 Token 用于拼 keyAuthorization。
type Challenge struct {
	Type   string   `json:"type"`
	URL    string   `json:"url"`
	Token  string   `json:"token"`
	Status string   `json:"status"`
	Error  *Problem `json:"error,omitempty"`
}

// IssueRequest 是一次签发请求（webroot 与 CA 由 certs 层配置传入）。
type IssueRequest struct {
	Domains      []string
	Webroot      string
	KeyType      string
	Contact      []string
	EAB          *EAB
	SkipPrecheck bool
	// PrecheckPort 覆盖预检端口（默认 80；仅测试/特殊环境需要）。
	PrecheckPort int
	// PrecheckHost 覆盖预检时使用的主机名（默认用域名本身）。
	// 用于分域 DNS / 本机无法回环解析自己公网域名的环境，以及本地测试替身。
	PrecheckHost string
}

// IssueResult 是签发结果：证书链 PEM + 私钥 PEM + 叶子证书元数据。
type IssueResult struct {
	CertPEM     []byte
	KeyPEM      []byte
	NotAfter    time.Time
	ChainLength int
	OrderURL    string
}

// Issue 执行完整 HTTP-01 签发流程：
// 账号 → 订单 → 每个授权写 token + 预检 + 触发 + 轮询 → CSR + finalize → 轮询 → 下载证书链。
// 无论成功失败，临时 token 文件都会被清理。
func (c *Client) Issue(ctx context.Context, req IssueRequest) (*IssueResult, error) {
	domains, err := NormalizeDomains(req.Domains)
	if err != nil {
		return nil, err
	}
	if err := ensureWebroot(req.Webroot); err != nil {
		return nil, err
	}
	if _, err := c.EnsureAccount(ctx, req.Contact, req.EAB); err != nil {
		return nil, err
	}
	key, keyPEM, err := GenerateCertKey(req.KeyType)
	if err != nil {
		return nil, err
	}
	order, orderURL, err := c.newOrder(ctx, domains)
	if err != nil {
		return nil, err
	}
	var challengeFiles []string
	defer func() {
		for _, path := range challengeFiles {
			_ = removeChallenge(path)
		}
	}()
	for _, authzURL := range order.Authorizations {
		path, err := c.authorize(ctx, authzURL, req)
		// 先登记再判错：失败路径同样要清理已写出的 token 文件。
		if path != "" {
			challengeFiles = append(challengeFiles, path)
		}
		if err != nil {
			return nil, err
		}
	}
	csr, err := BuildCSR(key, domains)
	if err != nil {
		return nil, err
	}
	if err := c.finalize(ctx, order.Finalize, csr); err != nil {
		return nil, err
	}
	finalOrder, err := c.waitOrder(ctx, orderURL)
	if err != nil {
		return nil, err
	}
	if finalOrder.Certificate == "" {
		return nil, errf(KindUpstream, "CA 未返回证书地址：稍后重试，或在 ssl.acme.builtin.status 查看审计", "订单已 valid 但没有 certificate 地址")
	}
	certPEM, leaf, chainLen, err := c.downloadCertificate(ctx, finalOrder.Certificate)
	if err != nil {
		return nil, err
	}
	return &IssueResult{CertPEM: certPEM, KeyPEM: keyPEM, NotAfter: leaf.NotAfter, ChainLength: chainLen, OrderURL: orderURL}, nil
}

// newOrder 提交订单并返回订单体与订单地址。
func (c *Client) newOrder(ctx context.Context, domains []string) (*Order, string, error) {
	identifiers := make([]Identifier, 0, len(domains))
	for _, domain := range domains {
		identifiers = append(identifiers, Identifier{Type: "dns", Value: domain})
	}
	payload := struct {
		Identifiers []Identifier `json:"identifiers"`
	}{identifiers}
	resp, body, err := c.post(ctx, c.dir.NewOrder, payload, false)
	if err != nil {
		return nil, "", err
	}
	order, err := decodeOrder(body)
	if err != nil {
		return nil, "", err
	}
	order.URL = strings.TrimSpace(resp.Header.Get("Location"))
	if order.URL == "" {
		return nil, "", errf(KindUpstream, "该 CA 的 newOrder 响应缺少 Location 头", "newOrder 成功但没有返回订单地址")
	}
	return order, order.URL, nil
}

// authorize 处理一个授权：写 token → 预检 → 触发 challenge → 轮询到 valid。
// 返回写入的 token 文件路径（供调用方统一清理）。
func (c *Client) authorize(ctx context.Context, authzURL string, req IssueRequest) (string, error) {
	authz, err := c.getAuthz(ctx, authzURL)
	if err != nil {
		return "", err
	}
	switch authz.Status {
	case "valid":
		return "", nil
	case "invalid":
		return "", challengeFailure(authz, "")
	}
	challenge, ok := pickHTTP01(authz)
	if !ok {
		return "", errf(KindUnsupported,
			"本客户端只支持 HTTP-01（DNS-01 未实现）：换一个提供 http-01 的 CA 或等 v1.1",
			"授权 %s 没有 http-01 挑战", authz.Identifier.Value)
	}
	keyAuth := challenge.Token + "." + JWKFromPublic(&c.key.PublicKey).Thumbprint()
	path, err := writeChallenge(req.Webroot, challenge.Token, keyAuth)
	if err != nil {
		return "", err
	}
	if !req.SkipPrecheck {
		precheckHost := req.PrecheckHost
		if precheckHost == "" {
			precheckHost = authz.Identifier.Value
		}
		if err := c.precheck(precheckHost, challenge.Token, keyAuth, req.PrecheckPort); err != nil {
			_ = removeChallenge(path)
			return "", err
		}
	}
	// 通知 CA 开始校验（RFC 8555 §7.5.1：payload 为空对象）。
	if _, _, err := c.post(ctx, challenge.URL, struct{}{}, false); err != nil {
		_ = removeChallenge(path)
		return "", err
	}
	deadline := time.Now().Add(authzTimeout)
	for {
		authz, err = c.getAuthz(ctx, authzURL)
		if err != nil {
			return path, err
		}
		switch authz.Status {
		case "valid":
			return path, nil
		case "invalid":
			return path, challengeFailure(authz, keyAuth)
		}
		if time.Now().After(deadline) {
			return path, errf(KindUpstream,
				"HTTP-01 校验超时：确认域名 A/AAAA 指向本机公网 IP、80 端口可达、webroot 是该域名站点根目录、防火墙放行 80",
				"等待授权 %s 超时（%s）", authz.Identifier.Value, authzTimeout)
		}
		if err := sleepCtx(ctx, authzPollInterval); err != nil {
			return path, errf(KindUpstream, "请求被取消或超时", "等待授权时上下文结束: %v", err)
		}
	}
}

// getAuthz 用 POST-as-GET 取授权。
func (c *Client) getAuthz(ctx context.Context, authzURL string) (*Authorization, error) {
	_, body, err := c.postAsGet(ctx, authzURL)
	if err != nil {
		return nil, err
	}
	var authz Authorization
	if err := decodeJSON(body, &authz); err != nil {
		return nil, errf(KindUpstream, "该 CA 的响应不是合法 JSON", "解析授权失败: %v", err)
	}
	return &authz, nil
}

// pickHTTP01 从授权里挑出 http-01 挑战。
func pickHTTP01(authz *Authorization) (Challenge, bool) {
	for _, challenge := range authz.Challenges {
		if challenge.Type == "http-01" {
			return challenge, true
		}
	}
	return Challenge{}, false
}

// challengeFailure 把 invalid 授权里的 challenge 错误转成可操作错误。
func challengeFailure(authz *Authorization, keyAuth string) error {
	for _, challenge := range authz.Challenges {
		if challenge.Status != "invalid" || challenge.Error == nil {
			continue
		}
		prob := *challenge.Error
		wrapped := newProblemError(prob)
		detail := wrapped.Detail
		if keyAuth != "" {
			detail += "（本次 keyAuthorization 已写入 webroot/.well-known/acme-challenge/，请确认站点能原样返回该文件）"
		}
		return &Error{
			Kind: KindInvalid, ProblemType: prob.Type, Detail: detail,
			Hint: "HTTP-01 校验失败：域名需公网解析到本机、80 端口可达、站点根目录就是 webroot、" +
				"且未拦截 /.well-known/acme-challenge/ 路径；失败后清理 token 文件重试",
		}
	}
	return errf(KindInvalid,
		"到 CA 控制台确认域名状态；或先用 letsencrypt-staging 重试以排除生产配额问题",
		"授权 %s 被判定为 invalid（CA 未给出具体 challenge 错误）", authz.Identifier.Value)
}

// finalize 提交 CSR。
func (c *Client) finalize(ctx context.Context, finalizeURL string, csrDER []byte) error {
	payload := struct {
		CSR string `json:"csr"`
	}{CSR: b64u(csrDER)}
	_, _, err := c.post(ctx, finalizeURL, payload, false)
	return err
}

// waitOrder 轮询订单直到 valid；invalid 时返回订单错误。
func (c *Client) waitOrder(ctx context.Context, orderURL string) (*Order, error) {
	deadline := time.Now().Add(orderTimeout)
	for {
		_, body, err := c.postAsGet(ctx, orderURL)
		if err != nil {
			return nil, err
		}
		var order Order
		if err := decodeJSON(body, &order); err != nil {
			return nil, errf(KindUpstream, "该 CA 的响应不是合法 JSON", "解析订单失败: %v", err)
		}
		order.URL = orderURL
		switch order.Status {
		case "valid":
			return &order, nil
		case "invalid":
			if order.Error != nil {
				return nil, newProblemError(*order.Error)
			}
			return nil, errf(KindInvalid, "订单被 CA 拒绝：到 CA 控制台确认域名与账号状态", "订单 %s 状态为 invalid", orderURL)
		}
		if time.Now().After(deadline) {
			return nil, errf(KindUpstream, "CA 签发耗时过长：稍后重试；连续超时换一个 CA 或用 staging 验证", "等待订单 valid 超时（%s）", orderTimeout)
		}
		if err := sleepCtx(ctx, orderPollInterval); err != nil {
			return nil, errf(KindUpstream, "请求被取消或超时", "等待订单时上下文结束: %v", err)
		}
	}
}

// downloadCertificate 下载 PEM 证书链（POST-as-GET + Accept: application/pem-certificate-chain）。
func (c *Client) downloadCertificate(ctx context.Context, certURL string) ([]byte, *x509.Certificate, int, error) {
	_, body, err := c.postAccept(ctx, certURL, nil, false, pemCertChainType)
	if err != nil {
		return nil, nil, 0, err
	}
	leaf, chainLen, err := parsePEMChain(body)
	if err != nil {
		return nil, nil, 0, err
	}
	return body, leaf, chainLen, nil
}

// parsePEMChain 解析证书链：返回叶子证书与证书总数（含叶子）。
func parsePEMChain(raw []byte) (*x509.Certificate, int, error) {
	rest := raw
	var leaf *x509.Certificate
	count := 0
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, errf(KindUpstream, "CA 返回的证书链无法解析：换一个 CA 或联系 CA 支持", "解析证书链失败: %v", err)
		}
		if leaf == nil {
			leaf = cert
		}
		count++
	}
	if leaf == nil {
		return nil, 0, errf(KindUpstream, "CA 返回的内容不是 PEM 证书：确认 CA 的证书端点正常", "证书链里没有 CERTIFICATE 块")
	}
	return leaf, count, nil
}

// decodeOrder / decodeJSON 是小工具：统一错误文案。
func decodeOrder(body []byte) (*Order, error) {
	var order Order
	if err := decodeJSON(body, &order); err != nil {
		return nil, errf(KindUpstream, "该 CA 的响应不是合法 JSON", "解析订单失败: %v", err)
	}
	return &order, nil
}

func decodeJSON(body []byte, dst any) error {
	if len(body) == 0 {
		return errors.New("空响应体")
	}
	return json.Unmarshal(body, dst)
}

// sleepCtx 是可用 ctx 取消的等待（G-19：用可 Stop 的 time.Timer，不用 time.After）。
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
