package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client 是内置 ACME 客户端（RFC 8555 最小可用子集）：nonce 管理、JWS 签名、
// 账号注册/复用、订单与 challenge 流程都收在这里。
//
// 边界：本类型只做协议，不碰磁盘、不读配置、不写证书目录——状态与策略都在
// internal/certs 层（账户密钥 0600、审计、自动续期开关），便于单测与审计。
const (
	// defaultUserAgent 是请求 UA（CA 侧日志可识别来源，不伪装成浏览器）。
	defaultUserAgent = "kore-ssl-acme/1.0 (+https://github.com/pengtang1024/kore-plugin-ssl)"
	// maxACMEResponseBytes 是响应体读取上限（证书链也只有几 KB）。
	maxACMEResponseBytes = 2 << 20
	// nonceCacheMax 最多缓存多少个 Replay-Nonce（每个响应都会带一个，够用即可）。
	nonceCacheMax = 8
)

// Options 是客户端构造参数。AccountKey 必填（P-256）；KID 为空时由 EnsureAccount 注册。
type Options struct {
	DirectoryURL string
	HTTPClient   *http.Client
	AccountKey   *ecdsa.PrivateKey
	KID          string
	UserAgent    string
}

// Client 是 ACME 会话：绑定一个 CA 目录、一把账户密钥、一个账号 KID。
type Client struct {
	hc     *http.Client
	dir    *Directory
	dirURL string
	key    *ecdsa.PrivateKey
	kid    string
	ua     string
	nonces []string
}

// NewClient 构造客户端并拉取目录（一次 GET，不做任何账号操作）。
func NewClient(ctx context.Context, opts Options) (*Client, error) {
	if opts.AccountKey == nil {
		return nil, errf(KindInvalid, "这是内部错误：缺少账户密钥", "缺少 ACME 账户密钥")
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = newHTTPClient()
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	dir, err := fetchDirectory(ctx, hc, opts.DirectoryURL)
	if err != nil {
		return nil, err
	}
	return &Client{hc: hc, dir: dir, dirURL: opts.DirectoryURL, key: opts.AccountKey, kid: opts.KID, ua: ua}, nil
}

// Directory 返回已拉取的目录副本。
func (c *Client) Directory() Directory { return *c.dir }

// DirectoryURL 返回目录地址（审计与结果展示用）。
func (c *Client) DirectoryURL() string { return c.dirURL }

// KID 返回账号标识；空表示尚未注册/复用。
func (c *Client) KID() string { return c.kid }

// AccountKey 返回账户密钥（certs 层持久化用；不得进任何返回值）。
func (c *Client) AccountKey() *ecdsa.PrivateKey { return c.key }

// AccountPublicJWK 返回账户公钥 JWK（审计/指纹用，非敏感）。
func (c *Client) AccountPublicJWK() JWK { return JWKFromPublic(&c.key.PublicKey) }

// newAccountRequest 是 newAccount 的请求体（显式结构，不用 map）。
type newAccountRequest struct {
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed,omitempty"`
	Contact                []string        `json:"contact,omitempty"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

// EnsureAccount 注册或复用账号，返回 KID。
//
// 复用优先：先发 onlyReturnExisting=true；CA 回 accountDoesNotExist 才创建
// （termsOfServiceAgreed=true）。CA 声明 externalAccountRequired 时必须给 EAB。
func (c *Client) EnsureAccount(ctx context.Context, contact []string, eab *EAB) (string, error) {
	if c.kid != "" {
		return c.kid, nil
	}
	existing := newAccountRequest{OnlyReturnExisting: true}
	resp, body, err := c.post(ctx, c.dir.NewAccount, existing, true)
	if err == nil {
		kid := kidFromResponse(resp, body)
		if kid == "" {
			return "", errf(KindUpstream, "该 CA 的响应缺少账号地址（Location 头）；换一个 CA 或联系 CA 支持", "newAccount 成功但没有返回账号地址")
		}
		c.kid = kid
		return kid, nil
	}
	var acmeErr *Error
	if !errors.As(err, &acmeErr) || shortProblemType(acmeErr.ProblemType) != "accountDoesNotExist" {
		return "", err
	}
	if c.dir.Meta.ExternalAccountRequired && (eab == nil || eab.Kid == "" || eab.HMACKey == "") {
		return "", errf(KindInvalid,
			"该 CA 要求 EAB：在 CA 控制台创建 ACME 账号，把 eab_kid 与 eab_hmac_key 填进 ssl.acme.auto 后重试",
			"CA %s 要求 External Account Binding（LiteSSL 等商业 CA 的常见要求）", c.dirURL)
	}
	create := newAccountRequest{TermsOfServiceAgreed: true, Contact: contact}
	if eab != nil && eab.Kid != "" && eab.HMACKey != "" {
		binding, eabErr := signEAB(*eab, JWKFromPublic(&c.key.PublicKey), c.dir.NewAccount)
		if eabErr != nil {
			return "", errf(KindInvalid, "检查 eab_kid / eab_hmac_key 是否与 CA 控制台一致（hmac key 是 base64url）", "生成 EAB 失败: %v", eabErr)
		}
		create.ExternalAccountBinding = binding
	}
	resp, body, err = c.post(ctx, c.dir.NewAccount, create, true)
	if err != nil {
		return "", err
	}
	kid := kidFromResponse(resp, body)
	if kid == "" {
		return "", errf(KindUpstream, "该 CA 的响应缺少账号地址（Location 头）", "创建账号成功但未返回账号地址")
	}
	c.kid = kid
	return kid, nil
}

// kidFromResponse 取账号地址：优先 Location 头，其次响应体的 id 字段。
func kidFromResponse(resp *http.Response, body []byte) string {
	if resp != nil {
		if loc := strings.TrimSpace(resp.Header.Get("Location")); loc != "" {
			return loc
		}
	}
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		return strings.TrimSpace(payload.ID)
	}
	return ""
}

// post 发送 JWS 请求；payload 为 nil 表示 POST-as-GET。
// useJWK=true 用于账号相关请求（此时 protected header 带 jwk 而不是 kid）。
func (c *Client) post(ctx context.Context, target string, payload any, useJWK bool) (*http.Response, []byte, error) {
	return c.postAccept(ctx, target, payload, useJWK, "application/json, application/problem+json")
}

// postAccept 是 post 的可指定 Accept 版本（下载证书链时用 application/pem-certificate-chain）。
func (c *Client) postAccept(ctx context.Context, target string, payload any, useJWK bool, accept string) (*http.Response, []byte, error) {
	var raw []byte
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, errf(KindInvalid, "这是内部错误：请求体无法序列化", "序列化请求体失败: %v", err)
		}
		raw = encoded
	}
	var lastNonceErr *Error
	for attempt := 0; attempt < 2; attempt++ {
		nonce, err := c.takeNonce(ctx)
		if err != nil {
			return nil, nil, err
		}
		kid := c.kid
		if useJWK {
			kid = ""
		}
		body, err := signJWS(c.key, kid, nonce, target, raw)
		if err != nil {
			return nil, nil, errf(KindInvalid, "这是内部错误：JWS 签名失败", "JWS 签名失败: %v", err)
		}
		resp, data, err := c.doPost(ctx, target, body, accept)
		if err != nil {
			return nil, nil, err
		}
		c.rememberNonce(resp.Header)
		if resp.StatusCode < http.StatusBadRequest {
			return resp, data, nil
		}
		prob := parseProblem(data, resp.StatusCode)
		perr := newProblemError(prob)
		// badNonce 是最常见的瞬时错误：换新 nonce 重试一次（RFC 8555 §6.5 建议）。
		if shortProblemType(prob.Type) == "badNonce" && attempt == 0 {
			lastNonceErr = perr
			continue
		}
		return resp, data, perr
	}
	if lastNonceErr != nil {
		return nil, nil, lastNonceErr
	}
	return nil, nil, errf(KindUpstream, "稍后重试", "ACME 请求重试后仍失败")
}

// doPost 发送一次 POST 并读完响应体（上限 maxACMEResponseBytes）。
func (c *Client) doPost(ctx context.Context, target string, body []byte, accept string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, errf(KindInvalid, "这是内部错误：请求地址非法", "构造 ACME 请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", accept)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, errf(KindUpstream, "确认本机能访问该 CA（出站 443、DNS、代理）", "请求 %s 失败: %v", target, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxACMEResponseBytes))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, nil, errf(KindUpstream, "重试；持续失败检查网络稳定性", "读取 ACME 响应失败: %v", readErr)
	}
	return resp, data, nil
}

// takeNonce 取一个可用 nonce：优先复用响应里带的，没有就向 newNonce 要。
func (c *Client) takeNonce(ctx context.Context) (string, error) {
	if n := len(c.nonces); n > 0 {
		nonce := c.nonces[n-1]
		c.nonces = c.nonces[:n-1]
		return nonce, nil
	}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, c.dir.NewNonce, nil)
		if err != nil {
			return "", errf(KindInvalid, "检查 directory_url 的 newNonce 地址", "构造 newNonce 请求失败: %v", err)
		}
		req.Header.Set("User-Agent", c.ua)
		resp, err := c.hc.Do(req)
		if err != nil {
			return "", errf(KindUpstream, "确认本机能访问该 CA 的 newNonce（出站 443）", "获取 ACME nonce 失败: %v", err)
		}
		nonce := strings.TrimSpace(resp.Header.Get("Replay-Nonce"))
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if nonce != "" {
			return nonce, nil
		}
	}
	return "", errf(KindUpstream, "该 CA 的 newNonce 没有返回 Replay-Nonce 头：地址可能不是 ACME v2", "获取 ACME nonce 失败：响应缺少 Replay-Nonce")
}

// rememberNonce 缓存响应里的 Replay-Nonce（最多 nonceCacheMax 个）。
func (c *Client) rememberNonce(header http.Header) {
	nonce := strings.TrimSpace(header.Get("Replay-Nonce"))
	if nonce == "" {
		return
	}
	if len(c.nonces) >= nonceCacheMax {
		c.nonces = c.nonces[1:]
	}
	c.nonces = append(c.nonces, nonce)
}

// postAsGet 是 RFC 8555 §6.3 的 POST-as-GET（空 payload）。
func (c *Client) postAsGet(ctx context.Context, target string) (*http.Response, []byte, error) {
	return c.post(ctx, target, nil, false)
}

// String 便于日志（不含密钥）。
func (c *Client) String() string {
	return fmt.Sprintf("acme.Client{dir=%s kid=%s}", c.dirURL, c.kid)
}
