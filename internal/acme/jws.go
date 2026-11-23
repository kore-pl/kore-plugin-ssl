package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// JWS / JWK 实现（RFC 7515 / RFC 7638 / RFC 8555 §6）。
//
// 只实现内置 ACME 客户端需要的最小集合：
//   - 账户密钥固定 ECDSA P-256，签名算法 ES256（签名是 r||s 定长 64 字节，
//     不是 ASN.1 DER——这是 JWS 与 Go 默认 ecdsa.Sign 输出最大的差异）；
//   - JWK 指纹（RFC 7638）用于 HTTP-01 的 keyAuthorization；
//   - EAB 用 HS256：对"账户 JWK 的 JSON"做 HMAC，外层 JWS 的 payload 就是该 JWK。
const (
	sigAlgES256 = "ES256"
	sigAlgHS256 = "HS256"
	curveP256   = "P-256"
	ktyEC       = "EC"
)

// JWK 是 EC P-256 公钥的 JWK 表示。
//
// 字段顺序刻意写成 RFC 7638 规范顺序（crv、kty、x、y）：thumbprint 的哈希输入
// 必须是这个字节序，顺序错了指纹就不同，CA 会判 keyAuthorization 不匹配。
type JWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKFromPublic 把 P-256 公钥转成 JWK（x/y 为定长 32 字节 base64url）。
func JWKFromPublic(pub *ecdsa.PublicKey) JWK {
	size := (pub.Curve.Params().BitSize + 7) / 8
	return JWK{
		Crv: curveP256,
		Kty: ktyEC,
		X:   b64u(leftPad(pub.X.Bytes(), size)),
		Y:   b64u(leftPad(pub.Y.Bytes(), size)),
	}
}

// MarshalJSON 之外的派生方法：thumbprint 用 RFC 7638 的规范化 JSON（无空白、字段字典序）。
func (k JWK) thumbprintInput() []byte {
	return []byte(fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, k.Crv, k.Kty, k.X, k.Y))
}

// Thumbprint 返回 RFC 7638 JWK 指纹（base64url(SHA-256(规范化 JSON))）。
func (k JWK) Thumbprint() string {
	sum := sha256.Sum256(k.thumbprintInput())
	return b64u(sum[:])
}

// PublicKey 从 JWK 还原公钥；只接受 P-256 EC（我们只生成这一种）。
func (k JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != ktyEC || k.Crv != curveP256 {
		return nil, fmt.Errorf("只支持 EC P-256 的 JWK，得到 kty=%q crv=%q", k.Kty, k.Crv)
	}
	xb, err := b64uDecode(k.X)
	if err != nil {
		return nil, fmt.Errorf("JWK.x 解码失败: %w", err)
	}
	yb, err := b64uDecode(k.Y)
	if err != nil {
		return nil, fmt.Errorf("JWK.y 解码失败: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

// jwsHeader 是 JWS 的 protected header；jwk 与 kid 二选一（新账户用 jwk，之后用 kid）。
type jwsHeader struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce,omitempty"`
	URL   string `json:"url"`
	Kid   string `json:"kid,omitempty"`
	JWK   *JWK   `json:"jwk,omitempty"`
}

// signJWS 生成 ACME 请求体（flattened JWS）。
//
// payload 为 nil 表示 POST-as-GET（RFC 8555 §6.3）：payload 段是空串。
func signJWS(key *ecdsa.PrivateKey, kid, nonce, url string, payload []byte) ([]byte, error) {
	header := jwsHeader{Alg: sigAlgES256, Nonce: nonce, URL: url}
	if kid != "" {
		header.Kid = kid
	} else {
		jwk := JWKFromPublic(&key.PublicKey)
		header.JWK = &jwk
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("序列化 JWS header: %w", err)
	}
	signingInput := b64u(headerJSON) + "." + b64u(payload)
	sig, err := signES256(key, []byte(signingInput))
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{b64u(headerJSON), b64u(payload), b64u(sig)})
}

// signES256 输出 JWS 规定的 r||s 定长签名（64 字节）。
func signES256(key *ecdsa.PrivateKey, signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA 签名失败: %w", err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, size*2)
	copy(sig[size-len(r.Bytes()):size], r.Bytes())
	copy(sig[size*2-len(s.Bytes()):], s.Bytes())
	return sig, nil
}

// verifyES256 校验 r||s 定长签名（测试与本地自检用；客户端不信任 CA 响应体签名）。
func verifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) bool {
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != size*2 {
		return false
	}
	digest := sha256.Sum256(signingInput)
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// EAB 是 External Account Binding 凭据（部分 CA——包括 LiteSSL——强制要求）。
// HMACKey 是 CA 控制台给出的 base64url 编码密钥，属于敏感凭据：只在内存与 0600 配置里。
type EAB struct {
	Kid     string
	HMACKey string
}

// signEAB 生成 newAccount 请求里的 externalAccountBinding 字段。
//
// 结构（RFC 8555 §7.3.4）：外层 JWS 的 payload 是账户 JWK 的 JSON，
// protected header 为 {alg:"HS256", kid, url}，密钥是 HMACKey 解码后的字节。
func signEAB(eab EAB, accountJWK JWK, newAccountURL string) (json.RawMessage, error) {
	if eab.Kid == "" || eab.HMACKey == "" {
		return nil, errors.New("EAB 缺少 kid 或 hmac key")
	}
	keyBytes, err := b64uDecode(eab.HMACKey)
	if err != nil {
		return nil, fmt.Errorf("EAB hmac key 不是合法 base64url: %w", err)
	}
	headerJSON, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		URL string `json:"url"`
	}{sigAlgHS256, eab.Kid, newAccountURL})
	if err != nil {
		return nil, fmt.Errorf("序列化 EAB header: %w", err)
	}
	jwkJSON, err := json.Marshal(accountJWK)
	if err != nil {
		return nil, fmt.Errorf("序列化账户 JWK: %w", err)
	}
	signingInput := b64u(headerJSON) + "." + b64u(jwkJSON)
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	return json.Marshal(struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{b64u(headerJSON), b64u(jwkJSON), b64u(sig)})
}

// leftPad 把大整数补到定长（P-256 坐标必须 32 字节，否则 base64url 长度不固定）。
func leftPad(raw []byte, size int) []byte {
	if len(raw) >= size {
		return raw
	}
	out := make([]byte, size)
	copy(out[size-len(raw):], raw)
	return out
}
