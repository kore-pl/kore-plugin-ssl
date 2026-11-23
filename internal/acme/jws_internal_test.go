package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

// fixedJWK 是固定向量（x/y 为 1..32、33..64 字节），用于锁死 RFC 7638 指纹。
const (
	fixedJWKX = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	fixedJWKY = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A"
	// fixedThumbprint 由独立实现（Python: sha256(canonical JSON) → base64url）算出，
	// 不是用被测代码自证。
	fixedThumbprint = "t1ZI8tOt77KZ9YepYcUiqtqXcpIYInMJhkFb6casAFo"
)

// TestJWKThumbprintVector 锁死 RFC 7638 规范化 JSON 与 base64url 编码。
func TestJWKThumbprintVector(t *testing.T) {
	jwk := JWK{Crv: curveP256, Kty: ktyEC, X: fixedJWKX, Y: fixedJWKY}
	if got := jwk.Thumbprint(); got != fixedThumbprint {
		t.Fatalf("thumbprint=%q，期望 %q（规范化 JSON 或编码方式变了）", got, fixedThumbprint)
	}
	canonical := string(jwk.thumbprintInput())
	if !strings.HasPrefix(canonical, `{"crv":"P-256","kty":"EC","x":`) {
		t.Fatalf("规范化 JSON 字段顺序必须是 crv/kty/x/y，实际 %s", canonical)
	}
}

// TestJWKRoundTrip 验证 JWK → 公钥 → JWK 一致。
func TestJWKRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	jwk := JWKFromPublic(&key.PublicKey)
	pub, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("还原公钥失败: %v", err)
	}
	if JWKFromPublic(pub).Thumbprint() != jwk.Thumbprint() {
		t.Fatal("JWK 往返后指纹不一致")
	}
	if len(jwk.X) != 43 || len(jwk.Y) != 43 {
		t.Fatalf("P-256 坐标应为 32 字节（base64url 43 字符），实际 x=%d y=%d", len(jwk.X), len(jwk.Y))
	}
}

// TestSignJWSES256RawSignature 验证 JWS 结构、header 字段与 r||s 定长签名（64 字节）。
func TestSignJWSES256RawSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	body, err := signJWS(key, "", "nonce-1", "https://ca.test/new-account", []byte(`{"onlyReturnExisting":true}`))
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		t.Fatalf("JWS 不是 JSON: %v", err)
	}
	headerRaw, err := b64uDecode(jws.Protected)
	if err != nil {
		t.Fatalf("protected 不是 base64url: %v", err)
	}
	var header jwsHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		t.Fatalf("protected 不是 JSON: %v", err)
	}
	if header.Alg != sigAlgES256 || header.Nonce != "nonce-1" || header.URL != "https://ca.test/new-account" {
		t.Fatalf("header 字段不符: %+v", header)
	}
	if header.JWK == nil || header.Kid != "" {
		t.Fatalf("无 kid 时必须带 jwk: %+v", header)
	}
	sig, err := b64uDecode(jws.Signature)
	if err != nil {
		t.Fatalf("signature 不是 base64url: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("ES256 签名应为 r||s 64 字节，实际 %d", len(sig))
	}
	if !verifyES256(&key.PublicKey, []byte(jws.Protected+"."+jws.Payload), sig) {
		t.Fatal("签名自校验失败")
	}

	// 带 kid 的请求不得再带 jwk（RFC 8555 §6.2）。
	body, err = signJWS(key, "https://ca.test/account/1", "nonce-2", "https://ca.test/new-order", nil)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	_ = json.Unmarshal(body, &jws)
	headerRaw, _ = b64uDecode(jws.Protected)
	var kidHeader jwsHeader
	_ = json.Unmarshal(headerRaw, &kidHeader)
	if kidHeader.Kid == "" || kidHeader.JWK != nil {
		t.Fatalf("有 kid 时不得带 jwk: %+v", kidHeader)
	}
	if jws.Payload != "" {
		t.Fatalf("POST-as-GET 的 payload 必须是空串，实际 %q", jws.Payload)
	}
}

// TestSignEABVector 用固定密钥锁死 EAB 的 HS256 签名（独立实现算出的期望值）。
func TestSignEABVector(t *testing.T) {
	jwk := JWK{Crv: curveP256, Kty: ktyEC, X: fixedJWKX, Y: fixedJWKY}
	raw, err := signEAB(EAB{Kid: "eab-kid-1", HMACKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}, jwk, "https://ca.test/new-account")
	if err != nil {
		t.Fatalf("EAB 签名失败: %v", err)
	}
	var binding struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &binding); err != nil {
		t.Fatalf("EAB 不是 JWS: %v", err)
	}
	// 期望签名由独立实现（Python hmac-sha256(固定 key, protected.payload)）算出。
	const wantSig = "VhX_ov4UyfZeZoRGuVHnjD1BMgiVizUTpO4e-7LjLgU"
	if binding.Signature != wantSig {
		t.Fatalf("EAB 签名=%q，期望 %q", binding.Signature, wantSig)
	}
	headerRaw, _ := b64uDecode(binding.Protected)
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		URL string `json:"url"`
	}
	_ = json.Unmarshal(headerRaw, &header)
	if header.Alg != sigAlgHS256 || header.Kid != "eab-kid-1" || header.URL != "https://ca.test/new-account" {
		t.Fatalf("EAB header 不符: %+v", header)
	}
	payload, _ := b64uDecode(binding.Payload)
	var inner JWK
	if err := json.Unmarshal(payload, &inner); err != nil {
		t.Fatalf("EAB payload 应是 JWK: %v", err)
	}
	if inner.Thumbprint() != jwk.Thumbprint() {
		t.Fatal("EAB payload 里的 JWK 与账户不一致")
	}
}

// TestEABRejectsBadKey 验证非法 hmac key 给出明确错误而不是 panic。
func TestEABRejectsBadKey(t *testing.T) {
	if _, err := signEAB(EAB{Kid: "k", HMACKey: "!!!"}, JWK{}, "https://ca.test"); err == nil {
		t.Fatal("非法 hmac key 应报错")
	}
	if _, err := signEAB(EAB{}, JWK{}, "https://ca.test"); err == nil {
		t.Fatal("缺 kid/hmac 应报错")
	}
}

// TestBuildCSRSANs 验证 CSR 里带全部 DNS 名且签名可校验。
func TestBuildCSRSANs(t *testing.T) {
	key, _, err := GenerateCertKey(KeyTypeECDSA256)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	der, err := BuildCSR(key, []string{"a.example.com", "b.example.com"})
	if err != nil {
		t.Fatalf("生成 CSR 失败: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("解析 CSR 失败: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR 签名校验失败: %v", err)
	}
	if strings.Join(csr.DNSNames, ",") != "a.example.com,b.example.com" {
		t.Fatalf("CSR DNSNames=%v", csr.DNSNames)
	}
	if csr.Subject.CommonName != "a.example.com" {
		t.Fatalf("CSR CN=%q", csr.Subject.CommonName)
	}
}

// mustPEMBlock 取 PEM 的 DER。
func mustPEMBlock(t *testing.T, raw []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("不是 PEM")
	}
	return block.Bytes
}

// TestGenerateCertKeyTypes 验证两种密钥类型的 PEM 可解析且是 PKCS#8。
func TestGenerateCertKeyTypes(t *testing.T) {
	for _, keyType := range []string{KeyTypeECDSA256, KeyTypeRSA2048, ""} {
		_, pemBytes, err := GenerateCertKey(keyType)
		if err != nil {
			t.Fatalf("%s: 生成密钥失败: %v", keyType, err)
		}
		if !strings.Contains(string(pemBytes), "BEGIN PRIVATE KEY") {
			t.Fatalf("%s: 私钥应为 PKCS#8 PEM", keyType)
		}
		if _, err := x509.ParsePKCS8PrivateKey(mustPEMBlock(t, pemBytes)); err != nil {
			t.Fatalf("%s: PKCS#8 解析失败: %v", keyType, err)
		}
	}
	if _, _, err := GenerateCertKey("ed25519"); err == nil {
		t.Fatal("不支持的 key_type 应报错")
	}
}

// TestNormalizeDomains 覆盖域名规整与拒绝口径。
func TestNormalizeDomains(t *testing.T) {
	got, err := NormalizeDomains([]string{" Example.COM ", "example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("归一化失败: %v", err)
	}
	if strings.Join(got, ",") != "example.com,www.example.com" {
		t.Fatalf("归一化结果=%v（应小写去重）", got)
	}
	bad := map[string]string{
		"通配符":  "*.example.com",
		"单标签":  "localhost",
		"非法字符": "exa mple.com",
		"连字符首": "-bad.example.com",
		"IP":   "127.0.0.1",
	}
	for name, domain := range bad {
		t.Run(name, func(t *testing.T) {
			if domain == "127.0.0.1" {
				// IP 在协议层被拒绝（本客户端只做 DNS-01 之外的 HTTP-01 DNS 名）。
				if _, err := NormalizeDomains([]string{domain}); err == nil {
					t.Fatal("IP 标识符暂不支持，应拒绝")
				}
				return
			}
			if _, err := NormalizeDomains([]string{domain}); err == nil {
				t.Fatalf("%q 应被拒绝", domain)
			}
		})
	}
	if _, err := NormalizeDomains(nil); err == nil {
		t.Fatal("空域名列表应报错")
	}
}
