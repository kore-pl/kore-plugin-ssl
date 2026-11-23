package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"strings"
)

// 证书密钥类型（与 ssl.selfsign 的 key_type 取值一致，便于前端复用一套选择器）。
const (
	KeyTypeECDSA256 = "ecdsa256"
	KeyTypeRSA2048  = "rsa2048"
	// maxCertDomains 限制单张证书的标识符数量（避免一次请求几百个域名）。
	maxCertDomains = 100
)

// GenerateCertKey 生成证书私钥并返回 PKCS#8 PEM（私钥只落盘 0600，不进返回值）。
func GenerateCertKey(keyType string) (crypto.Signer, []byte, error) {
	var key crypto.Signer
	switch strings.TrimSpace(keyType) {
	case "", KeyTypeECDSA256:
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, errf(KindInvalid, "重试；持续失败检查系统熵源", "生成 ECDSA 私钥失败: %v", err)
		}
		key = generated
	case KeyTypeRSA2048:
		generated, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, errf(KindInvalid, "重试；持续失败检查系统熵源", "生成 RSA 私钥失败: %v", err)
		}
		key = generated
	default:
		return nil, nil, errf(KindInvalid, "key_type 只支持 ecdsa256 / rsa2048", "不支持的 key_type=%q", keyType)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, errf(KindInvalid, "这是内部错误：私钥编码失败", "编码私钥失败: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// BuildCSR 生成最终提交给 CA 的 CSR（DER）：SAN 就是订单里的域名列表，CN 取第一个。
func BuildCSR(key crypto.Signer, domains []string) ([]byte, error) {
	if len(domains) == 0 {
		return nil, errf(KindInvalid, "至少给一个域名", "生成 CSR 时域名列表为空")
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, errf(KindInvalid, "这是内部错误：CSR 生成失败", "生成 CSR 失败: %v", err)
	}
	return der, nil
}

// NormalizeDomains 校验并归一化订单域名：小写、去重、拒绝通配符/IP/非法标签。
//
// HTTP-01 只能验证具体域名；通配符必须 DNS-01（本客户端未实现），所以这里
// 明确拒绝并给 hint，而不是让 CA 用一段难懂的 rejectedIdentifier 回绝。
func NormalizeDomains(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errf(KindInvalid, "传 domain（可加 alt_names）", "缺少域名")
	}
	if len(raw) > maxCertDomains {
		return nil, errf(KindInvalid, "拆成多张证书，每张 ≤100 个域名", "域名数量 %d 超过上限 %d", len(raw), maxCertDomains)
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		domain := strings.ToLower(strings.TrimSpace(item))
		if domain == "" {
			continue
		}
		if strings.Contains(domain, "*") {
			return nil, errf(KindUnsupported,
				"通配符证书需要 DNS-01 校验（本客户端只实现 HTTP-01）：改用具体域名，或等 v1.1 的 DNS-01",
				"不支持通配符域名 %q", domain)
		}
		if err := validateDNSName(domain); err != nil {
			return nil, err
		}
		if _, dup := seen[domain]; dup {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	if len(out) == 0 {
		return nil, errf(KindInvalid, "传真实域名（至少两个标签，如 example.com）", "没有可用的域名")
	}
	return out, nil
}

// validateDNSName 校验公网域名：小写字母数字与连字符、至少两个标签、每标签 ≤63、总长 ≤253。
func validateDNSName(domain string) error {
	if len(domain) > 253 {
		return errf(KindInvalid, "域名最长 253 字符", "域名过长: %q", domain)
	}
	if net.ParseIP(domain) != nil {
		return errf(KindInvalid, "用域名而不是 IP：本客户端只按 dns 标识符下单（IP 证书暂不支持）", "域名 %q 是 IP 地址", domain)
	}
	if !strings.Contains(domain, ".") {
		return errf(KindInvalid, "用完整域名（如 example.com），不要只写主机名", "域名 %q 不是完整域名", domain)
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return errf(KindInvalid, "检查域名里的连续点或超长标签", "域名 %q 含非法标签", domain)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errf(KindInvalid, "标签不能以连字符开头或结尾", "域名 %q 含非法标签", domain)
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return errf(KindInvalid, "域名只允许小写字母、数字、连字符与点（IP 暂不支持）", "域名 %q 含非法字符 %q", domain, string(r))
		}
	}
	return nil
}

// 编译期断言：ecdsa 私钥实现 crypto.Signer（BuildCSR 依赖）。
var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
