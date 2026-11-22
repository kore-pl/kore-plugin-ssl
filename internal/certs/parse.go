package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// certBundle 是一个证书文件解析结果：leaf 是首张证书，chain 是随文件的其余证书。
type certBundle struct {
	leaf  *x509.Certificate
	chain []*x509.Certificate
}

// parseCertPEM 逐块解析 PEM 中的 CERTIFICATE；首块为叶子，其余为链。
// 文件里出现非证书块（例如私钥）时明确报错，不猜测、不忽略。
func parseCertPEM(data []byte) (certBundle, error) {
	var bundle certBundle
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			if strings.Contains(block.Type, "PRIVATE KEY") {
				return certBundle{}, errors.New("文件包含私钥块，不是证书文件")
			}
			return certBundle{}, fmt.Errorf("PEM 块类型 %q 不是 CERTIFICATE", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certBundle{}, fmt.Errorf("x509 解析证书失败: %w", err)
		}
		if bundle.leaf == nil {
			bundle.leaf = cert
			continue
		}
		bundle.chain = append(bundle.chain, cert)
	}
	if bundle.leaf == nil {
		return certBundle{}, errors.New("不是 PEM 证书（未找到 CERTIFICATE 块）")
	}
	return bundle, nil
}

// countPEMCerts 统计 PEM 中的 CERTIFICATE 块数量（用于 chain_length）。
func countPEMCerts(data []byte) int {
	count := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return count
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
}

// inspectCert 把 x509.Certificate 转成对外结构；file 只保留文件名。
// chainLength 由调用方给出（同文件证书数 + 独立 chain 文件证书数）；
// dir 用于探测同名前缀的 .acme 标记文件。
func inspectCert(leaf *x509.Certificate, chainLength int, dir, file string, now time.Time) CertInfo {
	keyType, keyBits := publicKeyInfo(leaf.PublicKey)
	issuer := nameOrDN(leaf.Issuer.CommonName, leaf.Issuer.String())
	subject := nameOrDN(leaf.Subject.CommonName, leaf.Subject.String())
	days := daysLeft(leaf.NotAfter, now)
	expired := !now.Before(leaf.NotAfter)
	return CertInfo{
		Domain:            primaryDomain(leaf),
		Domains:           certDomains(leaf),
		File:              file,
		NotBefore:         leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:          days,
		Issuer:            issuer,
		Subject:           subject,
		Serial:            leaf.SerialNumber.Text(16),
		IsCA:              leaf.IsCA,
		KeyType:           keyType,
		KeyBits:           keyBits,
		ChainLength:       chainLength,
		FingerprintSHA256: fingerprint(leaf),
		SelfSigned:        isSelfSigned(leaf),
		Source:            certSource(leaf, dir, file),
		Expired:           expired,
		ExpiringSoon:      !expired && days < 30,
	}
}

// inspectCertFile 解析一个证书文件并补齐同名前缀的独立 chain 文件计数。
func inspectCertFile(path string, now time.Time) (CertInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CertInfo{}, err
	}
	bundle, err := parseCertPEM(data)
	if err != nil {
		return CertInfo{}, err
	}
	chainLength := 1 + len(bundle.chain)
	base := trimCertSuffix(filepath.Base(path))
	chainPath := filepath.Join(filepath.Dir(path), base+chainSuffix)
	if extra, readErr := os.ReadFile(chainPath); readErr == nil {
		chainLength += countPEMCerts(extra)
	}
	return inspectCert(bundle.leaf, chainLength, filepath.Dir(path), filepath.Base(path), now), nil
}

// daysLeft 计算剩余天数：向上取整，避免刚签发的 365 天证书显示 364；
// 已过期时向下取到负值（不足一天记 -1），与 expired 字段语义一致。
func daysLeft(notAfter, now time.Time) int {
	remaining := notAfter.Sub(now)
	days := int(math.Ceil(remaining.Hours() / 24))
	if remaining <= 0 && days >= 0 {
		return -1
	}
	return days
}

// primaryDomain 选出主域名：首个 DNS SAN → 首个 IP SAN → CN。
func primaryDomain(cert *x509.Certificate) string {
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String()
	}
	return cert.Subject.CommonName
}

// certDomains 汇总 SAN + CN 并去重排序，保证输出确定性。
func certDomains(cert *x509.Certificate) []string {
	seen := make(map[string]struct{}, len(cert.DNSNames)+len(cert.IPAddresses)+1)
	domains := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+1)
	add := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		domains = append(domains, value)
	}
	for _, name := range cert.DNSNames {
		add(name)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	add(cert.Subject.CommonName)
	sort.Strings(domains)
	return domains
}

// publicKeyInfo 返回公钥算法与位数。
func publicKeyInfo(pub any) (string, int) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return "rsa", key.N.BitLen()
	case *ecdsa.PublicKey:
		return "ecdsa", key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "ed25519", 256
	default:
		return "unknown", 0
	}
}

// fingerprint 返回证书 DER 的 SHA-256 小写十六进制。
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// isSelfSigned 判断自签：Issuer 与 Subject 的原始编码一致，且签名可用自身公钥验证。
// 不用 CheckSignatureFrom（它要求父证书是 CA，叶子自签证书会误判）。
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// certSource 判定证书来源：ACME 签发者/标记文件优先 → acme；其次自签 → self-signed；
// 否则 imported。标记优先是有意的：ACME 客户端可能同时落一张自签过渡证书，
// 有标记就说明归属 ACME，续期必须拒绝而不是当自签重签。
func certSource(cert *x509.Certificate, dir, file string) string {
	if isACMEIssuer(cert) || hasACMEMarker(dir, file) {
		return "acme"
	}
	if isSelfSigned(cert) {
		return "self-signed"
	}
	return "imported"
}

// isACMEIssuer 按签发者 CommonName/DN 识别公共 ACME CA。
func isACMEIssuer(cert *x509.Certificate) bool {
	name := strings.ToLower(cert.Issuer.CommonName + " " + cert.Issuer.String())
	for _, marker := range []string{"let's encrypt", "letsencrypt", "acme"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// hasACMEMarker 检查同名前缀的 .acme 归属标记（v1.1 ACME 客户端落盘的托管标记）。
// 标记存在即视为 ACME 托管：ssl.renew 不得把外部 ACME 证书当成自签来重签。
func hasACMEMarker(dir, file string) bool {
	if dir == "" || file == "" {
		return false
	}
	marker := filepath.Join(dir, trimCertSuffix(file)+acmeMarkerSuffix)
	info, err := os.Stat(marker)
	return err == nil && !info.IsDir()
}

// certCoversDomain 判断证书是否覆盖给定域名：精确 SAN、通配符 SAN 覆盖、或 IP SAN 相等。
// 不把 CN 当作覆盖依据——现代 TLS 栈已忽略 CN，导入时按 SAN 严格校验。
func certCoversDomain(cert *x509.Certificate, domain string) bool {
	if ip := net.ParseIP(domain); ip != nil {
		for _, candidate := range cert.IPAddresses {
			if candidate.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, name := range cert.DNSNames {
		if strings.EqualFold(name, domain) {
			return true
		}
		if strings.HasPrefix(name, "*.") && wildcardCovers(name, domain) {
			return true
		}
	}
	return false
}

// wildcardCovers 判断 *.example.com 是否覆盖 host 且只覆盖一级子域（RFC 6125）。
func wildcardCovers(pattern, host string) bool {
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := strings.TrimSuffix(host, suffix)
	return label != "" && !strings.Contains(label, ".")
}

// trimCertSuffix 去掉证书文件后缀，得到 base（用于派生 .key / .chain.pem / .acme）。
func trimCertSuffix(filename string) string {
	name := filepath.Base(filename)
	for _, suffix := range []string{certSuffix, pemSuffix} {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}

// nameOrDN 优先用 CommonName，为空时回退完整 DN。
func nameOrDN(commonName, dn string) string {
	if commonName != "" {
		return commonName
	}
	return dn
}
