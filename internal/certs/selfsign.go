package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"time"
)

// 密钥与有效期默认值：与 ssl.selfsign 的对外契约一致。
const (
	defaultSelfSignDays = 365
	keyTypeRSA2048      = "rsa2048"
	keyTypeECDSA256     = "ecdsa256"
	rsaKeyBits          = 2048
)

// SelfSign 生成密钥并签发自签证书，原子落盘后按磁盘内容回读返回。
// 返回结构只含公钥信息与 self_signed=true，绝不含私钥字节。
func (s *Service) SelfSign(req SelfSignRequest) (*CertInfo, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	if perr := validateDomain(req.Domain); perr != nil {
		return nil, perr
	}
	if perr := validateDays(req.Days); perr != nil {
		return nil, perr
	}
	if perr := validateKeyType(req.KeyType); perr != nil {
		return nil, perr
	}
	extra, perr := normalizeExtraSANs(req.ExtraSANs)
	if perr != nil {
		return nil, perr
	}
	days := req.Days
	if days == 0 {
		days = defaultSelfSignDays
	}
	keyType := req.KeyType
	if keyType == "" {
		keyType = keyTypeRSA2048
	}
	info, err := s.issueSelfSigned(req.Domain, req.Domain+certSuffix, days, keyType, extra, nowOr(s.now))
	if err != nil {
		return nil, internalErr("签发自签证书失败: " + err.Error())
	}
	return &info, nil
}

// normalizeExtraSANs 逐个校验附加 SAN 并去重。
func normalizeExtraSANs(values []string) ([]string, *CertError) {
	extra := make([]string, 0, len(values))
	for _, raw := range values {
		value, perr := normalizeExtraSAN(raw)
		if perr != nil {
			return nil, perr
		}
		if !containsString(extra, value) {
			extra = append(extra, value)
		}
	}
	return extra, nil
}

// issueSelfSigned 是自签的单一实现：生成密钥 → 构造并签名证书 → 原子写盘 → 回读。
// certFileName 决定写入哪个证书文件（续期时沿用原文件名，避免产生第二份证书）。
func (s *Service) issueSelfSigned(domain, certFileName string, days int, keyType string, extra []string, now time.Time) (CertInfo, error) {
	privateKey, err := generateKey(keyType)
	if err != nil {
		return CertInfo{}, err
	}
	template, err := selfSignedTemplate(domain, days, extra, now)
	if err != nil {
		return CertInfo{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return CertInfo{}, fmt.Errorf("编码私钥: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return CertInfo{}, errors.New("生成的私钥不支持签名")
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return CertInfo{}, fmt.Errorf("生成自签证书: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := s.store.writePair(certFileName, certPEM, keyPEM, nil); err != nil {
		return CertInfo{}, err
	}
	return s.inspectWritten(certFileName, now)
}

// inspectWritten 从磁盘回读刚写入的证书，保证返回内容与 ssl.list 同源、同口径。
func (s *Service) inspectWritten(certFileName string, now time.Time) (CertInfo, error) {
	path := filepath.Join(s.store.dir, certFileName)
	info, err := inspectCertFile(path, now)
	if err != nil {
		return CertInfo{}, fmt.Errorf("回读证书失败: %w", err)
	}
	return info, nil
}

// generateKey 按 key_type 生成 RSA-2048 或 ECDSA P-256 私钥。
func generateKey(keyType string) (any, error) {
	switch keyType {
	case keyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, rsaKeyBits)
	case keyTypeECDSA256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("不支持的 key_type %q", keyType)
	}
}

// selfSignedTemplate 构造自签证书模板：DNSNames=[domain]（domain 为 IP 时进 IPAddresses）、
// NotAfter=now+days、ServerAuth 用途。附加 SAN 同时支持 DNS 名与 IP。
func selfSignedTemplate(domain string, days int, extra []string, now time.Time) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("生成证书序列号: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain, Organization: []string{"kore self-signed"}},
		NotBefore:             now.Add(-1 * time.Minute), // 容忍轻微时钟偏差
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, domain)
	}
	for _, san := range extra {
		if ip := net.ParseIP(san); ip != nil {
			if !containsIP(template.IPAddresses, ip) {
				template.IPAddresses = append(template.IPAddresses, ip)
			}
			continue
		}
		if !containsString(template.DNSNames, san) {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
	return template, nil
}

// containsIP 判断 IP 列表是否已含目标地址（按值比较，不按字节切片比较）。
func containsIP(values []net.IP, want net.IP) bool {
	for _, value := range values {
		if value.Equal(want) {
			return true
		}
	}
	return false
}
