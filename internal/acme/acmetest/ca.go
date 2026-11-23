// Package acmetest 是本仓库测试专用的本地 ACME 替身（RFC 8555 最小子集）。
//
// 它不在生产二进制里：只有 *_test.go import 它，Go 不会把它链接进插件。
// 目的是让内置 ACME 客户端能在"零外网"前提下跑完整链路——签名、nonce、订单、
// HTTP-01、finalize、下载证书链——并可控地注入各类失败。
package acmetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// testCA 是测试用两级 CA：root 自签、intermediate 由 root 签，叶子由 intermediate 签。
// 返回链为"叶子 + intermediate"（不含 root），足以验证链完整性（逐级签名关联）。
type testCA struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
}

// newTestCA 生成测试 CA（P-256，快）。
func newTestCA(t testing.TB) *testCA {
	t.Helper()
	rootKey := mustKey(t)
	interKey := mustKey(t)
	now := time.Now()

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Kore Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("生成测试 root CA 失败: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("解析测试 root CA 失败: %v", err)
	}

	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Kore Test Intermediate CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("生成测试 intermediate CA 失败: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("解析测试 intermediate CA 失败: %v", err)
	}
	return &testCA{root: rootCert, rootKey: rootKey, inter: interCert, interKey: interKey}
}

// issue 用 intermediate 为 CSR 里的 DNS 名签出叶子证书，返回"叶子 + intermediate" PEM。
func (ca *testCA) issue(t testing.TB, csr *x509.CertificateRequest) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("生成序列号失败: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: firstDNS(csr)},
		DNSNames:              csr.DNSNames,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.inter, csr.PublicKey, ca.interKey)
	if err != nil {
		t.Fatalf("签发测试叶子证书失败: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.inter.Raw})
	return append(leafPEM, interPEM...)
}

// firstDNS 取 CSR 的第一个 DNS 名（没有时用占位 CN）。
func firstDNS(csr *x509.CertificateRequest) string {
	if len(csr.DNSNames) > 0 {
		return csr.DNSNames[0]
	}
	return "test.invalid"
}

// mustKey 生成 P-256 密钥。
func mustKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	return key
}

// String 便于调试输出。
func (ca *testCA) String() string {
	return fmt.Sprintf("testCA{root=%s inter=%s}", ca.root.Subject.CommonName, ca.inter.Subject.CommonName)
}
