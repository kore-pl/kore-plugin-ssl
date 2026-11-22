package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testService 返回指向临时目录的服务（无故障注入）。
func testService(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	return NewService(Options{Dir: dir}), dir
}

// testPairOptions 描述测试证书的生成参数。
type testPairOptions struct {
	domain      string
	dnsNames    []string
	ipAddresses []net.IP
	issuerCN    string // 空表示自签（Issuer==Subject）
	isCA        bool
	notBefore   time.Time
	notAfter    time.Time
	keyType     string // rsa2048（默认）/ ecdsa256 / ecdsa384
}

// makeTestPair 生成测试用证书 + 私钥 PEM。issuerCN 非空时只改 issuer 名，
// 签名仍由自身私钥完成——用于验证"非自签 issuer"分支，不冒充真实 CA。
func makeTestPair(t *testing.T, opts testPairOptions) (string, string) {
	t.Helper()
	if opts.domain == "" {
		opts.domain = "test.kore.local"
	}
	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	// 未显式给 SAN 时按 domain 补齐：DNS 进 DNSNames、IP 进 IPAddresses，
	// 与 selfsign 的口径一致，避免测试证书只有 CN（导入按 SAN 严格校验）。
	if len(opts.dnsNames) == 0 && len(opts.ipAddresses) == 0 {
		if ip := net.ParseIP(opts.domain); ip != nil {
			opts.ipAddresses = []net.IP{ip}
		} else {
			opts.dnsNames = []string{opts.domain}
		}
	}
	privateKey := generateTestKey(t, opts.keyType)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: opts.domain},
		DNSNames:              append([]string(nil), opts.dnsNames...),
		IPAddresses:           append([]net.IP(nil), opts.ipAddresses...),
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
	}
	parent := template
	if opts.issuerCN != "" {
		parent = &x509.Certificate{Subject: pkix.Name{CommonName: opts.issuerCN}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("编码测试私钥失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// generateTestKey 生成指定类型的测试私钥。
func generateTestKey(t *testing.T, keyType string) crypto.Signer {
	t.Helper()
	switch keyType {
	case "ecdsa256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("生成 ECDSA P-256 私钥失败: %v", err)
		}
		return key
	case "ecdsa384":
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("生成 ECDSA P-384 私钥失败: %v", err)
		}
		return key
	default:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("生成 RSA 私钥失败: %v", err)
		}
		return key
	}
}

// writeTestFile 在目录写一个文件（0644）并返回路径。
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写测试文件 %s 失败: %v", name, err)
	}
	return path
}

// readTestFile 读文件内容。
func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读文件 %s 失败: %v", path, err)
	}
	return string(data)
}

// fileMode 返回文件权限位。
func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s 失败: %v", path, err)
	}
	return info.Mode().Perm()
}

// serveTestTLS 用给定证书起真实 TLS 服务，返回监听地址。
func serveTestTLS(t *testing.T, certPEM, keyPEM string) string {
	t.Helper()
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("加载测试证书失败: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听本地端口失败: %v", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("kore-ssl-test-ok"))
	})}
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}
