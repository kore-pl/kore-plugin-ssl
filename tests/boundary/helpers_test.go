//go:build linux

package boundary

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
)

// newService 在独立临时目录上构造无故障注入的 Service。
// MetaDir 与 Dir 同目录，保证 bindings/backups 落在临时目录内（测试彼此隔离，
// 不写宿主机默认路径）。
func newService(t *testing.T, dir string) *certs.Service {
	t.Helper()
	return certs.NewService(certs.Options{Dir: dir, MetaDir: dir})
}

// certPair 生成指定域名与有效期的自签证书/私钥 PEM。
// 用 ECDSA P-256 是为了让并发用例在毫秒级建出多张证书，同时仍是真实可握手的证书。
func certPair(t *testing.T, domain string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("生成序列号失败: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("编码测试私钥失败: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

// writeCertPair 按生产落盘口径（证书 0644、私钥 0600）把证书/私钥写进目录。
func writeCertPair(t *testing.T, dir, domain, certPEM, keyPEM string) (string, string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("创建测试证书目录失败: %v", err)
	}
	certPath := filepath.Join(dir, domain+".crt")
	keyPath := filepath.Join(dir, domain+".key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		t.Fatalf("写入测试证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatalf("写入测试私钥失败: %v", err)
	}
	return certPath, keyPath
}

// mustSelfSign 生成一张自签证书并要求成功（用例的前置状态，不是被测行为）。
func mustSelfSign(t *testing.T, svc *certs.Service, domain string) *certs.CertInfo {
	t.Helper()
	info, perr := svc.SelfSign(certs.SelfSignRequest{Domain: domain, KeyType: "ecdsa256"})
	if perr != nil {
		t.Fatalf("前置自签 %s 失败: %s/%s", domain, perr.Code, perr.Message)
	}
	return info
}

// requireCertError 断言业务错误码与关键词（message 或 hint 任一命中即可，
// hint 是给用户的可操作提示，两者都算"明确错误"）。
func requireCertError(t *testing.T, perr *certs.CertError, wantCode, wantWord string) {
	t.Helper()
	if perr == nil {
		t.Fatalf("期望错误 %s（含 %q），实际成功", wantCode, wantWord)
	}
	if perr.Code != wantCode {
		t.Fatalf("错误码=%q，期望 %q（message=%q hint=%q）", perr.Code, wantCode, perr.Message, perr.Hint)
	}
	combined := strings.ToLower(perr.Message + " " + perr.Hint)
	if !strings.Contains(combined, strings.ToLower(wantWord)) {
		t.Fatalf("错误信息未含关键词 %q：message=%q hint=%q", wantWord, perr.Message, perr.Hint)
	}
}

// chmodRestore 修改权限并在用例结束时恢复，保证 TempDir 可被清理（含 root 场景）。
func chmodRestore(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s 失败: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
}
