//go:build linux

package boundary

import (
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
)

// 异常输入：坏证书 / 域名不匹配 / 私钥不匹配 / 加密私钥 / 过期证书 / 非法域名。
//
// 每个用例都走真实业务入口（Import / SelfSign / List），断言结构化错误码而不是
// "返回了 error 就算过"——错误码是内核映射 HTTP 与前端提示的唯一依据。这 6 个用例
// 与 internal/certs 单测的代表性场景同源，放进 tests/boundary 是为了满足
// PLUGIN-CATALOG §6.1 判据①"异常输入 ≥1 例且进 CI"的独立边界套件要求。

// TestAbnormalInputMalformedCertPEM 覆盖证书不是合法 PEM/证书的情形。
func TestAbnormalInputMalformedCertPEM(t *testing.T) {
	svc := newService(t, t.TempDir())
	_, perr := svc.Import(certs.ImportRequest{
		Domain:  "malformed.kore.local",
		CertPEM: "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n",
	})
	requireCertError(t, perr, "E_INVALID", "不是合法证书")
}

// TestAbnormalInputDomainMismatch 覆盖证书 SAN 不覆盖请求域名的情形。
func TestAbnormalInputDomainMismatch(t *testing.T) {
	svc := newService(t, t.TempDir())
	now := time.Now()
	certPEM, keyPEM := certPair(t, "real.kore.local", now.Add(-time.Hour), now.Add(24*time.Hour))
	_, perr := svc.Import(certs.ImportRequest{
		Domain:  "other.kore.local",
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	requireCertError(t, perr, "E_INVALID", "SAN 不含")
}

// TestAbnormalInputKeyMismatch 覆盖证书与私钥不是一对的情形。
func TestAbnormalInputKeyMismatch(t *testing.T) {
	svc := newService(t, t.TempDir())
	now := time.Now()
	certPEM, _ := certPair(t, "pair.kore.local", now.Add(-time.Hour), now.Add(24*time.Hour))
	_, otherKey := certPair(t, "other.kore.local", now.Add(-time.Hour), now.Add(24*time.Hour))
	_, perr := svc.Import(certs.ImportRequest{
		Domain:  "pair.kore.local",
		CertPEM: certPEM,
		KeyPEM:  otherKey,
	})
	requireCertError(t, perr, "E_INVALID", "不匹配")
}

// TestAbnormalInputEncryptedPrivateKey 覆盖带 passphrase 的加密私钥被明确拒绝。
func TestAbnormalInputEncryptedPrivateKey(t *testing.T) {
	svc := newService(t, t.TempDir())
	now := time.Now()
	certPEM, _ := certPair(t, "enc.kore.local", now.Add(-time.Hour), now.Add(24*time.Hour))
	encryptedKey := string(pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00112233445566778899AABBCCDDEEFF"},
		Bytes:   []byte("encrypted-bytes"),
	}))
	_, perr := svc.Import(certs.ImportRequest{
		Domain:  "enc.kore.local",
		CertPEM: certPEM,
		KeyPEM:  encryptedKey,
	})
	requireCertError(t, perr, "E_INVALID", "passphrase")
}

// TestAbnormalInputExpiredCertificate 覆盖过期证书：List 必须如实标记 expired 与负
// days_left，而不是把过期证书当成正常证书（过期是观测值，不是方法失败）。
func TestAbnormalInputExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	svc := newService(t, dir)
	now := time.Now()
	certPEM, keyPEM := certPair(t, "expired.kore.local", now.Add(-72*time.Hour), now.Add(-24*time.Hour))
	writeCertPair(t, dir, "expired.kore.local", certPEM, keyPEM)

	result, perr := svc.List()
	if perr != nil {
		t.Fatalf("List 失败: %s/%s", perr.Code, perr.Message)
	}
	if result.Count != 1 {
		t.Fatalf("过期证书应被列出 1 条，实际 %d", result.Count)
	}
	info := result.Certs[0]
	if info.Error != "" {
		t.Fatalf("过期证书解析不应报错: %s", info.Error)
	}
	if !info.Expired {
		t.Fatalf("过期证书未标记 expired: %+v", info)
	}
	if info.DaysLeft >= 0 {
		t.Fatalf("过期证书 days_left 应 <0，实际 %d", info.DaysLeft)
	}
}

// TestAbnormalInputInvalidDomain 覆盖非法域名（大写 / 下划线）在写盘前被拒绝。
func TestAbnormalInputInvalidDomain(t *testing.T) {
	svc := newService(t, t.TempDir())
	for _, domain := range []string{"Bad_Domain.kore.local", "UPPER.kore.local", "../escape.kore.local"} {
		_, perr := svc.SelfSign(certs.SelfSignRequest{Domain: domain})
		if perr == nil {
			t.Fatalf("非法域名 %q 应被拒绝，实际成功", domain)
		}
		if perr.Code != "E_INVALID" || !strings.Contains(perr.Message, "domain") {
			t.Fatalf("非法域名 %q 错误不符: %s/%s", domain, perr.Code, perr.Message)
		}
	}
}
