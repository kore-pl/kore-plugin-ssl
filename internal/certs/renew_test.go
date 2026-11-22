package certs

import (
	"strings"
	"testing"
)

// TestRenewSelfSigned 校验自签续期：新证书、文件名不变、密钥类型保留、目录里仍只有一张。
func TestRenewSelfSigned(t *testing.T) {
	svc, dir := testService(t)
	first, perr := svc.SelfSign(SelfSignRequest{Domain: "renew.kore.local", Days: 90})
	if perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	renewed, perr := svc.Renew(RenewRequest{Domain: "renew.kore.local", Days: 30})
	if perr != nil {
		t.Fatalf("续期失败: %v", perr)
	}
	if !renewed.Renewed || !renewed.SelfSigned {
		t.Fatalf("续期标记不符: %+v", renewed)
	}
	if renewed.DaysLeft != 30 {
		t.Fatalf("days_left=%d，期望 30", renewed.DaysLeft)
	}
	if renewed.FingerprintSHA256 == first.FingerprintSHA256 {
		t.Fatal("续期后指纹应变化")
	}
	if renewed.File != "renew.kore.local.crt" || renewed.KeyType != "rsa" || renewed.KeyBits != 2048 {
		t.Fatalf("续期产物文件名/密钥类型不符: %+v", renewed)
	}
	list, lerr := svc.List()
	if lerr != nil || list.Count != 1 {
		t.Fatalf("续期不应产生第二张证书: count=%d err=%v", list.Count, lerr)
	}
	if fileMode(t, dir+"/renew.kore.local.key") != 0o600 {
		t.Fatal("续期后私钥权限应为 0600")
	}
}

// TestRenewKeepsExtraSANs 续期保留原证书的附加 SAN（DNS 与 IP）。
func TestRenewKeepsExtraSANs(t *testing.T) {
	svc, _ := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{
		Domain: "multi.kore.local", Days: 30, ExtraSANs: []string{"127.0.0.1", "alt.multi.kore.local"},
	}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	renewed, perr := svc.Renew(RenewRequest{Domain: "multi.kore.local"})
	if perr != nil {
		t.Fatalf("续期失败: %v", perr)
	}
	for _, want := range []string{"multi.kore.local", "alt.multi.kore.local", "127.0.0.1"} {
		if !containsString(renewed.Domains, want) {
			t.Fatalf("续期后丢失 SAN %q: %v", want, renewed.Domains)
		}
	}
}

// TestRenewDefaultDaysKeepsSpan 未传 days 时沿用原有效期跨度。
func TestRenewDefaultDaysKeepsSpan(t *testing.T) {
	svc, _ := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "span.kore.local", Days: 120}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	renewed, perr := svc.Renew(RenewRequest{Domain: "span.kore.local"})
	if perr != nil {
		t.Fatalf("续期失败: %v", perr)
	}
	if renewed.DaysLeft != 120 {
		t.Fatalf("days_left=%d，期望沿用 120", renewed.DaysLeft)
	}
}

// TestRenewKeepsECDSA 续期保留 ECDSA P-256，不静默降级为 RSA。
func TestRenewKeepsECDSA(t *testing.T) {
	svc, _ := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "ecdsa-renew.kore.local", KeyType: "ecdsa256", Days: 20}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	renewed, perr := svc.Renew(RenewRequest{Domain: "ecdsa-renew.kore.local"})
	if perr != nil {
		t.Fatalf("续期失败: %v", perr)
	}
	if renewed.KeyType != "ecdsa" || renewed.KeyBits != 256 {
		t.Fatalf("续期后密钥类型=%s/%d，应保持 ECDSA P-256", renewed.KeyType, renewed.KeyBits)
	}
}

// TestRenewACMEUnsupported ACME 证书续期必须 E_UNSUPPORTED 且不改动原文件。
func TestRenewACMEUnsupported(t *testing.T) {
	svc, dir := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{
		domain: "acme.kore.local", dnsNames: []string{"acme.kore.local"}, issuerCN: "Let's Encrypt R3",
	})
	if _, perr := svc.Import(ImportRequest{Domain: "acme.kore.local", CertPEM: certPEM, KeyPEM: keyPEM}); perr != nil {
		t.Fatalf("导入 ACME 风格证书失败: %v", perr)
	}
	before := readTestFile(t, dir+"/acme.kore.local.crt")
	renewed, perr := svc.Renew(RenewRequest{Domain: "acme.kore.local"})
	if renewed != nil || perr == nil {
		t.Fatalf("ACME 续期应被拒绝: %+v %v", renewed, perr)
	}
	if perr.Code != codeUnsupported {
		t.Fatalf("错误码=%q，期望 %q", perr.Code, codeUnsupported)
	}
	if !strings.Contains(perr.Message, "ACME 客户端") || !strings.Contains(perr.Message, "v1.1") {
		t.Fatalf("错误信息应说明 ACME 未实现与版本计划: %q", perr.Message)
	}
	if after := readTestFile(t, dir+"/acme.kore.local.crt"); after != before {
		t.Fatal("ACME 续期失败不应改动原证书")
	}
}

// TestRenewACMEMarkerUnsupported .acme 标记优先于自签判定：不把 ACME 托管证书当自签重签。
func TestRenewACMEMarkerUnsupported(t *testing.T) {
	svc, dir := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "marked-renew.kore.local"}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	writeTestFile(t, dir, "marked-renew.kore.local.acme", "")
	before := readTestFile(t, dir+"/marked-renew.kore.local.crt")
	renewed, perr := svc.Renew(RenewRequest{Domain: "marked-renew.kore.local"})
	if renewed != nil || perr == nil || perr.Code != codeUnsupported {
		t.Fatalf("带 .acme 标记应 E_UNSUPPORTED: %+v %v", renewed, perr)
	}
	if after := readTestFile(t, dir+"/marked-renew.kore.local.crt"); after != before {
		t.Fatal("拒绝续期时不应改动原证书")
	}
}

// TestRenewNonSelfSignedUnsupported 非自签、非 ACME 的证书同样 E_UNSUPPORTED。
func TestRenewNonSelfSignedUnsupported(t *testing.T) {
	svc, _ := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{
		domain: "corp.kore.local", dnsNames: []string{"corp.kore.local"}, issuerCN: "Internal CA",
	})
	if _, perr := svc.Import(ImportRequest{Domain: "corp.kore.local", CertPEM: certPEM, KeyPEM: keyPEM}); perr != nil {
		t.Fatalf("导入失败: %v", perr)
	}
	_, perr := svc.Renew(RenewRequest{Domain: "corp.kore.local"})
	if perr == nil || perr.Code != codeUnsupported {
		t.Fatalf("应 E_UNSUPPORTED，得到 %v", perr)
	}
	if !strings.Contains(perr.Message, "不是自签") || !strings.Contains(perr.Message, "ssl.import") {
		t.Fatalf("错误信息应说明不支持原因与替代路径: %q", perr.Message)
	}
}

// TestRenewUnsupportedCurve 自签 P-384 不在 v1 支持范围：显式拒绝，不静默降级。
func TestRenewUnsupportedCurve(t *testing.T) {
	svc, _ := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{
		domain: "p384.kore.local", dnsNames: []string{"p384.kore.local"}, keyType: "ecdsa384",
	})
	if _, perr := svc.Import(ImportRequest{Domain: "p384.kore.local", CertPEM: certPEM, KeyPEM: keyPEM}); perr != nil {
		t.Fatalf("导入 P-384 证书失败: %v", perr)
	}
	_, perr := svc.Renew(RenewRequest{Domain: "p384.kore.local"})
	if perr == nil || perr.Code != codeUnsupported || !strings.Contains(perr.Message, "P-384") {
		t.Fatalf("应 E_UNSUPPORTED 且说明 P-384，得到 %v", perr)
	}
}

// TestRenewNotFound 目录里没有该域名时返回 E_NOTFOUND。
func TestRenewNotFound(t *testing.T) {
	svc, _ := testService(t)
	_, perr := svc.Renew(RenewRequest{Domain: "missing.kore.local"})
	if perr == nil || perr.Code != codeNotFound {
		t.Fatalf("应 E_NOTFOUND，得到 %v", perr)
	}
}

// TestRenewInvalidParams 校验域名与天数的拒绝分支。
func TestRenewInvalidParams(t *testing.T) {
	svc, _ := testService(t)
	if _, perr := svc.Renew(RenewRequest{Domain: "BAD"}); perr == nil || perr.Code != codeInvalid {
		t.Fatalf("非法域名应 E_INVALID，得到 %v", perr)
	}
	if _, perr := svc.Renew(RenewRequest{Domain: "ok.kore.local", Days: 99999}); perr == nil || perr.Code != codeInvalid {
		t.Fatalf("非法天数应 E_INVALID，得到 %v", perr)
	}
}
