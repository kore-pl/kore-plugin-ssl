package certs

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestListEmptyDirs 校验空目录与不存在的目录都返回空清单（不是错误）。
func TestListEmptyDirs(t *testing.T) {
	svc, _ := testService(t)
	list, perr := svc.List()
	if perr != nil || list.Count != 0 || list.Certs == nil {
		t.Fatalf("空目录应返回 count=0 的空列表: %+v err=%v", list, perr)
	}
	missing := NewService(Options{Dir: t.TempDir() + "/not-created"})
	list, perr = missing.List()
	if perr != nil || list.Count != 0 {
		t.Fatalf("不存在的目录应返回空清单: %+v err=%v", list, perr)
	}
}

// TestListScansMultiple 校验多证书扫描、字段解析与排序。
func TestListScansMultiple(t *testing.T) {
	svc, dir := testService(t)
	rsaCert, rsaKey := makeTestPair(t, testPairOptions{domain: "b.kore.local", dnsNames: []string{"b.kore.local", "alt.b.kore.local"}})
	writeTestFile(t, dir, "b.kore.local.crt", rsaCert)
	writeTestFile(t, dir, "b.kore.local.key", rsaKey)

	ecdsaCert, _ := makeTestPair(t, testPairOptions{domain: "a.kore.local", dnsNames: []string{"a.kore.local"}, keyType: "ecdsa256"})
	writeTestFile(t, dir, "a.kore.local.pem", ecdsaCert)

	caCert, _ := makeTestPair(t, testPairOptions{domain: "ca.kore.local", dnsNames: []string{"ca.kore.local"}, isCA: true})
	writeTestFile(t, dir, "ca.kore.local.crt", caCert)

	list, perr := svc.List()
	if perr != nil {
		t.Fatalf("list 失败: %v", perr)
	}
	if list.Count != 3 {
		t.Fatalf("count=%d，期望 3: %+v", list.Count, list.Certs)
	}
	if list.Certs[0].Domain != "a.kore.local" || list.Certs[1].Domain != "b.kore.local" || list.Certs[2].Domain != "ca.kore.local" {
		t.Fatalf("排序不符: %v", []string{list.Certs[0].Domain, list.Certs[1].Domain, list.Certs[2].Domain})
	}
	if list.Certs[0].KeyType != "ecdsa" || list.Certs[0].KeyBits != 256 {
		t.Fatalf("ECDSA 条目公钥信息不符: %+v", list.Certs[0])
	}
	if len(list.Certs[1].Domains) != 2 {
		t.Fatalf("b 条目 SAN 数量不符: %v", list.Certs[1].Domains)
	}
	if !list.Certs[2].IsCA {
		t.Fatal("CA 证书应标记 is_ca=true")
	}
	if list.Certs[0].ChainLength != 1 || len(list.Certs[0].FingerprintSHA256) != 64 {
		t.Fatalf("链长/指纹不符: %+v", list.Certs[0])
	}
}

// TestListExpiredAndExpiringSoon 校验有效期标记：过期、临期（<30 天）、正常三档。
func TestListExpiredAndExpiringSoon(t *testing.T) {
	svc, dir := testService(t)
	now := time.Now()
	expiredCert, _ := makeTestPair(t, testPairOptions{
		domain: "expired.kore.local", dnsNames: []string{"expired.kore.local"},
		notBefore: now.Add(-100 * 24 * time.Hour), notAfter: now.Add(-48 * time.Hour),
	})
	writeTestFile(t, dir, "expired.kore.local.crt", expiredCert)
	soonCert, _ := makeTestPair(t, testPairOptions{
		domain: "soon.kore.local", dnsNames: []string{"soon.kore.local"},
		notBefore: now.Add(-355 * 24 * time.Hour), notAfter: now.Add(10 * 24 * time.Hour),
	})
	writeTestFile(t, dir, "soon.kore.local.crt", soonCert)

	list, perr := svc.List()
	if perr != nil {
		t.Fatalf("list 失败: %v", perr)
	}
	byDomain := map[string]CertInfo{}
	for _, entry := range list.Certs {
		byDomain[entry.Domain] = entry
	}
	expired := byDomain["expired.kore.local"]
	if !expired.Expired || expired.DaysLeft >= 0 || expired.ExpiringSoon {
		t.Fatalf("过期证书标记不符: %+v", expired)
	}
	soon := byDomain["soon.kore.local"]
	if soon.Expired || !soon.ExpiringSoon || soon.DaysLeft != 10 {
		t.Fatalf("临期证书标记不符: %+v", soon)
	}
}

// TestListErrorEntry 校验无法解析的条目只标记 error，不影响其它条目。
func TestListErrorEntry(t *testing.T) {
	svc, dir := testService(t)
	writeTestFile(t, dir, "broken.kore.local.crt", "this is not a certificate")
	good, _ := makeTestPair(t, testPairOptions{domain: "good.kore.local", dnsNames: []string{"good.kore.local"}})
	writeTestFile(t, dir, "good.kore.local.crt", good)

	list, perr := svc.List()
	if perr != nil {
		t.Fatalf("list 失败: %v", perr)
	}
	if list.Count != 2 {
		t.Fatalf("count=%d，期望 2: %+v", list.Count, list.Certs)
	}
	var broken *CertInfo
	for i := range list.Certs {
		if list.Certs[i].Domain == "broken.kore.local" {
			broken = &list.Certs[i]
		}
	}
	if broken == nil || broken.Error == "" || broken.File != "broken.kore.local.crt" {
		t.Fatalf("坏证书条目不符: %+v", broken)
	}
	if list.Certs[0].Error == "" && list.Certs[1].Error == "" {
		t.Fatal("应至少有一个条目带 error")
	}
}

// TestListSkipsKeyAndDeduplicates 校验私钥不被扫描、同一证书多文件名只列一次。
func TestListSkipsKeyAndDeduplicates(t *testing.T) {
	svc, dir := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "dedupe.kore.local"}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	original := readTestFile(t, dir+"/dedupe.kore.local.crt")
	writeTestFile(t, dir, "copy.kore.local.crt", original)
	list, perr := svc.List()
	if perr != nil {
		t.Fatalf("list 失败: %v", perr)
	}
	if list.Count != 1 {
		t.Fatalf("重复证书应只列一次，count=%d: %+v", list.Count, list.Certs)
	}
}

// TestListDetectsACMESource 校验 ACME 来源判定：issuer 命中与 .acme 标记两条路径。
func TestListDetectsACMESource(t *testing.T) {
	svc, dir := testService(t)
	acmeCert, _ := makeTestPair(t, testPairOptions{
		domain: "lets.kore.local", dnsNames: []string{"lets.kore.local"}, issuerCN: "Let's Encrypt R3",
	})
	writeTestFile(t, dir, "lets.kore.local.crt", acmeCert)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "marked.kore.local"}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	writeTestFile(t, dir, "marked.kore.local.acme", "")

	list, perr := svc.List()
	if perr != nil {
		t.Fatalf("list 失败: %v", perr)
	}
	byDomain := map[string]CertInfo{}
	for _, entry := range list.Certs {
		byDomain[entry.Domain] = entry
	}
	if got := byDomain["lets.kore.local"].Source; got != "acme" {
		t.Fatalf("Let's Encrypt issuer 应识别为 acme，得到 %q", got)
	}
	if got := byDomain["marked.kore.local"].Source; got != "acme" {
		t.Fatalf(".acme 标记应识别为 acme，得到 %q", got)
	}
}

// TestListForeignFilesAreIgnored 校验目录里的非证书文件（私钥、其它后缀）不被当成证书。
func TestListForeignFilesAreIgnored(t *testing.T) {
	svc, dir := testService(t)
	writeTestFile(t, dir, "notes.txt", "hello")
	writeTestFile(t, dir, "orphan.key", "not a key")
	if list, perr := svc.List(); perr != nil || list.Count != 0 {
		t.Fatalf("非证书文件不应被扫描: count=%d err=%v", list.Count, perr)
	}
}

// TestListIPCertificate 校验 IP 证书的主域名取 IP SAN。
func TestListIPCertificate(t *testing.T) {
	svc, dir := testService(t)
	certPEM, _ := makeTestPair(t, testPairOptions{
		domain: "127.0.0.1", ipAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	writeTestFile(t, dir, "127.0.0.1.crt", certPEM)
	list, perr := svc.List()
	if perr != nil || list.Count != 1 {
		t.Fatalf("list 失败: count=%d err=%v", list.Count, perr)
	}
	if list.Certs[0].Domain != "127.0.0.1" || !strings.Contains(strings.Join(list.Certs[0].Domains, ","), "127.0.0.1") {
		t.Fatalf("IP 条目域名不符: %+v", list.Certs[0])
	}
}

// TestListChainFileCountedNotListed 校验独立 chain 文件计入叶子 chain_length 但不单独列出。
func TestListChainFileCountedNotListed(t *testing.T) {
	svc, dir := testService(t)
	leaf, _ := makeTestPair(t, testPairOptions{domain: "leaf.kore.local", dnsNames: []string{"leaf.kore.local"}})
	chain, _ := makeTestPair(t, testPairOptions{domain: "Intermediate", dnsNames: []string{"Intermediate"}, isCA: true})
	writeTestFile(t, dir, "leaf.kore.local.crt", leaf)
	writeTestFile(t, dir, "leaf.kore.local.chain.pem", chain)
	list, perr := svc.List()
	if perr != nil || list.Count != 1 {
		t.Fatalf("chain 文件不应单独列出: count=%d err=%v", list.Count, perr)
	}
	if list.Certs[0].ChainLength != 2 {
		t.Fatalf("chain_length=%d，期望 2", list.Certs[0].ChainLength)
	}
}

// TestListUnreadableFileIsErrorEntry 校验权限拒绝等读取失败也按条目 error 处理。
func TestListUnreadableFileIsErrorEntry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 不受文件权限限制，跳过")
	}
	svc, dir := testService(t)
	path := writeTestFile(t, dir, "blocked.kore.local.crt", "x")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 失败: %v", err)
	}
	defer func() { _ = os.Chmod(path, 0o644) }()
	list, perr := svc.List()
	if perr != nil || list.Count != 1 {
		t.Fatalf("count=%d err=%v", list.Count, perr)
	}
	if list.Certs[0].Error == "" {
		t.Fatalf("不可读文件应带 error: %+v", list.Certs[0])
	}
}
