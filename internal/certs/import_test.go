package certs

import (
	"encoding/pem"
	"net"
	"os"
	"strings"
	"testing"
)

// TestImportRoundTrip 校验导入落盘：字段、权限、磁盘字节与 list 口径一致。
func TestImportRoundTrip(t *testing.T) {
	svc, dir := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{domain: "import.kore.local"})
	info, perr := svc.Import(ImportRequest{Domain: "import.kore.local", CertPEM: certPEM, KeyPEM: keyPEM})
	if perr != nil {
		t.Fatalf("导入失败: %v", perr)
	}
	if info.Domain != "import.kore.local" || !containsString(info.Domains, "import.kore.local") {
		t.Fatalf("导入结果域名不符: %+v", info)
	}
	if !info.SelfSigned || info.Source != "self-signed" {
		t.Fatalf("导入的自签证书应标记 self-signed: %+v", info)
	}
	if info.KeyType != "rsa" || info.KeyBits != 2048 || info.ChainLength != 1 {
		t.Fatalf("公钥/链长不符: %s/%d chain=%d", info.KeyType, info.KeyBits, info.ChainLength)
	}
	if fileMode(t, dir+"/import.kore.local.crt") != 0o644 {
		t.Fatal("证书权限应为 0644")
	}
	if fileMode(t, dir+"/import.kore.local.key") != 0o600 {
		t.Fatal("私钥权限应为 0600")
	}
	if got := readTestFile(t, dir+"/import.kore.local.crt"); got != certPEM {
		t.Fatal("落盘证书应与导入的 PEM 字节一致")
	}
	list, lerr := svc.List()
	if lerr != nil || list.Count != 1 || list.Certs[0].FingerprintSHA256 != info.FingerprintSHA256 {
		t.Fatalf("list 口径不一致: count=%d err=%v", list.Count, lerr)
	}
}

// TestImportWithChain 校验独立中间链：写入 .chain.pem（0644），chain_length=2，且不作为独立条目列出。
func TestImportWithChain(t *testing.T) {
	svc, dir := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{
		domain: "chain.kore.local", dnsNames: []string{"chain.kore.local"},
	})
	chainPEM, _ := makeTestPair(t, testPairOptions{
		domain: "Test Intermediate", dnsNames: []string{"Test Intermediate"}, isCA: true,
	})
	info, perr := svc.Import(ImportRequest{
		Domain: "chain.kore.local", CertPEM: certPEM, KeyPEM: keyPEM, ChainPEM: chainPEM,
	})
	if perr != nil {
		t.Fatalf("带链导入失败: %v", perr)
	}
	if info.ChainLength != 2 {
		t.Fatalf("chain_length=%d，期望 2", info.ChainLength)
	}
	if fileMode(t, dir+"/chain.kore.local.chain.pem") != 0o644 {
		t.Fatal("证书链权限应为 0644")
	}
	list, lerr := svc.List()
	if lerr != nil || list.Count != 1 {
		t.Fatalf("chain 不应作为独立条目列出: count=%d err=%v", list.Count, lerr)
	}
	if list.Certs[0].ChainLength != 2 {
		t.Fatalf("list chain_length=%d，期望 2", list.Certs[0].ChainLength)
	}
}

// TestImportRejectsMismatchedKey 证书与私钥不匹配必须 E_INVALID，且不落盘。
func TestImportRejectsMismatchedKey(t *testing.T) {
	svc, dir := testService(t)
	certPEM, _ := makeTestPair(t, testPairOptions{domain: "mismatch.kore.local", dnsNames: []string{"mismatch.kore.local"}})
	_, otherKey := makeTestPair(t, testPairOptions{domain: "other.kore.local", dnsNames: []string{"other.kore.local"}})
	info, perr := svc.Import(ImportRequest{Domain: "mismatch.kore.local", CertPEM: certPEM, KeyPEM: otherKey})
	if info != nil || perr == nil {
		t.Fatalf("不匹配私钥应被拒绝，得到 info=%+v perr=%v", info, perr)
	}
	if perr.Code != codeInvalid || !strings.Contains(perr.Message, "不匹配") {
		t.Fatalf("错误=%v，期望 E_INVALID 且含“不匹配”", perr)
	}
	assertEmptyDir(t, dir)
}

// TestImportRejectsSANMismatch 证书 SAN 不含 domain 必须 E_INVALID。
func TestImportRejectsSANMismatch(t *testing.T) {
	svc, dir := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{domain: "other.kore.local", dnsNames: []string{"other.kore.local"}})
	info, perr := svc.Import(ImportRequest{Domain: "wanted.kore.local", CertPEM: certPEM, KeyPEM: keyPEM})
	if info != nil || perr == nil {
		t.Fatalf("SAN 不含 domain 应被拒绝，得到 info=%+v perr=%v", info, perr)
	}
	if perr.Code != codeInvalid || !strings.Contains(perr.Message, "SAN") {
		t.Fatalf("错误=%v，期望 E_INVALID 且含 SAN", perr)
	}
	if !strings.Contains(perr.Message, "other.kore.local") {
		t.Fatalf("错误信息应列出证书实际标识: %q", perr.Message)
	}
	assertEmptyDir(t, dir)
}

// TestImportWildcardSAN 校验通配符 SAN 覆盖一级子域、不覆盖多级子域。
func TestImportWildcardSAN(t *testing.T) {
	svc, _ := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{domain: "*.wild.kore.local", dnsNames: []string{"*.wild.kore.local"}})
	if _, perr := svc.Import(ImportRequest{Domain: "www.wild.kore.local", CertPEM: certPEM, KeyPEM: keyPEM}); perr != nil {
		t.Fatalf("通配符应覆盖一级子域: %v", perr)
	}
	if _, perr := svc.Import(ImportRequest{Domain: "a.b.wild.kore.local", CertPEM: certPEM, KeyPEM: keyPEM}); perr == nil {
		t.Fatal("通配符不应覆盖多级子域")
	}
}

// TestImportIPDomain 校验 IP 主体按 IPAddresses 匹配（而不是 DNSNames）。
func TestImportIPDomain(t *testing.T) {
	svc, _ := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{
		domain: "127.0.0.1", ipAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	info, perr := svc.Import(ImportRequest{Domain: "127.0.0.1", CertPEM: certPEM, KeyPEM: keyPEM})
	if perr != nil {
		t.Fatalf("IP 证书导入失败: %v", perr)
	}
	if len(info.Domains) != 1 || info.Domains[0] != "127.0.0.1" {
		t.Fatalf("IP SAN 不符: %v", info.Domains)
	}
}

// TestImportRejectsEncryptedKey 覆盖两类加密私钥与传统加密 PEM 头。
func TestImportRejectsEncryptedKey(t *testing.T) {
	certPEM, _ := makeTestPair(t, testPairOptions{domain: "enc.kore.local", dnsNames: []string{"enc.kore.local"}})
	cases := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "legacy-proc-type",
			key: "-----BEGIN RSA PRIVATE KEY-----\n" +
				"Proc-Type: 4,ENCRYPTED\n" +
				"DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAA\n" +
				"-----END RSA PRIVATE KEY-----\n",
			want: "passphrase",
		},
		{
			name: "pkcs8-encrypted",
			key:  string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")})),
			want: "passphrase",
		},
		{
			name: "openssh",
			key:  string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("x")})),
			want: "OpenSSH",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, dir := testService(t)
			info, perr := svc.Import(ImportRequest{Domain: "enc.kore.local", CertPEM: certPEM, KeyPEM: tc.key})
			if info != nil || perr == nil {
				t.Fatalf("加密/非法私钥应被拒绝，得到 info=%+v perr=%v", info, perr)
			}
			if perr.Code != codeInvalid || !strings.Contains(perr.Message, tc.want) {
				t.Fatalf("错误=%v，期望 E_INVALID 且含 %q", perr, tc.want)
			}
			assertEmptyDir(t, dir)
		})
	}
}

// TestImportRejectsBadInputs 覆盖缺失字段、非证书 PEM 与非法链。
func TestImportRejectsBadInputs(t *testing.T) {
	svc, dir := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{domain: "bad.kore.local", dnsNames: []string{"bad.kore.local"}})
	cases := []struct {
		name string
		req  ImportRequest
		want string
	}{
		{"missing-cert", ImportRequest{Domain: "bad.kore.local", KeyPEM: keyPEM}, "cert_pem"},
		{"missing-key", ImportRequest{Domain: "bad.kore.local", CertPEM: certPEM}, "key_pem"},
		{"junk-cert", ImportRequest{Domain: "bad.kore.local", CertPEM: "junk", KeyPEM: keyPEM}, "cert_pem"},
		{"cert-file-has-key", ImportRequest{Domain: "bad.kore.local", CertPEM: keyPEM, KeyPEM: keyPEM}, "私钥"},
		{"bad-chain", ImportRequest{Domain: "bad.kore.local", CertPEM: certPEM, KeyPEM: keyPEM, ChainPEM: "junk"}, "chain_pem"},
		{"bad-domain", ImportRequest{Domain: "Bad.Domain", CertPEM: certPEM, KeyPEM: keyPEM}, "domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, perr := svc.Import(tc.req)
			if info != nil || perr == nil {
				t.Fatalf("应拒绝: info=%+v perr=%v", info, perr)
			}
			if !strings.Contains(perr.Message, tc.want) {
				t.Fatalf("错误信息 %q 未含 %q", perr.Message, tc.want)
			}
		})
	}
	assertEmptyDir(t, dir)
}

// TestImportFailureKeepsExistingCert 校验写入失败不会覆盖已有证书：
// 用同名目录占住私钥路径，让原子写失败，既有证书必须字节级不变。
func TestImportFailureKeepsExistingCert(t *testing.T) {
	svc, dir := testService(t)
	firstPEM, firstKey := makeTestPair(t, testPairOptions{domain: "keep.kore.local", dnsNames: []string{"keep.kore.local"}})
	if _, perr := svc.Import(ImportRequest{Domain: "keep.kore.local", CertPEM: firstPEM, KeyPEM: firstKey}); perr != nil {
		t.Fatalf("预置证书失败: %v", perr)
	}
	original := readTestFile(t, dir+"/keep.kore.local.crt")

	// 私钥路径换成目录：snapshot 读取失败，writePair 在写入前返回错误。
	if err := os.Remove(dir + "/keep.kore.local.key"); err != nil {
		t.Fatalf("移除预置私钥失败: %v", err)
	}
	if err := os.Mkdir(dir+"/keep.kore.local.key", 0o700); err != nil {
		t.Fatalf("构造失败条件失败: %v", err)
	}
	secondPEM, secondKey := makeTestPair(t, testPairOptions{domain: "keep.kore.local", dnsNames: []string{"keep.kore.local"}})
	info, perr := svc.Import(ImportRequest{Domain: "keep.kore.local", CertPEM: secondPEM, KeyPEM: secondKey})
	if info != nil || perr == nil {
		t.Fatalf("写入失败应返回错误: info=%+v perr=%v", info, perr)
	}
	if got := readTestFile(t, dir+"/keep.kore.local.crt"); got != original {
		t.Fatal("写入失败后既有证书被改写")
	}
}

// assertEmptyDir 断言目录为空（失败路径不得留下任何文件）。
func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	names, err := readDirNames(dir)
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("目录应为空，实际=%v", names)
	}
}
