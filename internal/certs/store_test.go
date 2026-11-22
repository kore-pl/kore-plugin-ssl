package certs

import (
	"os"
	"strings"
	"testing"
)

// TestWritePairModes 校验落盘权限与链文件命名。
func TestWritePairModes(t *testing.T) {
	svc, dir := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{domain: "pair.kore.local", dnsNames: []string{"pair.kore.local"}})
	chainPEM, _ := makeTestPair(t, testPairOptions{domain: "CA", dnsNames: []string{"CA"}, isCA: true})
	if err := svc.store.writePair("pair.kore.local.crt", []byte(certPEM), []byte(keyPEM), []byte(chainPEM)); err != nil {
		t.Fatalf("writePair 失败: %v", err)
	}
	if mode := fileMode(t, dir+"/pair.kore.local.crt"); mode != 0o644 {
		t.Fatalf("证书权限=%#o", mode)
	}
	if mode := fileMode(t, dir+"/pair.kore.local.key"); mode != 0o600 {
		t.Fatalf("私钥权限=%#o", mode)
	}
	if mode := fileMode(t, dir+"/pair.kore.local.chain.pem"); mode != 0o644 {
		t.Fatalf("链权限=%#o", mode)
	}
	if mode := fileMode(t, dir); mode != 0o700 {
		t.Fatalf("目录权限=%#o", mode)
	}
}

// TestWritePairRejectsUnsafeFileName 校验文件名白名单：路径分量与非证书后缀一律拒绝。
func TestWritePairRejectsUnsafeFileName(t *testing.T) {
	svc, dir := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{domain: "x.kore.local", dnsNames: []string{"x.kore.local"}})
	for _, name := range []string{"../escape.crt", "a/b.crt", "noext", "x.crt.bak"} {
		if err := svc.store.writePair(name, []byte(certPEM), []byte(keyPEM), nil); err == nil {
			t.Fatalf("%q 应被拒绝", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("非法文件名不应落盘，目录=%v", entries)
	}
}

// TestRenewKeepsImportedPEMFileName 续期沿用用户原有的 .pem 文件名，不另建 .crt。
func TestRenewKeepsImportedPEMFileName(t *testing.T) {
	svc, dir := testService(t)
	certPEM, keyPEM := makeTestPair(t, testPairOptions{domain: "custom.kore.local", dnsNames: []string{"custom.kore.local"}})
	writeTestFile(t, dir, "custom.pem", certPEM)
	writeTestFile(t, dir, "custom.key", keyPEM)

	renewed, perr := svc.Renew(RenewRequest{Domain: "custom.kore.local", Days: 15})
	if perr != nil {
		t.Fatalf("续期失败: %v", perr)
	}
	if renewed.File != "custom.pem" {
		t.Fatalf("续期应写回 custom.pem，得到 %q", renewed.File)
	}
	if _, err := os.Stat(dir + "/custom.kore.local.crt"); !os.IsNotExist(err) {
		t.Fatalf("不应生成第二份证书文件: %v", err)
	}
	list, lerr := svc.List()
	if lerr != nil || list.Count != 1 {
		t.Fatalf("续期后应只有 1 张证书: count=%d err=%v", list.Count, lerr)
	}
}

// TestImportOverwritesExistingPEMFileName 覆盖导入沿用已有 .pem 文件名。
func TestImportOverwritesExistingPEMFileName(t *testing.T) {
	svc, dir := testService(t)
	firstPEM, firstKey := makeTestPair(t, testPairOptions{domain: "overwrite.kore.local", dnsNames: []string{"overwrite.kore.local"}})
	writeTestFile(t, dir, "overwrite.pem", firstPEM)
	writeTestFile(t, dir, "overwrite.key", firstKey)

	secondPEM, secondKey := makeTestPair(t, testPairOptions{domain: "overwrite.kore.local", dnsNames: []string{"overwrite.kore.local"}})
	info, perr := svc.Import(ImportRequest{Domain: "overwrite.kore.local", CertPEM: secondPEM, KeyPEM: secondKey})
	if perr != nil {
		t.Fatalf("覆盖导入失败: %v", perr)
	}
	if info.File != "overwrite.pem" {
		t.Fatalf("应覆盖 overwrite.pem，得到 %q", info.File)
	}
	if got := readTestFile(t, dir+"/overwrite.pem"); got != secondPEM {
		t.Fatal("覆盖导入后文件内容不是新证书")
	}
	if _, err := os.Stat(dir + "/overwrite.kore.local.crt"); !os.IsNotExist(err) {
		t.Fatalf("不应生成第二份证书文件: %v", err)
	}
}

// TestDirFromEnv 校验目录解析：环境变量优先，空值回退默认目录。
func TestDirFromEnv(t *testing.T) {
	t.Setenv(DirEnv, "")
	if got := DirFromEnv(); got != DefaultDir {
		t.Fatalf("默认目录=%q，期望 %q", got, DefaultDir)
	}
	t.Setenv(DirEnv, "/tmp/kore-ssl-custom")
	if got := DirFromEnv(); got != "/tmp/kore-ssl-custom" {
		t.Fatalf("环境变量目录=%q", got)
	}
	if strings.HasSuffix(DirFromEnv(), "/") {
		t.Fatal("目录不应带尾斜杠")
	}
}
