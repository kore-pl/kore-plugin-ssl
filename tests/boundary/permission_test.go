//go:build linux

package boundary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
)

// 权限不足：三种真实场景，全部在非 root 下可复现（root 会绕过权限检查，用例显式 skip）。
//
//  1. 私钥文件 chmod 000：续期前必须读旧私钥做备份，读不到就要中止且不覆盖旧证书；
//  2. 证书文件 chmod 000：覆盖导入要先快照原文件，读不到就必须失败，不能"盲写"；
//  3. ACME webroot 只读：HTTP-01 要往站点根写校验文件，权限不足时必须在联网前拒绝。
//
// 关于"非 root 访问需要 root 的 ACME 端口"：本插件不监听 80/443——HTTP-01 校验文件
// 由 site 插件的 web server 提供，插件只写 webroot；因此该场景在本仓的真实映射是
// webroot 写权限（场景 3），而不是插件自己去 bind 特权端口。用例按真实代码路径覆盖，
// 不写"测 OS 而不是测插件"的伪用例。

// TestPermissionPrivateKeyUnreadableRenew 私钥 chmod 000 → 续期中止，旧证书不被覆盖。
func TestPermissionPrivateKeyUnreadableRenew(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 会绕过文件权限检查，本用例只在非 root 下有意义")
	}
	dir := t.TempDir()
	svc := newService(t, dir)
	mustSelfSign(t, svc, "perm-key.kore.local")

	certPath := filepath.Join(dir, "perm-key.kore.local.crt")
	keyPath := filepath.Join(dir, "perm-key.kore.local.key")
	before := mustReadFile(t, certPath)

	chmodRestore(t, keyPath, 0o000)

	_, perr := svc.Renew(certs.RenewRequest{Domain: "perm-key.kore.local"})
	requireCertError(t, perr, "E_INTERNAL", "permission denied")

	// 中止必须发生在覆盖之前：旧证书字节不变。
	if after := mustReadFile(t, certPath); after != before {
		t.Fatalf("权限失败路径不应覆盖旧证书：长度 %d → %d", len(before), len(after))
	}
}

// TestPermissionCertFileUnreadableImport 证书 chmod 000 → 覆盖导入失败且不写新文件。
func TestPermissionCertFileUnreadableImport(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 会绕过文件权限检查，本用例只在非 root 下有意义")
	}
	dir := t.TempDir()
	svc := newService(t, dir)
	mustSelfSign(t, svc, "perm-cert.kore.local")

	certPath := filepath.Join(dir, "perm-cert.kore.local.crt")
	chmodRestore(t, certPath, 0o000)

	// 新证书/私钥本身合法，失败只能来自"读不到原证书"。
	now := nowForTest()
	certPEM, keyPEM := certPair(t, "perm-cert.kore.local", now, now.AddDate(1, 0, 0))
	_, perr := svc.Import(certs.ImportRequest{
		Domain:  "perm-cert.kore.local",
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	})
	requireCertError(t, perr, "E_INTERNAL", "permission denied")
}

// TestPermissionACMEWebrootNotWritable webroot 目录只读 → ACME 配置在联网前被拒绝。
func TestPermissionACMEWebrootNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 会绕过目录写权限检查，本用例只在非 root 下有意义")
	}
	base := t.TempDir()
	webroot := filepath.Join(base, "site-root")
	if err := os.MkdirAll(webroot, 0o700); err != nil {
		t.Fatalf("创建 webroot 失败: %v", err)
	}
	chmodRestore(t, webroot, 0o500)

	svc := newService(t, t.TempDir())
	_, perr := svc.ACMEAuto(certs.ACMEAutoRequest{
		Confirm: true,
		CA:      "letsencrypt",
		Webroot: webroot,
	})
	requireCertError(t, perr, "E_INVALID", "permission denied")
	if perr.Hint == "" {
		t.Fatalf("权限错误必须带可操作 hint，实际为空")
	}
}

// mustReadFile 读取文件并要求成功。
func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	return string(raw)
}
