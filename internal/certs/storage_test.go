package certs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveMetaDir 验证元数据根解析：$KORE_PLUGIN_DATA 优先、显式 Options.MetaDir 最高、
// 都缺失时回退证书目录（阶段 C 之前的完全兼容行为）。
func TestResolveMetaDir(t *testing.T) {
	t.Setenv(PluginDataEnv, "")
	if got := ResolveMetaDir("/etc/kore/ssl"); got != "/etc/kore/ssl" {
		t.Fatalf("无 KORE_PLUGIN_DATA 时应回退证书目录，实际 %q", got)
	}
	t.Setenv(PluginDataEnv, "/install/data/plugins/ssl")
	if got := ResolveMetaDir("/etc/kore/ssl"); got != filepath.Join("/install/data/plugins/ssl", "ssl") {
		t.Fatalf("应解析为 <KORE_PLUGIN_DATA>/ssl，实际 %q", got)
	}
	// 显式 MetaDir 覆盖环境变量。
	svc := NewService(Options{Dir: t.TempDir(), MetaDir: "/tmp/explicit-meta"})
	if svc.store.metaDir != "/tmp/explicit-meta" {
		t.Fatalf("显式 MetaDir 未生效：%q", svc.store.metaDir)
	}
	if svc.store.dir == svc.store.metaDir {
		t.Fatal("证书目录与元数据目录应分离")
	}
}

// TestMetaFilesStayPortable 验证可迁项真的落在元数据根、证书仍留在证书目录。
func TestMetaFilesStayPortable(t *testing.T) {
	certDir := t.TempDir()
	metaDir := t.TempDir()
	svc := NewService(Options{Dir: certDir, MetaDir: metaDir})
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "app.kore.local", Days: 30}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	if _, perr := svc.SetBinding(SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local"}); perr != nil {
		t.Fatalf("登记归属失败: %v", perr)
	}
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{Webroot: t.TempDir(), Confirm: true}); perr != nil {
		t.Fatalf("写 ACME 设置失败: %v", perr)
	}
	// 证书 + 标记在证书目录（web server 要读）。
	for _, name := range []string{"app.kore.local.crt", "app.kore.local.key"} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			t.Fatalf("%s 应留在证书目录: %v", name, err)
		}
	}
	// 元数据在 metaDir。
	for _, name := range []string{"bindings.json", filepath.Join(acmeDirName, acmeSettingsFileName)} {
		if _, err := os.Stat(filepath.Join(metaDir, name)); err != nil {
			t.Fatalf("%s 应迁到元数据目录: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(certDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s 不应再落在证书目录: %v", name, err)
		}
	}
}

// TestStorageInfoPortableAndSystemPaths 验证 storage 标注：元数据 portable、
// 证书目录在安装目录外时列为 system_paths 并写明"web server 必须读"。
func TestStorageInfoPortableAndSystemPaths(t *testing.T) {
	t.Setenv(PluginDataEnv, "/install/data/plugins/ssl")
	t.Setenv(InstallDirEnv, "/install")
	svc := NewService(Options{Dir: "/etc/kore/ssl"})
	info := svc.storageInfo()
	if !info.Portable {
		t.Fatalf("KORE_PLUGIN_DATA 已注入时 portable 应为 true: %+v", info)
	}
	if info.PortableRoot != "/install/data/plugins/ssl" || info.InstallDir != "/install" {
		t.Fatalf("storage 根/安装目录不符: %+v", info)
	}
	if info.MetaDir != filepath.Join("/install/data/plugins/ssl", "ssl") {
		t.Fatalf("meta_dir=%q", info.MetaDir)
	}
	if len(info.SystemPaths) == 0 {
		t.Fatal("证书目录在安装目录外时应出现在 system_paths")
	}
	entry := info.SystemPaths[0]
	if entry.Path != "/etc/kore/ssl" || entry.InsideInstall {
		t.Fatalf("system_paths 条目不符: %+v", entry)
	}
	if !strings.Contains(entry.Reason, "web server") || !strings.Contains(entry.Reason, "ADR-0023") {
		t.Fatalf("必须写明为什么在外（web server 读取 + ADR 豁免）: %q", entry.Reason)
	}
	if !strings.Contains(info.Hint, "portable") {
		t.Fatalf("hint 应说明元数据已 portable: %q", info.Hint)
	}
}

// TestStorageInfoLegacyFallback 验证未注入 KORE_PLUGIN_DATA 时的向后兼容标注。
func TestStorageInfoLegacyFallback(t *testing.T) {
	t.Setenv(PluginDataEnv, "")
	svc := NewService(Options{Dir: t.TempDir()})
	info := svc.storageInfo()
	if info.Portable || info.MetaDir != info.CertDir {
		t.Fatalf("未注入时应回退同目录且 portable=false: %+v", info)
	}
	if !strings.Contains(info.Hint, "KORE_PLUGIN_DATA") {
		t.Fatalf("hint 应说明未注入 KORE_PLUGIN_DATA: %q", info.Hint)
	}
}

// TestStorageExposedInListAndStatus 验证 list / acme.builtin.status 都带 storage 字段。
func TestStorageExposedInListAndStatus(t *testing.T) {
	t.Setenv(PluginDataEnv, t.TempDir())
	t.Setenv(InstallDirEnv, "/install")
	svc := NewService(Options{Dir: t.TempDir()})
	list, perr := svc.List()
	if perr != nil {
		t.Fatalf("list 失败: %v", perr)
	}
	if list.Storage.CertDir == "" || !list.Storage.Portable {
		t.Fatalf("list.storage 标注不完整: %+v", list.Storage)
	}
	status, perr := svc.ACMEBuiltinStatus()
	if perr != nil {
		t.Fatalf("status 失败: %v", perr)
	}
	if status.Storage.CertDir != list.Storage.CertDir || status.Storage.MetaDir != list.Storage.MetaDir {
		t.Fatalf("status 与 list 的 storage 不一致: %+v vs %+v", status.Storage, list.Storage)
	}
}
