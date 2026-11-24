package certs

import (
	"path/filepath"
	"strings"
	"testing"
)

// 本文件是「注入 = 插件写 = site 指向」三者路径一致性的可执行判据。
//
// 契约三方（缺一即 SSL 站点全被拒）：
//   - 安装器 scripts/install-root-once.sh `resolve_allow_dirs` 默认注入
//     KORE_FILE_WRITE_ALLOW_DIRS=<install>/data/ssl/（ADR-0052）；
//   - 本仓证书目录 = <KORE_INSTALL_DIR>/data/ssl（ADR-0023 §3.4 方案 C）；
//   - site.bindSSL 的 cert_path/key_path 取本仓 store 的绝对路径，site 把它写进站点配置时
//     要过上面那道前缀白名单（ADR-0052 §104 的证书路径判据）。

// installRoot 是样例安装根。
const installRoot = "/opt/kore"

// installAllowDirs 复刻安装器的默认白名单：`<install>/data/ssl/`（尾斜杠是判据的一部分，
// 内核按「路径前缀在列表内」放行，少了斜杠会把 `data/ssl-evil/` 也算进来）。
func installAllowDirs(install string) []string {
	return []string{filepath.Join(install, installCertSubdir) + "/"}
}

// withinAllowDirs 复刻内核受控写的前缀判定（只做前缀匹配，不做通配）。
func withinAllowDirs(path string, dirs []string) bool {
	for _, dir := range dirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	return false
}

// kernelEnv 按 supervisor/start.go 的真实注入值构造环境：
// KORE_INSTALL_DIR=<install>，KORE_STATE_DIR=<install>/data/plugins/<id>。
func kernelEnv(t *testing.T, id string) {
	t.Helper()
	t.Setenv(DirEnv, "")
	t.Setenv(installDirEnv, installRoot)
	t.Setenv(kernelStateEnv, filepath.Join(installRoot, "data", "plugins", id))
}

// TestCertDirMatchesInstallerAllowDirs 断言插件默认目录与安装器注入值是同一目录。
func TestCertDirMatchesInstallerAllowDirs(t *testing.T) {
	kernelEnv(t, "ssl")
	allow := installAllowDirs(installRoot)

	dir, source := ResolveCertDir()
	want := filepath.Join(installRoot, installCertSubdir)
	if dir != want || source != DirSourceInstall {
		t.Fatalf("证书目录=(%q,%q)，期望 (%q,install-dir)", dir, source, want)
	}
	if dir != strings.TrimSuffix(allow[0], "/") {
		t.Fatalf("证书目录 %q 与安装器白名单 %q 不是同一目录", dir, allow[0])
	}
	t.Logf("安装器注入白名单 = %s", allow[0])
	t.Logf("插件证书目录     = %s（来源 %s）", dir, source)
}

// TestCertAndKeyPathsAreWritable 断言 ssl 落盘的证书/私钥路径（也就是 site 绑定时
// 传给 cert_path/key_path 的取值）都落在白名单内。
func TestCertAndKeyPathsAreWritable(t *testing.T) {
	kernelEnv(t, "ssl")
	allow := installAllowDirs(installRoot)
	svc := NewService(Options{Dir: "", MetaDir: t.TempDir()})

	certPath := svc.store.certAbsPath("example.com.crt")
	keyPath := svc.store.certAbsPath("example.com.key")
	for _, p := range []string{svc.store.dir + "/", certPath, keyPath} {
		if !withinAllowDirs(p, allow) {
			t.Fatalf("%q 不在安装器白名单 %v 内：site.bindSSL 绑定证书会被受控写拒绝", p, allow)
		}
		t.Logf("受控写放行 ✓ %s", p)
	}
}

// TestLegacyStateCertDirIsRejected 是反例自证：把解析改回 0.7.0 的口径
// （只认 <KORE_STATE_DIR>/ssl）时落点变成 <install>/data/plugins/ssl/ssl，
// 必须被同一个前缀判定拒掉——证明上面两条断言真能 FAIL，不是装饰。
func TestLegacyStateCertDirIsRejected(t *testing.T) {
	t.Setenv(DirEnv, "")
	t.Setenv(installDirEnv, "") // 模拟修复前：安装根未被用来定位证书目录
	t.Setenv(kernelStateEnv, filepath.Join(installRoot, "data", "plugins", "ssl"))

	legacy, source := ResolveCertDir()
	want := filepath.Join(installRoot, "data", "plugins", "ssl", "ssl")
	if legacy != want || source != DirSourceKernelState {
		t.Fatalf("兼容兜底=(%q,%q)，期望 (%q,kernel-state)", legacy, source, want)
	}
	allow := installAllowDirs(installRoot)
	legacyCert := filepath.Join(legacy, "example.com.crt")
	if withinAllowDirs(legacyCert, allow) {
		t.Fatalf("旧口径证书路径 %q 竟被判在白名单 %v 内——反例失效，一致性断言不可信", legacyCert, allow)
	}
	// 阳性对照：只把旧目录也加进白名单，同一路径必须放行 —— 证明判定只取决于前缀，
	// 上面那次 FAIL 是「目录不对」，不是判定本身写死返回 false。
	if !withinAllowDirs(legacyCert, append(append([]string{}, allow...), legacy+"/")) {
		t.Fatal("阳性对照失败：把旧目录加进白名单后仍未放行，判定逻辑不可信")
	}
}
