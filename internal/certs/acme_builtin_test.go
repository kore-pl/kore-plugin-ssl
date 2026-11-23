package certs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	acmeproto "github.com/pengtang1024/kore-plugin-ssl/internal/acme"
	"github.com/pengtang1024/kore-plugin-ssl/internal/acme/acmetest"
)

// newACMEService 返回指向临时目录的服务（无故障注入）。
func newACMEService(t *testing.T) (*Service, string) {
	t.Helper()
	return testService(t)
}

// newACMEWebrootService 构造带 HTTP-01 预检替身的服务：
// 用回环文件服务模拟"站点根可通过 http://域名/.well-known/... 访问到"，
// 让续期路径的预检能在测试里真实通过（生产用域名 + 80 端口）。
func newACMEWebrootService(t *testing.T, webroot string) (*Service, string) {
	t.Helper()
	fileServer := httptest.NewServer(http.FileServer(http.Dir(webroot)))
	t.Cleanup(fileServer.Close)
	parsed, err := url.Parse(fileServer.URL)
	if err != nil {
		t.Fatalf("解析测试服务地址失败: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("取端口失败: %v", err)
	}
	dir := t.TempDir()
	return NewService(Options{Dir: dir, ACMEPrecheckPort: port, ACMEPrecheckHost: "127.0.0.1"}), dir
}

// configureMockCA 用 ssl.acme.auto 把服务指向本地 mock CA，并配置 webroot。
func configureMockCA(t *testing.T, svc *Service, webroot, directoryURL string) *ACMEAutoResult {
	t.Helper()
	result, perr := svc.ACMEAuto(ACMEAutoRequest{
		CA: "custom", DirectoryURL: directoryURL,
		Webroot: webroot, Email: "ops@example.com", Confirm: true,
	})
	if perr != nil {
		t.Fatalf("配置 mock CA 失败: %v（hint=%s）", perr, perr.Hint)
	}
	return result
}

// TestACMEAutoDefaultsClosed 验证出厂默认：staging CA、自动续期关闭、续期方法拒绝且零联网。
func TestACMEAutoDefaultsClosed(t *testing.T) {
	svc, _ := newACMEService(t)
	mock := acmetest.New(t, acmetest.Options{})
	status, perr := svc.ACMEBuiltinStatus()
	if perr != nil {
		t.Fatalf("status 失败: %v", perr)
	}
	if status.CA != acmeproto.CAStaging {
		t.Fatalf("默认 CA=%q，期望 staging（避免一上来打满生产配额）", status.CA)
	}
	if status.AutoRenew {
		t.Fatal("自动续期必须默认关闭（G-10）")
	}
	if status.DaysBefore != acmeDefaultDaysBefore {
		t.Fatalf("默认 days_before=%d", status.DaysBefore)
	}
	if status.EABConfigured {
		t.Fatal("默认不应有 EAB")
	}
	// 预设里必须能查到 LiteSSL 的 directory 与 EAB 要求（UI 依赖它）。
	var litessl *acmeproto.CAPreset
	for index := range status.Presets {
		if status.Presets[index].ID == acmeproto.CALiteSSL {
			litessl = &status.Presets[index]
		}
	}
	if litessl == nil || !litessl.RequiresEAB || litessl.DirectoryURL != "https://acme.litessl.com/acme/v2/directory" {
		t.Fatalf("LiteSSL 预设不符: %+v", litessl)
	}

	// 未开启自动续期：renew 直接拒绝，且不得发生任何网络请求。
	before := mock.Requests()
	if _, perr := svc.ACMEBuiltinRenew(ACMEBuiltinRenewRequest{}); perr == nil || perr.Code != codeUnsupported {
		t.Fatalf("自动续期关闭时 renew 应 E_UNSUPPORTED，实际 %v", perr)
	}
	if after := mock.Requests(); after != before {
		t.Fatalf("关闭状态不得联网：before=%d after=%d", before, after)
	}
}

// TestACMEAutoRequiresConfirm 验证配置写入必须显式 confirm。
func TestACMEAutoRequiresConfirm(t *testing.T) {
	svc, dir := newACMEService(t)
	enabled := true
	result, perr := svc.ACMEAuto(ACMEAutoRequest{Enabled: &enabled, Confirm: false})
	if result != nil {
		t.Fatalf("未确认不应返回结果: %+v", result)
	}
	if perr == nil || perr.Code != codeInvalid {
		t.Fatalf("应 E_INVALID，实际 %v", perr)
	}
	if !strings.Contains(perr.Hint, "confirm") {
		t.Fatalf("hint 应说明带 confirm：%q", perr.Hint)
	}
	if _, err := os.Stat(filepath.Join(dir, acmeDirName, acmeSettingsFileName)); !os.IsNotExist(err) {
		t.Fatalf("未确认不应写设置文件: %v", err)
	}
}

// TestACMEAutoEnableRequiresWebroot 验证开启自动续期前必须有可用 webroot。
func TestACMEAutoEnableRequiresWebroot(t *testing.T) {
	svc, _ := newACMEService(t)
	enabled := true
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{Enabled: &enabled, Confirm: true}); perr == nil ||
		perr.Code != codeInvalid || !strings.Contains(perr.Hint, "webroot") {
		t.Fatalf("缺 webroot 应 E_INVALID 且 hint 指向 webroot，实际 %v", perr)
	}
	webroot := t.TempDir()
	result, perr := svc.ACMEAuto(ACMEAutoRequest{Enabled: &enabled, Webroot: webroot, Confirm: true})
	if perr != nil {
		t.Fatalf("配置 webroot 后应开启成功: %v（hint=%s）", perr, perr.Hint)
	}
	if !result.AutoRenew || result.Warning == "" {
		t.Fatalf("开启后应有 auto_renew=true + 联网警告: %+v", result)
	}
	if !strings.Contains(result.Warning, "联网") {
		t.Fatalf("warning 应说明会联网：%q", result.Warning)
	}
	if result.Task.Method != "ssl.acme.builtin.renew" || result.Task.Plugin != "ssl" {
		t.Fatalf("推荐任务不符: %+v", result.Task)
	}
	if result.Task.Schedule != acmeAutoTaskSchedule {
		t.Fatalf("任务 cron=%q，期望 %q", result.Task.Schedule, acmeAutoTaskSchedule)
	}
	// 设置文件权限必须是 0600（含 EAB 等敏感项）。
	info, err := os.Stat(filepath.Join(result.UpdatedAt, ""))
	if err == nil {
		t.Fatalf("UpdatedAt 不应是可 stat 的路径: %v", info)
	}
	settingsPath := filepath.Join(mustDir(t, svc), acmeDirName, acmeSettingsFileName)
	fileInfo, statErr := os.Stat(settingsPath)
	if statErr != nil {
		t.Fatalf("设置文件不存在: %v", statErr)
	}
	if perm := fileInfo.Mode().Perm(); perm != keyFileMode {
		t.Fatalf("设置文件权限=%o，期望 %o", perm, keyFileMode)
	}
}

// TestACMEAutoLiteSSLRequiresEAB 验证 LiteSSL 预设强制 EAB，且状态输出脱敏。
func TestACMEAutoLiteSSLRequiresEAB(t *testing.T) {
	svc, _ := newACMEService(t)
	webroot := t.TempDir()
	enabled := true
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{
		Enabled: &enabled, CA: acmeproto.CALiteSSL, Webroot: webroot, Confirm: true,
	}); perr == nil || !strings.Contains(perr.Hint, "EAB") {
		t.Fatalf("LiteSSL 无 EAB 应拒绝并提示 EAB，实际 %v", perr)
	}
	const hmacKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	result, perr := svc.ACMEAuto(ACMEAutoRequest{
		Enabled: &enabled, CA: acmeproto.CALiteSSL, Webroot: webroot,
		EABKid: "eab-kid-1", EABHMACKey: hmacKey, Confirm: true,
	})
	if perr != nil {
		t.Fatalf("带 EAB 应开启成功: %v（hint=%s）", perr, perr.Hint)
	}
	if result.DirectoryURL != "https://acme.litessl.com/acme/v2/directory" {
		t.Fatalf("LiteSSL directory=%q", result.DirectoryURL)
	}
	if !result.EABConfigured {
		t.Fatal("EABConfigured 应为 true")
	}
	status, _ := svc.ACMEBuiltinStatus()
	raw, _ := json.Marshal(status)
	if strings.Contains(string(raw), hmacKey) {
		t.Fatal("status 输出不得包含 EAB hmac key（敏感凭据）")
	}
	if !status.EABConfigured {
		t.Fatal("status 应报告 eab_configured=true")
	}
}

// TestACMEIssueEndToEnd 用本地 mock CA 跑完整签发：落盘、标记、来源、审计。
func TestACMEIssueEndToEnd(t *testing.T) {
	svc, dir := newACMEService(t)
	webroot := t.TempDir()
	mock := acmetest.New(t, acmetest.Options{Webroot: webroot})
	configureMockCA(t, svc, webroot, mock.DirectoryURL())

	result, perr := svc.ACMEBuiltinIssue(ACMEBuiltinIssueRequest{
		Domain: "acme.kore.local", AltNames: []string{"www.acme.kore.local"},
		Confirm: true, SkipPrecheck: true,
	})
	if perr != nil {
		t.Fatalf("签发失败: %v（hint=%s）", perr, perr.Hint)
	}
	if result.ChainLength != 2 || result.DaysLeft < 80 {
		t.Fatalf("签发结果异常: %+v", result)
	}
	if !strings.HasSuffix(result.CertPath, "acme.kore.local.crt") {
		t.Fatalf("证书路径=%q", result.CertPath)
	}
	for _, path := range []string{result.CertPath, result.KeyPath, result.ChainPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("文件应存在 %s: %v", path, err)
		}
	}
	if info, err := os.Stat(result.KeyPath); err != nil || info.Mode().Perm() != keyFileMode {
		t.Fatalf("私钥权限应为 0600: %v err=%v", info, err)
	}
	marker := filepath.Join(dir, "acme.kore.local.acme")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf(".acme 归属标记应存在: %v", err)
	}
	list, _ := svc.List()
	if list.Count != 1 || list.Certs[0].Source != "acme" {
		t.Fatalf("list 应把 ACME 证书识别为 acme：%+v", list.Certs)
	}
	status, _ := svc.ACMEBuiltinStatus()
	if len(status.LastAudit) == 0 || status.LastAudit[0].Result != "ok" || status.LastAudit[0].Action != "issue" {
		t.Fatalf("审计应记录一次成功签发: %+v", status.LastAudit)
	}
}

// TestACMEBuiltinIssueRequiresConfirm 验证未确认时零联网。
func TestACMEBuiltinIssueRequiresConfirm(t *testing.T) {
	svc, _ := newACMEService(t)
	webroot := t.TempDir()
	mock := acmetest.New(t, acmetest.Options{Webroot: webroot})
	configureMockCA(t, svc, webroot, mock.DirectoryURL())
	before := mock.Requests()
	if _, perr := svc.ACMEBuiltinIssue(ACMEBuiltinIssueRequest{Domain: "nope.kore.local"}); perr == nil ||
		perr.Code != codeInvalid {
		t.Fatalf("未确认应 E_INVALID，实际 %v", perr)
	}
	if after := mock.Requests(); after != before {
		t.Fatalf("未确认不得联网：before=%d after=%d", before, after)
	}
}

// TestACMEIssueFailureWritesNothing 验证失败路径不落任何证书。
func TestACMEIssueFailureWritesNothing(t *testing.T) {
	svc, dir := newACMEService(t)
	webroot := t.TempDir()
	mock := acmetest.New(t, acmetest.Options{Webroot: webroot, ChallengeInvalid: true})
	configureMockCA(t, svc, webroot, mock.DirectoryURL())
	if _, perr := svc.ACMEBuiltinIssue(ACMEBuiltinIssueRequest{
		Domain: "fail.kore.local", Confirm: true, SkipPrecheck: true,
	}); perr == nil {
		t.Fatal("challenge 失败时应报错")
	}
	list, _ := svc.List()
	if list.Count != 0 {
		t.Fatalf("失败不应留下证书: %+v", list.Certs)
	}
	status, _ := svc.ACMEBuiltinStatus()
	if len(status.LastAudit) == 0 || status.LastAudit[0].Result != "failed" {
		t.Fatalf("失败应进审计: %+v", status.LastAudit)
	}
	_ = dir
}

// TestACMEAutoRenewSkipsNotDue 验证未到窗口的续期是 no-op 且不联网。
func TestACMEAutoRenewSkipsNotDue(t *testing.T) {
	svc, _ := newACMEService(t)
	webroot := t.TempDir()
	mock := acmetest.New(t, acmetest.Options{Webroot: webroot})
	configureMockCA(t, svc, webroot, mock.DirectoryURL())
	if _, perr := svc.ACMEBuiltinIssue(ACMEBuiltinIssueRequest{
		Domain: "fresh.kore.local", Confirm: true, SkipPrecheck: true,
	}); perr != nil {
		t.Fatalf("预置证书失败: %v", perr)
	}
	enabled := true
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{Enabled: &enabled, DaysBefore: 30, Confirm: true}); perr != nil {
		t.Fatalf("开启自动续期失败: %v", perr)
	}
	before := mock.Requests()
	result, perr := svc.ACMEBuiltinRenew(ACMEBuiltinRenewRequest{})
	if perr != nil {
		t.Fatalf("未到期续期应成功返回（只是跳过）: %v", perr)
	}
	if result.Skipped != 1 || result.Renewed != 0 {
		t.Fatalf("应跳过 1 张：%+v", result)
	}
	if after := mock.Requests(); after != before {
		t.Fatalf("未到期不应联网：before=%d after=%d", before, after)
	}
}

// TestACMEAutoRenewRenewsDue 验证到期证书被续期且旧证书有备份。
func TestACMEAutoRenewRenewsDue(t *testing.T) {
	webroot := t.TempDir()
	svc, dir := newACMEWebrootService(t, webroot)
	mock := acmetest.New(t, acmetest.Options{Webroot: webroot})
	configureMockCA(t, svc, webroot, mock.DirectoryURL())
	if _, perr := svc.ACMEBuiltinIssue(ACMEBuiltinIssueRequest{
		Domain: "due.kore.local", Confirm: true, SkipPrecheck: true,
	}); perr != nil {
		t.Fatalf("预置证书失败: %v", perr)
	}
	enabled := true
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{Enabled: &enabled, DaysBefore: 120, Confirm: true}); perr != nil {
		t.Fatalf("开启自动续期失败: %v", perr)
	}
	result, perr := svc.ACMEBuiltinRenew(ACMEBuiltinRenewRequest{})
	if perr != nil {
		t.Fatalf("续期失败: %v（hint=%s）", perr, perr.Hint)
	}
	if result.Renewed != 1 || result.Failed != 0 {
		t.Fatalf("应成功续期 1 张：%+v", result)
	}
	entry := result.Certs[0]
	if entry.Action != "renewed" || entry.BackupPath == "" {
		t.Fatalf("续期条目应有备份路径: %+v", entry)
	}
	backups, err := filepath.Glob(filepath.Join(dir, backupDirName, "due.kore.local-*.crt"))
	if err != nil || len(backups) == 0 {
		t.Fatalf("应有旧证书备份: %v err=%v", backups, err)
	}
	list, _ := svc.List()
	if list.Count != 1 || list.Certs[0].Source != "acme" || list.Certs[0].DaysLeft < 80 {
		t.Fatalf("续期后证书异常: %+v", list.Certs)
	}
}

// TestACMEAutoRenewFailureKeepsOldCert 验证续期失败时旧证书字节不变。
func TestACMEAutoRenewFailureKeepsOldCert(t *testing.T) {
	webroot := t.TempDir()
	svc, _ := newACMEWebrootService(t, webroot)
	good := acmetest.New(t, acmetest.Options{Webroot: webroot})
	configureMockCA(t, svc, webroot, good.DirectoryURL())
	issued, perr := svc.ACMEBuiltinIssue(ACMEBuiltinIssueRequest{
		Domain: "keep.kore.local", Confirm: true, SkipPrecheck: true,
	})
	if perr != nil {
		t.Fatalf("预置证书失败: %v", perr)
	}
	oldCert, err := os.ReadFile(issued.CertPath)
	if err != nil {
		t.Fatalf("读旧证书失败: %v", err)
	}
	// 把 CA 切到注定失败的 mock。
	bad := acmetest.New(t, acmetest.Options{Webroot: webroot, ChallengeInvalid: true})
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{
		CA: "custom", DirectoryURL: bad.DirectoryURL(), DaysBefore: 120, Confirm: true,
	}); perr != nil {
		t.Fatalf("切换 CA 失败: %v", perr)
	}
	enabled := true
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{Enabled: &enabled, Confirm: true}); perr != nil {
		t.Fatalf("开启失败: %v", perr)
	}
	result, perr := svc.ACMEBuiltinRenew(ACMEBuiltinRenewRequest{})
	if perr == nil {
		t.Fatalf("全部失败应返回协议错误，实际成功: %+v", result)
	}
	if result == nil || result.Failed != 1 || result.Renewed != 0 {
		t.Fatalf("失败计数不符: %+v", result)
	}
	newCert, err := os.ReadFile(issued.CertPath)
	if err != nil {
		t.Fatalf("读回证书失败: %v", err)
	}
	if string(newCert) != string(oldCert) {
		t.Fatal("续期失败不得覆盖旧证书")
	}
	status, _ := svc.ACMEBuiltinStatus()
	if status.LastAudit[0].Result != "failed" || status.LastAudit[0].Action != "renew" {
		t.Fatalf("失败应进审计: %+v", status.LastAudit)
	}
}

// mustDir 取服务的证书目录（测试用）。
func mustDir(t *testing.T, svc *Service) string {
	t.Helper()
	return svc.store.dir
}
