package certs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// httpsFixture 返回带自签证书的服务与证书目录（固定时钟保证快照稳定）。
func httpsFixture(t *testing.T) (*Service, string, time.Time) {
	t.Helper()
	dir := t.TempDir()
	now := time.Date(2026, 11, 23, 20, 0, 0, 0, time.UTC)
	svc := NewService(Options{Dir: dir, Now: func() time.Time { return now }})
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "app.kore.local", Days: 90}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	return svc, dir, now
}

// TestHTTPSEnforceRequiresCert 验证没有证书的域名拒绝开启（443 不可能存在）。
func TestHTTPSEnforceRequiresCert(t *testing.T) {
	svc, _, _ := httpsFixture(t)
	result, perr := svc.HTTPSEnforce("nocert.kore.local")
	if result != nil {
		t.Fatalf("无证书不应返回结果: %+v", result)
	}
	if perr == nil || perr.Code != codeInvalid {
		t.Fatalf("应 E_INVALID，实际 %v", perr)
	}
	if !strings.Contains(perr.Hint, "证书") || !strings.Contains(perr.Hint, "site.bindSSL") {
		t.Fatalf("hint 应引导先绑证书: %q", perr.Hint)
	}
}

// TestHTTPSEnforceIdempotent 验证幂等：重复 enforce 不产生重复条目、changed=false。
func TestHTTPSEnforceIdempotent(t *testing.T) {
	svc, dir, now := httpsFixture(t)
	first, perr := svc.HTTPSEnforce("app.kore.local")
	if perr != nil {
		t.Fatalf("首次 enforce 失败: %v", perr)
	}
	if !first.Created || !first.Changed || first.Source != "plugin" {
		t.Fatalf("首次结果不符: %+v", first)
	}
	if first.ApplyHint.Plugin != "site" || first.ApplyHint.Method != "site.bindSSL" ||
		first.ApplyHint.Params.ForceHTTPS == nil || !*first.ApplyHint.Params.ForceHTTPS {
		t.Fatalf("apply_hint 应是 site.bindSSL + force_https=true: %+v", first.ApplyHint)
	}
	second, perr := svc.HTTPSEnforce("app.kore.local")
	if perr != nil {
		t.Fatalf("重复 enforce 失败: %v", perr)
	}
	if second.Created || second.Changed {
		t.Fatalf("重复 enforce 应 created=false changed=false: %+v", second)
	}
	// 落盘快照：单条、0600、字段固定。
	raw, err := os.ReadFile(filepath.Join(dir, httpsStateFileName))
	if err != nil {
		t.Fatalf("状态文件不存在: %v", err)
	}
	want := `{
  "schema": 1,
  "entries": [
    {
      "domain": "app.kore.local",
      "enforced": true,
      "updated_at": "` + now.UTC().Format(time.RFC3339) + `"
    }
  ]
}
`
	if string(raw) != want {
		t.Fatalf("状态文件快照不符：\n--- got ---\n%s\n--- want ---\n%s", raw, want)
	}
	if info, err := os.Stat(filepath.Join(dir, httpsStateFileName)); err != nil || info.Mode().Perm() != keyFileMode {
		t.Fatalf("状态文件权限应为 0600: %v err=%v", info, err)
	}
	// apply_hint 快照（路径随临时目录，只锁形状与语义）。
	hintRaw, _ := json.Marshal(second.ApplyHint)
	for _, fragment := range []string{
		`"plugin":"site"`, `"method":"site.bindSSL"`, `"domain":"app.kore.local"`,
		`"force_https":true`, `"cert_path":"` + dir + `/app.kore.local.crt"`,
		`"key_path":"` + dir + `/app.kore.local.key"`,
	} {
		if !strings.Contains(string(hintRaw), fragment) {
			t.Fatalf("apply_hint 缺片段 %s: %s", fragment, hintRaw)
		}
	}
}

// TestHTTPSUnenforceOnlyOwn 验证卸载只删自己那条，不影响其它域名与站点配置。
func TestHTTPSUnenforceOnlyOwn(t *testing.T) {
	svc, _, _ := httpsFixture(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "api.kore.local", Days: 90}); perr != nil {
		t.Fatalf("自签 api 失败: %v", perr)
	}
	for _, domain := range []string{"app.kore.local", "api.kore.local"} {
		if _, perr := svc.HTTPSEnforce(domain); perr != nil {
			t.Fatalf("enforce %s 失败: %v", domain, perr)
		}
	}
	result, perr := svc.HTTPSUnenforce("app.kore.local")
	if perr != nil {
		t.Fatalf("unenforce 失败: %v", perr)
	}
	if !result.Removed || result.Enforced {
		t.Fatalf("卸载结果不符: %+v", result)
	}
	if result.ApplyHint.Params.ForceHTTPS == nil || *result.ApplyHint.Params.ForceHTTPS {
		t.Fatalf("卸载的 apply_hint 应建议 force_https=false: %+v", result.ApplyHint)
	}
	// 另一个域名仍保留。
	if enforced, registered := svc.httpsEnforced("api.kore.local"); !registered || !enforced {
		t.Fatal("不应影响其它域名的登记")
	}
	// 重复卸载幂等（removed=false，不报错）。
	again, perr := svc.HTTPSUnenforce("app.kore.local")
	if perr != nil || again.Removed {
		t.Fatalf("重复卸载应 removed=false 且无错误: %+v / %v", again, perr)
	}
}

// TestHTTPSStatusThreeStates 验证 status 的 enforced/source/redirect_code 三态：
// plugin（本仓登记）/ manual（未登记但实测在跳）/ none（都没有）。
func TestHTTPSStatusThreeStates(t *testing.T) {
	httpPort, _ := startHTTPProbeServer(t, true)
	httpsPort, _ := startHTTPSProbeServer(t)
	probe := HTTPSStatusRequest{Domain: "127.0.0.1", HTTPPort: httpPort, HTTPSPort: httpsPort}

	// plugin：直接写登记（等价于 enforce 后的状态），实测 80 也跳。
	pluginSvc := NewService(Options{Dir: t.TempDir()})
	if err := pluginSvc.store.saveHTTPSState(httpsStateFile{
		Schema:  httpsStateSchema,
		Entries: []httpsStateEntry{{Domain: "127.0.0.1", Enforced: true, UpdatedAt: "2026-11-23T20:00:00Z"}},
	}); err != nil {
		t.Fatalf("写入登记失败: %v", err)
	}
	result, perr := pluginSvc.HTTPSStatus(probe)
	if perr != nil {
		t.Fatalf("status 失败: %v", perr)
	}
	if result.Source != "plugin" || !result.Enforced || result.RedirectCode != 301 {
		t.Fatalf("plugin 态不符: source=%q enforced=%v code=%d", result.Source, result.Enforced, result.RedirectCode)
	}
	if result.Verdict != VerdictForceHTTPS {
		t.Fatalf("verdict=%q", result.Verdict)
	}

	// manual：没有登记，但 80 实测在跳。
	manualSvc := NewService(Options{Dir: t.TempDir()})
	manual, perr := manualSvc.HTTPSStatus(probe)
	if perr != nil {
		t.Fatalf("status 失败: %v", perr)
	}
	if manual.Source != "manual" || manual.Enforced || !manual.ForceHTTPS {
		t.Fatalf("manual 态不符: %+v", manual)
	}

	// none：没有登记，80 不跳。
	plainPort, _ := startHTTPProbeServer(t, false)
	noneSvc := NewService(Options{Dir: t.TempDir()})
	none, perr := noneSvc.HTTPSStatus(HTTPSStatusRequest{
		Domain: "127.0.0.1", HTTPPort: plainPort, HTTPSPort: httpsPort,
	})
	if perr != nil {
		t.Fatalf("status 失败: %v", perr)
	}
	if none.Source != "none" || none.Enforced || none.RedirectCode != 200 {
		t.Fatalf("none 态不符: source=%q enforced=%v code=%d", none.Source, none.Enforced, none.RedirectCode)
	}
}

// TestHTTPSEnforceWritesAudit 验证登记写操作进审计（可追溯到域名与动作）。
func TestHTTPSEnforceWritesAudit(t *testing.T) {
	svc, _, _ := httpsFixture(t)
	if _, perr := svc.HTTPSEnforce("app.kore.local"); perr != nil {
		t.Fatalf("enforce 失败: %v", perr)
	}
	if _, perr := svc.HTTPSUnenforce("app.kore.local"); perr != nil {
		t.Fatalf("unenforce 失败: %v", perr)
	}
	entries := svc.acmeAuditTail(4)
	if len(entries) < 2 {
		t.Fatalf("审计条数不足: %+v", entries)
	}
	actions := []string{entries[0].Action, entries[1].Action}
	joined := strings.Join(actions, ",")
	if !strings.Contains(joined, "https-unenforce") || !strings.Contains(joined, "https-enforce") {
		t.Fatalf("审计应记录两次写动作（最近在前）: %v", actions)
	}
}
