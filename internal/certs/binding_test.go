package certs

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newBindingFixture 返回一个装了真实自签证书的服务（证书落盘，可被归属登记引用）。
func newBindingFixture(t *testing.T) (*Service, string) {
	t.Helper()
	svc, dir := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "app.kore.local", Days: 30}); perr != nil {
		t.Fatalf("自签 app.kore.local 失败: %v", perr)
	}
	return svc, dir
}

// readBindingFile 读回登记文件并断言其落盘形状（schema / 权限）。
func readBindingFile(t *testing.T, dir string) bindingFile {
	t.Helper()
	path := filepath.Join(dir, bindingsFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("登记文件不存在: %v", err)
	}
	if perm := info.Mode().Perm(); perm != bindingsFileMode {
		t.Fatalf("登记文件权限=%o，期望 %o", perm, bindingsFileMode)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取登记文件失败: %v", err)
	}
	var file bindingFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("登记文件不是合法 JSON: %v", err)
	}
	if file.Schema != bindingsSchema {
		t.Fatalf("登记文件 schema=%d，期望 %d", file.Schema, bindingsSchema)
	}
	return file
}

// TestSetBindingPersistsAndLists 验证归属登记真实落盘、list 读回同一份事实，
// 且站点侧推荐载荷（site.bindSSL）带上证书 / 私钥路径。
func TestSetBindingPersistsAndLists(t *testing.T) {
	svc, dir := newBindingFixture(t)
	result, perr := svc.SetBinding(SetBindingRequest{
		Cert: "app.kore.local", Site: "www.kore.local", Note: "主站",
	})
	if perr != nil {
		t.Fatalf("登记归属失败: %v", perr)
	}
	if !result.Created {
		t.Fatal("首次登记应 Created=true")
	}
	binding := result.Binding
	if binding.Cert != "app.kore.local" || binding.Site != "www.kore.local" || binding.Note != "主站" {
		t.Fatalf("归属字段不符: %+v", binding)
	}
	if !binding.CertExists {
		t.Fatal("证书存在时 CertExists 应为 true")
	}
	if !strings.HasSuffix(binding.CertPath, ".crt") || !strings.HasSuffix(binding.KeyPath, ".key") {
		t.Fatalf("证书 / 私钥路径后缀不符: %q / %q", binding.CertPath, binding.KeyPath)
	}
	if !strings.HasPrefix(binding.CertPath, dir) || !strings.HasPrefix(binding.KeyPath, dir) {
		t.Fatalf("路径必须落在证书目录内: %q / %q", binding.CertPath, binding.KeyPath)
	}
	// 站点侧动作只生成建议，不执行：插件/方法/载荷必须是 site.bindSSL 形态。
	if result.SiteBind.Plugin != "site" || result.SiteBind.Method != "site.bindSSL" {
		t.Fatalf("站点侧建议应为 site.bindSSL，实际 %q / %q", result.SiteBind.Plugin, result.SiteBind.Method)
	}
	if result.SiteBind.Params.Domain != "www.kore.local" ||
		result.SiteBind.Params.CertPath != binding.CertPath ||
		result.SiteBind.Params.KeyPath != binding.KeyPath {
		t.Fatalf("站点侧载荷未带证书路径: %+v", result.SiteBind.Params)
	}
	if result.SiteBind.Params.ForceHTTPS == nil || !*result.SiteBind.Params.ForceHTTPS {
		t.Fatal("站点侧载荷应建议 force_https=true")
	}
	if result.HTTPS != nil {
		t.Fatalf("未显式给 probe 时不应发起探测: %+v", result.HTTPS)
	}

	file := readBindingFile(t, dir)
	if len(file.Bindings) != 1 {
		t.Fatalf("登记文件应有 1 条，实际 %d", len(file.Bindings))
	}
	if file.Bindings[0].Cert != "app.kore.local" || file.Bindings[0].Site != "www.kore.local" {
		t.Fatalf("落盘记录不符: %+v", file.Bindings[0])
	}

	list, perr := svc.Bindings()
	if perr != nil {
		t.Fatalf("读取归属列表失败: %v", perr)
	}
	if list.Count != 1 || len(list.Bindings) != 1 {
		t.Fatalf("列表应有 1 条，实际 count=%d len=%d", list.Count, len(list.Bindings))
	}
	if list.Bindings[0] != binding {
		t.Fatalf("list 与 set 返回不一致：\nset=%+v\nlist=%+v", binding, list.Bindings[0])
	}
}

// TestSetBindingIsIdempotent 验证同对重复登记是幂等的：只刷新 note / updated_at，
// created_at 不变、条数不增。
func TestSetBindingIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	svc := NewService(Options{Dir: dir, Now: func() time.Time { return now }})
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "app.kore.local", Days: 30}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	first, perr := svc.SetBinding(SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local", Note: "旧备注"})
	if perr != nil {
		t.Fatalf("首次登记失败: %v", perr)
	}
	now = now.Add(2 * time.Hour)
	second, perr := svc.SetBinding(SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local", Note: "新备注"})
	if perr != nil {
		t.Fatalf("重复登记失败: %v", perr)
	}
	if second.Created {
		t.Fatal("同对重复登记应 Created=false")
	}
	if second.Binding.CreatedAt != first.Binding.CreatedAt {
		t.Fatalf("created_at 不应变化：%q → %q", first.Binding.CreatedAt, second.Binding.CreatedAt)
	}
	if second.Binding.UpdatedAt == first.Binding.UpdatedAt {
		t.Fatal("updated_at 应随重复登记刷新")
	}
	if second.Binding.Note != "新备注" {
		t.Fatalf("note 未刷新: %q", second.Binding.Note)
	}
	list, _ := svc.Bindings()
	if list.Count != 1 {
		t.Fatalf("幂等登记后应仍为 1 条，实际 %d", list.Count)
	}
}

// TestSetBindingConflicts 验证一对一冲突：一张证书只能属于一个站点、一个站点只能挂一张证书。
func TestSetBindingConflicts(t *testing.T) {
	svc, dir := newBindingFixture(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "api.kore.local", Days: 30}); perr != nil {
		t.Fatalf("自签 api.kore.local 失败: %v", perr)
	}
	if _, perr := svc.SetBinding(SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local"}); perr != nil {
		t.Fatalf("首次登记失败: %v", perr)
	}

	certConflict, perr := svc.SetBinding(SetBindingRequest{Cert: "app.kore.local", Site: "admin.kore.local"})
	if perr == nil {
		t.Fatalf("同一证书登记第二个站点应冲突，实际成功: %+v", certConflict)
	}
	if perr.Code != codeConflict || !strings.Contains(perr.Message, "已归属站点") {
		t.Fatalf("证书冲突应 E_CONFLICT + 指明旧站点，实际 %+v", perr)
	}
	if perr.Hint == "" {
		t.Fatal("冲突错误必须带 hint（可操作下一步）")
	}

	siteConflict, perr := svc.SetBinding(SetBindingRequest{Cert: "api.kore.local", Site: "www.kore.local"})
	if perr == nil {
		t.Fatalf("同一站点登记第二张证书应冲突，实际成功: %+v", siteConflict)
	}
	if perr.Code != codeConflict || !strings.Contains(perr.Message, "已绑定证书") {
		t.Fatalf("站点冲突应 E_CONFLICT + 指明旧证书，实际 %+v", perr)
	}

	// 冲突失败不得留下半成品：登记文件仍是 1 条。
	file := readBindingFile(t, dir)
	if len(file.Bindings) != 1 {
		t.Fatalf("冲突登记不应写入，实际 %d 条", len(file.Bindings))
	}
}

// TestSetBindingRequiresExistingCert 验证归属只能引用真实存在的证书。
func TestSetBindingRequiresExistingCert(t *testing.T) {
	svc, _ := newBindingFixture(t)
	result, perr := svc.SetBinding(SetBindingRequest{Cert: "absent.kore.local", Site: "www.kore.local"})
	if result != nil {
		t.Fatalf("证书缺失时不应返回结果: %+v", result)
	}
	if perr == nil || perr.Code != codeNotFound {
		t.Fatalf("证书缺失应 E_NOTFOUND，实际 %+v", perr)
	}
	if perr.Hint == "" {
		t.Fatal("E_NOTFOUND 必须带 hint")
	}
}

// TestSetBindingValidation 覆盖入参校验（域名口径 / note 限长与控制字符）。
func TestSetBindingValidation(t *testing.T) {
	svc, _ := newBindingFixture(t)
	cases := []struct {
		name string
		req  SetBindingRequest
	}{
		{"empty-cert", SetBindingRequest{Cert: "", Site: "www.kore.local"}},
		{"uppercase-cert", SetBindingRequest{Cert: "APP.kore.local", Site: "www.kore.local"}},
		{"bad-site", SetBindingRequest{Cert: "app.kore.local", Site: "../etc/passwd"}},
		{"empty-site", SetBindingRequest{Cert: "app.kore.local", Site: ""}},
		{"note-too-long", SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local", Note: strings.Repeat("长", bindingNoteMaxLen+1)}},
		{"note-control", SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local", Note: "换\n行"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, perr := svc.SetBinding(tc.req); perr == nil || perr.Code != codeInvalid {
				t.Fatalf("期望 E_INVALID，实际 %+v", perr)
			}
		})
	}
}

// TestRemoveBinding 验证解除归属的三种口径：按证书、按站点、缺失与非法入参。
func TestRemoveBinding(t *testing.T) {
	svc, dir := newBindingFixture(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "api.kore.local", Days: 30}); perr != nil {
		t.Fatalf("自签 api.kore.local 失败: %v", perr)
	}
	if _, perr := svc.SetBinding(SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local"}); perr != nil {
		t.Fatalf("登记 app 失败: %v", perr)
	}
	if _, perr := svc.SetBinding(SetBindingRequest{Cert: "api.kore.local", Site: "api.kore.local"}); perr != nil {
		t.Fatalf("登记 api 失败: %v", perr)
	}

	removed, perr := svc.RemoveBinding(RemoveBindingRequest{Cert: "app.kore.local"})
	if perr != nil {
		t.Fatalf("按证书解除失败: %v", perr)
	}
	if removed.Removed != 1 || removed.Binding.Cert != "app.kore.local" {
		t.Fatalf("解除结果不符: %+v", removed)
	}
	if removed.Hint == "" {
		t.Fatal("解除结果应提示站点侧需另行 unbindSSL")
	}

	// cert 与 site 不指向同一条时不得误删。
	if _, perr := svc.RemoveBinding(RemoveBindingRequest{Cert: "api.kore.local", Site: "www.kore.local"}); perr == nil ||
		perr.Code != codeNotFound {
		t.Fatalf("cert / site 不匹配应 E_NOTFOUND，实际 %+v", perr)
	}

	// 按站点解除。
	if _, perr := svc.RemoveBinding(RemoveBindingRequest{Site: "api.kore.local"}); perr != nil {
		t.Fatalf("按站点解除失败: %v", perr)
	}
	list, _ := svc.Bindings()
	if list.Count != 0 {
		t.Fatalf("全部解除后应为 0 条，实际 %d", list.Count)
	}
	file := readBindingFile(t, dir)
	if len(file.Bindings) != 0 {
		t.Fatalf("落盘文件应清空，实际 %d 条", len(file.Bindings))
	}

	// 已经不存在 → E_NOTFOUND。
	if _, perr := svc.RemoveBinding(RemoveBindingRequest{Cert: "app.kore.local"}); perr == nil ||
		perr.Code != codeNotFound {
		t.Fatalf("重复解除应 E_NOTFOUND，实际 %+v", perr)
	}
	// cert / site 都不给 → E_INVALID。
	if _, perr := svc.RemoveBinding(RemoveBindingRequest{}); perr == nil || perr.Code != codeInvalid {
		t.Fatalf("空入参应 E_INVALID，实际 %+v", perr)
	}
}

// TestBindingsStaleCert 验证证书被删除后登记仍保留，但 CertExists=false（陈旧归属可见）。
func TestBindingsStaleCert(t *testing.T) {
	svc, dir := newBindingFixture(t)
	if _, perr := svc.SetBinding(SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local"}); perr != nil {
		t.Fatalf("登记失败: %v", perr)
	}
	for _, name := range []string{"app.kore.local.crt", "app.kore.local.key"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatalf("删除 %s 失败: %v", name, err)
		}
	}
	list, perr := svc.Bindings()
	if perr != nil {
		t.Fatalf("读取列表失败: %v", perr)
	}
	if list.Count != 1 {
		t.Fatalf("证书删除后归属仍应保留，实际 %d 条", list.Count)
	}
	if list.Bindings[0].CertExists {
		t.Fatal("证书已删除时 CertExists 应为 false")
	}
	if list.Bindings[0].CertPath == "" || list.Bindings[0].KeyPath == "" {
		t.Fatal("陈旧归属仍应给出期望路径，便于提示用户补回证书")
	}
}

// TestBindingsLimit 验证登记条数上限：满额后新增返回 E_CONFLICT，而不是无限增长。
func TestBindingsLimit(t *testing.T) {
	svc, _ := newBindingFixture(t)
	store := svc.store
	records := make([]bindingRecord, 0, maxBindings)
	for i := 0; i < maxBindings; i++ {
		records = append(records, bindingRecord{
			Cert: "bulk-" + strconv.Itoa(i) + ".kore.local", Site: "bulk-" + strconv.Itoa(i) + ".kore.local",
			CreatedAt: "2026-01-02T03:04:05Z", UpdatedAt: "2026-01-02T03:04:05Z",
		})
	}
	if err := store.saveBindings(bindingFile{Schema: bindingsSchema, Bindings: records}); err != nil {
		t.Fatalf("预置满额登记失败: %v", err)
	}
	if _, perr := svc.SetBinding(SetBindingRequest{Cert: "app.kore.local", Site: "www.kore.local"}); perr == nil ||
		perr.Code != codeConflict {
		t.Fatalf("满额新增应 E_CONFLICT，实际 %+v", perr)
	}
}

// TestBindingsProbeOptIn 验证 probe 是显式可选项：给出才探测（关联结果里带只读判定），
// 且端口透传到判定；不给则完全不发起探测。
func TestBindingsProbeOptIn(t *testing.T) {
	svc, _ := newBindingFixture(t)
	httpPort, _ := startHTTPProbeServer(t, true)
	httpsPort, _ := startHTTPSProbeServer(t)
	result, perr := svc.SetBinding(SetBindingRequest{
		Cert: "app.kore.local", Site: "127.0.0.1",
		Probe: &BindingProbeRequest{HTTPPort: httpPort, HTTPSPort: httpsPort},
	})
	if perr != nil {
		t.Fatalf("带 probe 的登记失败: %v", perr)
	}
	if result.HTTPS == nil {
		t.Fatal("给出 probe 时关联结果应带只读 HTTPS 判定")
	}
	if result.HTTPS.Verdict != VerdictForceHTTPS {
		t.Fatalf("判定=%q，期望 %q", result.HTTPS.Verdict, VerdictForceHTTPS)
	}
	if result.HTTPS.HTTP.Address != net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)) {
		t.Fatalf("探测端口未透传: %q", result.HTTPS.HTTP.Address)
	}
}
