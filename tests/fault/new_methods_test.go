package fault

import (
	"os"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultCoversNewMethods 校验本轮新增的三类能力同样在方法入口被故障拦截：
// 到期聚合、续期任务描述、ACME 探测/签发。四类故障按协议码分两组断言，
// 并设无故障对照组，防止"永远失败"的假通过。
func TestFaultCoversNewMethods(t *testing.T) {
	cases := []struct {
		name     string
		kind     certs.FaultKind
		wantCode string
		wantHint string
	}{
		{"kill", certs.FaultKill, pluginapi.E_UPSTREAM, "kill"},
		{"timeout", certs.FaultTimeout, pluginapi.E_UPSTREAM, "超时"},
		{"disk-full", certs.FaultDiskFull, pluginapi.E_INTERNAL, "ENOSPC"},
		{"cgroup-limit", certs.FaultCgroupLimit, pluginapi.E_INTERNAL, "OOM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, dir := newService(t, tc.kind)
			// 到期聚合
			result, perr := svc.Expiring(certs.ExpiringRequest{})
			if result != nil {
				t.Fatalf("故障下 expiring 不应返回结果: %+v", result)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			// 续期任务描述
			task, perr := svc.RenewalTask(certs.RenewalTaskRequest{Name: "fault.kore.local"})
			if task != nil {
				t.Fatalf("故障下 renew.set 不应返回任务: %+v", task)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			// ACME 探测与签发
			status, perr := svc.ACMEStatus()
			if status != nil {
				t.Fatalf("故障下 acme.status 不应返回结果: %+v", status)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			issue, perr := svc.ACMEIssue(certs.ACMEIssueRequest{
				Domain: "fault.kore.local", Email: "ops@example.com", Confirm: true,
			})
			if issue != nil {
				t.Fatalf("故障下 acme.issue 不应返回结果: %+v", issue)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			// 故障路径不得留下任何证书/私钥/ACME 标记文件。
			assertNoCertFiles(t, dir)
		})
	}

	// 对照组：同一方法在无故障下必须正常返回，证明上面的失败来自注入而非方法本身坏了。
	svc, _ := newService(t, certs.FaultNone)
	if result, perr := svc.Expiring(certs.ExpiringRequest{}); perr != nil || result.Checked != 0 {
		t.Fatalf("对照组 expiring 应成功且 checked=0，实际 %+v / %+v", result, perr)
	}
	if status, perr := svc.ACMEStatus(); perr != nil || status.Available {
		t.Fatalf("对照组 acme.status 应可用=false 且无错误，实际 %+v / %+v", status, perr)
	}
	if _, perr := svc.RenewalTask(certs.RenewalTaskRequest{Name: "fault.kore.local"}); perr == nil || perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("对照组对不存在证书应 E_NOTFOUND，实际 %+v", perr)
	}
}

// TestFaultCoversSiteBindingAndHTTPS 校验 0.4.0 新增的归属登记 / 强制 HTTPS 判定
// 同样在方法入口被故障拦截：故障下不落登记文件、不发起探测，并设无故障对照组。
func TestFaultCoversSiteBindingAndHTTPS(t *testing.T) {
	cases := []struct {
		name     string
		kind     certs.FaultKind
		wantCode string
		wantHint string
	}{
		{"kill", certs.FaultKill, pluginapi.E_UPSTREAM, "kill"},
		{"timeout", certs.FaultTimeout, pluginapi.E_UPSTREAM, "超时"},
		{"disk-full", certs.FaultDiskFull, pluginapi.E_INTERNAL, "ENOSPC"},
		{"cgroup-limit", certs.FaultCgroupLimit, pluginapi.E_INTERNAL, "OOM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, dir := newService(t, tc.kind)
			bind, perr := svc.SetBinding(certs.SetBindingRequest{
				Cert: "fault.kore.local", Site: "www.kore.local",
			})
			if bind != nil {
				t.Fatalf("故障下 bind.set 不应返回结果: %+v", bind)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			list, perr := svc.Bindings()
			if list != nil {
				t.Fatalf("故障下 bind.list 不应返回结果: %+v", list)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			status, perr := svc.HTTPSStatus(certs.HTTPSStatusRequest{Domain: "fault.kore.local"})
			if status != nil {
				t.Fatalf("故障下 https.status 不应返回结果: %+v", status)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			// 故障路径不得落任何登记文件（bindings.json 也不允许出现）。
			for _, entry := range mustReadDir(t, dir) {
				if entry.Name() == "bindings.json" {
					t.Fatal("故障路径不应写入站点归属登记文件")
				}
			}
		})
	}

	// 对照组：无故障时三个方法都正常工作（bind.list 空登记、https.status 探测回环失败也是观测值）。
	svc, _ := newService(t, certs.FaultNone)
	if list, perr := svc.Bindings(); perr != nil || list.Count != 0 {
		t.Fatalf("对照组 bind.list 应成功且 count=0，实际 %+v / %+v", list, perr)
	}
	status, perr := svc.HTTPSStatus(certs.HTTPSStatusRequest{Domain: "127.0.0.1", HTTPPort: 1, HTTPSPort: 1})
	if perr != nil {
		t.Fatalf("对照组 https.status 不应返回协议错误: %v", perr)
	}
	if status.Verdict != certs.VerdictHTTPSUnreachable {
		t.Fatalf("对照组对不可达目标应判 https-unreachable，实际 %q", status.Verdict)
	}
}

// mustReadDir 读目录，失败即测试失败。
func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取证书目录失败: %v", err)
	}
	return entries
}
