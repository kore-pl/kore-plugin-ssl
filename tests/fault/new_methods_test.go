package fault

import (
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
