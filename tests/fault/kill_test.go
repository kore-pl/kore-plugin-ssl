package fault

import (
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultKill 注入 kill -9 类故障：签发通道进程失联时，selfsign 必须返回
// E_UPSTREAM，且不能留下任何证书/私钥半成品。
func TestFaultKill(t *testing.T) {
	svc, dir := newService(t, certs.FaultKill)
	info, perr := svc.SelfSign(certs.SelfSignRequest{Domain: "kill.example.com"})
	if info != nil {
		t.Fatalf("kill 故障下不应返回证书，得到 %+v", info)
	}
	assertError(t, perr, pluginapi.E_UPSTREAM, "kill")
	assertNoCertFiles(t, dir)
}

// TestKillHealthyPath 对照组：无故障时同一方法必须真实签出证书，证明故障断言不是假通过。
func TestKillHealthyPath(t *testing.T) {
	_, dir := newService(t, certs.FaultNone)
	svc := healthyService(dir)
	info, perr := svc.SelfSign(certs.SelfSignRequest{Domain: "ok.example.com", Days: 10})
	if perr != nil {
		t.Fatalf("健康路径不应报错: %v", perr)
	}
	if !info.SelfSigned || info.Domain != "ok.example.com" || info.DaysLeft != 10 {
		t.Fatalf("健康路径结果不符: %+v", info)
	}
	list, perr := svc.List()
	if perr != nil || list.Count != 1 {
		t.Fatalf("健康路径应能列出 1 张证书，得到 count=%d err=%v", list.Count, perr)
	}
}
