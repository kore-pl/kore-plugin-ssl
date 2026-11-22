// Package fault 承载 ssl 插件的四类故障注入测试（G-20 / S-04）。
// 本文件测 kill -9 类故障：签发通道所在进程崩溃时，方法必须返回 E_UPSTREAM。
package fault

import (
	"context"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultKill 注入 kill 故障，断言 ssl.issue 返回上游错误且不落库。
func TestFaultKill(t *testing.T) {
	issuer := &certs.StubIssuer{Fault: certs.Fault{Kind: certs.FaultKill, Message: "worker pid 4242 SIGKILL"}}
	svc := certs.NewService(issuer)

	cert, perr := svc.Issue(context.Background(), "kill.example.com", "")
	if cert != nil {
		t.Fatalf("kill 故障下不应返回证书，得到 %+v", cert)
	}
	if perr == nil {
		t.Fatal("kill 故障下应返回错误")
	}
	if perr.Code != pluginapi.E_UPSTREAM {
		t.Fatalf("错误码=%q，期望 %q", perr.Code, pluginapi.E_UPSTREAM)
	}
	if !strings.Contains(perr.Message, "kill") {
		t.Fatalf("错误信息应含 kill，得到 %q", perr.Message)
	}

	// 崩溃后清单必须保持为空：失败不应污染状态。
	list, lerr := svc.List()
	if lerr != nil || list.Count != 0 {
		t.Fatalf("kill 后清单应为空，得到 count=%d err=%v", list.Count, lerr)
	}
}
