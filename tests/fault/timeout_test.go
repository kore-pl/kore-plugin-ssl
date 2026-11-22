// Package fault 承载 ssl 插件的四类故障注入测试（G-20 / S-04）。
// 本文件测超时故障：ACME 签发不返回时，请求级 timeout 必须终止并回上游错误。
package fault

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultTimeout 注入 timeout 故障，断言 ssl.issue 返回上游超时错误。
func TestFaultTimeout(t *testing.T) {
	issuer := &certs.StubIssuer{Fault: certs.Fault{Kind: certs.FaultTimeout, Message: "ACME 30s 无响应"}}
	svc := certs.NewService(issuer)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cert, perr := svc.Issue(ctx, "slow.example.com", "")
	if cert != nil {
		t.Fatalf("超时故障下不应返回证书，得到 %+v", cert)
	}
	if perr == nil {
		t.Fatal("超时故障下应返回错误")
	}
	if perr.Code != pluginapi.E_UPSTREAM {
		t.Fatalf("错误码=%q，期望 %q", perr.Code, pluginapi.E_UPSTREAM)
	}
	if !strings.Contains(perr.Message, "超时") {
		t.Fatalf("错误信息应含超时，得到 %q", perr.Message)
	}
}

// TestTimeoutContextCancellation 校验真实 context 超时会让签发通道返回上游错误。
func TestTimeoutContextCancellation(t *testing.T) {
	issuer := &certs.StubIssuer{} // 无故障
	svc := certs.NewService(issuer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	<-ctx.Done() // 等待超时真实发生
	_, perr := svc.Issue(ctx, "cancelled.example.com", "")
	if perr == nil || perr.Code != pluginapi.E_UPSTREAM {
		t.Fatalf("已取消的 context 应返回 E_UPSTREAM，得到 %v", perr)
	}
}
