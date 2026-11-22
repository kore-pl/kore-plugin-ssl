// Package fault 承载 ssl 插件的四类故障注入测试（G-20 / S-04）。
// 本文件测 cgroup 超限故障：memory.max 触顶被 OOM 时，续期方法必须回内部错误。
package fault

import (
	"context"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultCgroupLimit 注入 cgroup_limit 故障，断言 ssl.renew 返回 E_INTERNAL。
func TestFaultCgroupLimit(t *testing.T) {
	issuer := &certs.StubIssuer{Fault: certs.Fault{Kind: certs.FaultCgroupLimit, Message: "memory.max=6M exceeded"}}
	svc := certs.NewService(issuer)

	cert, perr := svc.Renew(context.Background(), "cgroup.example.com")
	if cert != nil {
		t.Fatalf("cgroup 超限下不应返回证书，得到 %+v", cert)
	}
	if perr == nil {
		t.Fatal("cgroup 超限下应返回错误")
	}
	if perr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("错误码=%q，期望 %q", perr.Code, pluginapi.E_INTERNAL)
	}
	if !strings.Contains(perr.Message, "OOM") && !strings.Contains(perr.Message, "cgroup") {
		t.Fatalf("错误信息应含 OOM/cgroup，得到 %q", perr.Message)
	}
}

// TestCgroupHealthyPath 校验无故障时续期成功并标记 renewed（对照组，防止空测试）。
func TestCgroupHealthyPath(t *testing.T) {
	svc := certs.NewService(&certs.StubIssuer{}) // 无故障：memory.max 充足
	cert, perr := svc.Renew(context.Background(), "ok.example.com")
	if perr != nil {
		t.Fatalf("健康路径不应报错，得到 %v", perr)
	}
	if cert.Status != "renewed" || cert.Source != "stub" {
		t.Fatalf("续期结果状态=%q source=%q，期望 renewed/stub", cert.Status, cert.Source)
	}
}
