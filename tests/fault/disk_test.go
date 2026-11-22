// Package fault 承载 ssl 插件的四类故障注入测试（G-20 / S-04）。
// 本文件测磁盘满故障：证书落盘 ENOSPC 时，方法必须回内部错误且不写入清单。
package fault

import (
	"context"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultDiskFull 注入 disk_full 故障，断言 ssl.issue 返回 E_INTERNAL 且不落库。
func TestFaultDiskFull(t *testing.T) {
	issuer := &certs.StubIssuer{Fault: certs.Fault{Kind: certs.FaultDiskFull, Message: "/var/lib/kore/certs no space left"}}
	svc := certs.NewService(issuer)

	cert, perr := svc.Issue(context.Background(), "disk.example.com", "")
	if cert != nil {
		t.Fatalf("磁盘满故障下不应返回证书，得到 %+v", cert)
	}
	if perr == nil {
		t.Fatal("磁盘满故障下应返回错误")
	}
	if perr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("错误码=%q，期望 %q", perr.Code, pluginapi.E_INTERNAL)
	}
	if !strings.Contains(perr.Message, "ENOSPC") {
		t.Fatalf("错误信息应含 ENOSPC，得到 %q", perr.Message)
	}

	list, _ := svc.List()
	if list.Count != 0 {
		t.Fatalf("磁盘满失败不应污染清单，得到 count=%d", list.Count)
	}
}
