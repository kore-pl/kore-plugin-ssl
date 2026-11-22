package fault

import (
	"net"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultTimeout 注入超时故障：selfsign 在预算内未完成时返回 E_UPSTREAM，
// 且不留下半成品。
func TestFaultTimeout(t *testing.T) {
	svc, dir := newService(t, certs.FaultTimeout)
	info, perr := svc.SelfSign(certs.SelfSignRequest{Domain: "slow.example.com"})
	if info != nil {
		t.Fatalf("超时故障下不应返回证书，得到 %+v", info)
	}
	assertError(t, perr, pluginapi.E_UPSTREAM, "超时")
	assertNoCertFiles(t, dir)
}

// TestRealHandshakeTimeout 用"只监听不说 TLS"的真实 TCP 端点验证握手超时：
// 连接能建立但握手永远等不到 ServerHello，Verify 必须在预算内放弃并返回
// reachable=false，而不是挂死或报成协议错误。
func TestRealHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听本地端口失败: %v", err)
	}
	defer func() { _ = listener.Close() }()

	svc := certs.NewService(certs.Options{Dir: t.TempDir(), VerifyTimeout: 200 * time.Millisecond})
	start := time.Now()
	result, perr := svc.Verify(certs.VerifyRequest{Domain: listener.Addr().String()})
	elapsed := time.Since(start)
	if perr != nil {
		t.Fatalf("握手超时不应是协议错误，得到 %v", perr)
	}
	if result.Reachable {
		t.Fatalf("握手未完成不应 reachable=true: %+v", result)
	}
	if result.Error == "" {
		t.Fatal("握手超时应带 error 说明")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("握手超时未按预算生效，耗时 %s", elapsed)
	}
}
