// Package fault 承载 ssl 插件的四类故障注入测试（G-20 / S-04）。
//
// 每个用例通过 KORE_FAULT 同源的 Fault 注入（Service 构造参数）驱动真实方法，
// 断言四类故障都被映射成结构化协议错误，且失败路径不会在证书目录留下半成品。
// 另设无故障对照组，防止"永远失败"的假通过；timeout 另做一次真实 TLS 握手超时探测。
package fault

import (
	"os"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
)

// newService 返回注入指定故障的服务与独立证书目录。
func newService(t *testing.T, kind certs.FaultKind) (*certs.Service, string) {
	t.Helper()
	dir := t.TempDir()
	return certs.NewService(certs.Options{Dir: dir, Fault: certs.Fault(kind)}), dir
}

// healthyService 返回同一目录上的无故障服务，用于验证故障路径没有污染状态。
func healthyService(dir string) *certs.Service {
	return certs.NewService(certs.Options{Dir: dir})
}

// assertNoCertFiles 断言目录里没有写进任何证书/私钥文件。
func assertNoCertFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取证书目录失败: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") {
			t.Fatalf("故障路径不应写入文件，发现 %s", name)
		}
	}
}

// assertError 断言错误码与消息关键词。
func assertError(t *testing.T, perr *certs.CertError, wantCode, wantHint string) {
	t.Helper()
	if perr == nil {
		t.Fatalf("期望错误 %s/%s，实际成功", wantCode, wantHint)
	}
	if perr.Code != wantCode {
		t.Fatalf("错误码=%q，期望 %q（message=%q）", perr.Code, wantCode, perr.Message)
	}
	if !strings.Contains(perr.Message, wantHint) {
		t.Fatalf("错误信息 %q 未含关键词 %q", perr.Message, wantHint)
	}
}
