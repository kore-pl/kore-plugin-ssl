package fault

import (
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultDiskFull 注入磁盘满（ENOSPC）：落盘失败必须返回 E_INTERNAL，
// 且不能出现"证书写了、私钥没写"的半成品状态。
func TestFaultDiskFull(t *testing.T) {
	svc, dir := newService(t, certs.FaultDiskFull)
	info, perr := svc.SelfSign(certs.SelfSignRequest{Domain: "disk.example.com"})
	if info != nil {
		t.Fatalf("磁盘满故障下不应返回证书，得到 %+v", info)
	}
	assertError(t, perr, pluginapi.E_INTERNAL, "ENOSPC")
	assertNoCertFiles(t, dir)
}

// TestDiskFullImport 说明导入路径同样在入口被故障拦截，不会解析后写盘。
func TestDiskFullImport(t *testing.T) {
	svc, dir := newService(t, certs.FaultDiskFull)
	info, perr := svc.Import(certs.ImportRequest{
		Domain: "disk.example.com", CertPEM: "not-a-cert", KeyPEM: "not-a-key",
	})
	if info != nil {
		t.Fatalf("磁盘满故障下导入不应返回证书，得到 %+v", info)
	}
	assertError(t, perr, pluginapi.E_INTERNAL, "ENOSPC")
	assertNoCertFiles(t, dir)
}
