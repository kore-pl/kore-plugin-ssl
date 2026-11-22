package fault

import (
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFaultCgroupLimit 注入 cgroup memory.max 触顶（OOM）：
// 证书操作返回 E_INTERNAL，且不写盘。
func TestFaultCgroupLimit(t *testing.T) {
	svc, dir := newService(t, certs.FaultCgroupLimit)
	info, perr := svc.SelfSign(certs.SelfSignRequest{Domain: "cgroup.example.com"})
	if info != nil {
		t.Fatalf("cgroup 超限下不应返回证书，得到 %+v", info)
	}
	assertError(t, perr, pluginapi.E_INTERNAL, "OOM")
	assertNoCertFiles(t, dir)
}

// TestCgroupHealthyRenew 对照组：无故障时自签 + 续期完整闭环，
// 证明故障断言之外真实路径可用（续期换新证书且仍是自签）。
func TestCgroupHealthyRenew(t *testing.T) {
	dir := t.TempDir()
	svc := healthyService(dir)
	first, perr := svc.SelfSign(certs.SelfSignRequest{Domain: "renew.example.com", Days: 30})
	if perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	renewed, perr := svc.Renew(certs.RenewRequest{Domain: "renew.example.com"})
	if perr != nil {
		t.Fatalf("自签续期失败: %v", perr)
	}
	if !renewed.Renewed || !renewed.SelfSigned {
		t.Fatalf("续期结果应为 renewed/self_signed=true: %+v", renewed)
	}
	if renewed.FingerprintSHA256 == first.FingerprintSHA256 {
		t.Fatal("续期后证书指纹应变化（新密钥 + 新序列号）")
	}
	list, perr := svc.List()
	if perr != nil || list.Count != 1 {
		t.Fatalf("续期后应只有 1 张证书，得到 count=%d err=%v", list.Count, perr)
	}
}
