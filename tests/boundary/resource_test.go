//go:build linux

package boundary

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
)

// 资源耗尽：真实注入文件大小上限（等价 shell 的 `ulimit -f`），在进程内用
// RLIMIT_FSIZE 把单文件上限压到 128 字节，再让 SelfSign 落盘。
//
// 这不是"把磁盘写满"的模拟：写入会真实返回 EFBIG，插件必须把 OS 错误映射成
// E_INTERNAL 并保持目录干净（原子写失败要清掉临时文件，不留半张证书）。
// 用例结束前恢复原 rlimit，再做一次正常签发作为对照组，防止"永远失败"的假通过。

// fileSizeLimit 是注入的单文件上限：远小于一张 ECDSA 证书 PEM（约 600+ 字节）。
const fileSizeLimit = 128

// TestResourceExhaustionFileSizeLimit 文件大小上限耗尽 → 结构化失败且无残留文件。
func TestResourceExhaustionFileSizeLimit(t *testing.T) {
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
		t.Fatalf("读取 RLIMIT_FSIZE 失败: %v", err)
	}
	restore := func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
			t.Fatalf("恢复 RLIMIT_FSIZE 失败: %v", err)
		}
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original) })

	dir := t.TempDir()
	svc := newService(t, dir)

	limited := syscall.Rlimit{Cur: fileSizeLimit, Max: original.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Fatalf("注入 RLIMIT_FSIZE 失败: %v", err)
	}
	_, perr := svc.SelfSign(certs.SelfSignRequest{Domain: "quota.kore.local", KeyType: "ecdsa256"})
	restore()

	if perr == nil {
		t.Fatalf("文件大小上限耗尽时签发应失败，实际成功")
	}
	if perr.Code != "E_INTERNAL" {
		t.Fatalf("错误码=%q，期望 E_INTERNAL（message=%q）", perr.Code, perr.Message)
	}
	if !strings.Contains(strings.ToLower(perr.Message), "file too large") {
		t.Fatalf("错误信息应保留 OS 的 EFBIG 原文（file too large），实际 %q", perr.Message)
	}

	// 原子写失败必须清理临时文件，目录里不能留下 .crt / .key / .tmp 半成品。
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取证书目录失败: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".tmp") {
			t.Fatalf("资源耗尽路径不应留下文件，发现 %s", name)
		}
	}

	// 对照组：限制恢复后同一服务可正常签发，证明失败来自注入而不是环境坏掉。
	info, perr := svc.SelfSign(certs.SelfSignRequest{Domain: "quota-ok.kore.local", KeyType: "ecdsa256"})
	if perr != nil {
		t.Fatalf("恢复限制后正常签发失败: %s/%s", perr.Code, perr.Message)
	}
	if info.Domain != "quota-ok.kore.local" || info.Error != "" {
		t.Fatalf("恢复限制后签发自检失败: %+v", info)
	}
}

// nowForTest 是证书有效期基准：直接取当前时间，供异常/权限用例构造"现在有效"的证书。
func nowForTest() time.Time { return time.Now() }
