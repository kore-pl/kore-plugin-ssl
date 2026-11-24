//go:build linux

package boundary

import (
	"fmt"
	"sync"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
)

// 并发：同一进程内多请求并发登记/读取站点归属，断言
//  1. 不丢更新（N 条登记最后都在 bindings.json 里，Count == N）；
//  2. 无数据竞争（必须用 go test -race 跑本包）；
//  3. 并发读（List/Bindings）不破坏写路径。
//
// ssl 的共享可变状态只有"证书目录里的登记文件"与 Service 的 bindMu 串行化读改写，
// 这正是真实并发威胁面：前端多标签页同时点击绑定、或 site 插件批量登记时，若丢失
// 串行化就会出现"最后一条覆盖前一条"的静默丢数据。

// TestConcurrentBindingUpdatesNoLostUpdate 并发登记 N 个互不冲突的证书→站点归属。
func TestConcurrentBindingUpdatesNoLostUpdate(t *testing.T) {
	const goroutines = 16
	dir := t.TempDir()
	svc := newService(t, dir)

	domains := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		domains[i] = fmt.Sprintf("cert-%02d.kore.local", i)
		mustSelfSign(t, svc, domains[i])
	}

	start := make(chan struct{})
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			_, perr := svc.SetBinding(certs.SetBindingRequest{
				Cert: domains[index],
				Site: fmt.Sprintf("site-%02d.kore.local", index),
				Note: "boundary-concurrency",
			})
			if perr != nil {
				errCh <- fmt.Errorf("SetBinding %s: %s/%s", domains[index], perr.Code, perr.Message)
			}
		}(i)
	}

	// 并发读者：与写路径同时运行，-race 下任何共享内存竞争都会报错。
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for k := 0; k < 10; k++ {
				if _, perr := svc.List(); perr != nil {
					errCh <- fmt.Errorf("并发 List 失败: %s/%s", perr.Code, perr.Message)
					return
				}
				if _, perr := svc.Bindings(); perr != nil {
					errCh <- fmt.Errorf("并发 Bindings 失败: %s/%s", perr.Code, perr.Message)
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发路径出错: %v", err)
	}

	result, perr := svc.Bindings()
	if perr != nil {
		t.Fatalf("读取归属失败: %s/%s", perr.Code, perr.Message)
	}
	if result.Count != goroutines {
		t.Fatalf("并发登记丢失更新：期望 %d 条，实际 %d 条（bindMu 串行化失效）", goroutines, result.Count)
	}
	byCert := make(map[string]string, len(result.Bindings))
	for _, binding := range result.Bindings {
		byCert[binding.Cert] = binding.Site
	}
	for i := 0; i < goroutines; i++ {
		wantSite := fmt.Sprintf("site-%02d.kore.local", i)
		if got := byCert[domains[i]]; got != wantSite {
			t.Fatalf("归属丢失/错配：cert=%s 期望 site=%s 实际 %q", domains[i], wantSite, got)
		}
	}
}
