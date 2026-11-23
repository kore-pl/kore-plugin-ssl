package certs

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// startHTTPProbeServer 在回环上起一个 80 侧替身：redirect=true 时 301 跳 https，
// 否则 200 纯文本。返回端口与命中计数（命中数用于断言"不跟随跳转"）。
func startHTTPProbeServer(t *testing.T, redirect bool) (int, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if redirect {
			http.Redirect(w, r, "https://"+r.Host+"/login?next=%2F", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("plain-http"))
	}))
	t.Cleanup(srv.Close)
	return portFromURL(t, srv.URL), &hits
}

// startHTTPSProbeServer 起一个 443 侧 TLS 替身（httptest 自带自签证书）。
// 探测只做 TLS 握手、不发 HTTP 请求，所以命中计数应为 0——这也是"不跟随跳转"的证据。
func startHTTPSProbeServer(t *testing.T) (int, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return portFromURL(t, srv.URL), &hits
}

// portFromURL 从 httptest 的 URL 取端口。
func portFromURL(t *testing.T, raw string) int {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("解析测试服务地址 %q 失败: %v", raw, err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("测试服务地址 %q 没有可用端口: %v", raw, err)
	}
	return port
}

// freeClosedPort 返回一个"刚释放、必然连不上"的回环端口（用于不可达分支）。
func freeClosedPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("申请空闲端口失败: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("释放端口失败: %v", err)
	}
	return port
}

// TestHTTPSStatusForceHTTPS 验证"443 可握手 + 80 已跳 https"判定为 force-https。
func TestHTTPSStatusForceHTTPS(t *testing.T) {
	svc, _ := testService(t)
	httpPort, httpHits := startHTTPProbeServer(t, true)
	httpsPort, httpsHits := startHTTPSProbeServer(t)

	result, perr := svc.HTTPSStatus(HTTPSStatusRequest{
		Domain: "127.0.0.1", HTTPPort: httpPort, HTTPSPort: httpsPort,
	})
	if perr != nil {
		t.Fatalf("判定失败: %v", perr)
	}
	if result.Verdict != VerdictForceHTTPS || !result.ForceHTTPS {
		t.Fatalf("判定=%q force_https=%v，期望 force-https / true（结果 %+v）",
			result.Verdict, result.ForceHTTPS, result)
	}
	if !result.HTTPS.Reachable {
		t.Fatalf("443 侧应可达: %+v", result.HTTPS)
	}
	if !result.HTTP.Reachable || result.HTTP.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("80 侧应返回 301: %+v", result.HTTP)
	}
	if !strings.HasPrefix(result.HTTP.Location, "https://") {
		t.Fatalf("Location 应指向 https: %q", result.HTTP.Location)
	}
	// 只读判定：不跟随跳转（80 侧只被打 1 次，443 侧一次 HTTP 请求都没有）。
	if got := atomic.LoadInt32(httpHits); got != 1 {
		t.Fatalf("80 侧应只被探测 1 次，实际 %d 次（不得跟随或重试）", got)
	}
	if got := atomic.LoadInt32(httpsHits); got != 0 {
		t.Fatalf("443 侧只做 TLS 握手，不应发 HTTP 请求，实际命中 %d 次", got)
	}
	// 站点侧动作：指向 site.bindSSL + force_https=true，且不改配置（本仓只给载荷）。
	if result.SiteAction.Plugin != "site" || result.SiteAction.Method != "site.bindSSL" {
		t.Fatalf("站点侧动作应为 site.bindSSL，实际 %+v", result.SiteAction)
	}
	if result.SiteAction.Params.ForceHTTPS == nil || !*result.SiteAction.Params.ForceHTTPS {
		t.Fatal("站点侧动作应建议 force_https=true")
	}
	if result.Hint == "" || !strings.Contains(result.Hint, "site") {
		t.Fatalf("force-https 的 hint 应说明配置由 site 侧持有: %q", result.Hint)
	}
}

// TestHTTPSStatusWithoutRedirect 验证 443 可达但 80 不跳转时的判定与可操作提示。
func TestHTTPSStatusWithoutRedirect(t *testing.T) {
	svc, _ := testService(t)
	httpPort, _ := startHTTPProbeServer(t, false)
	httpsPort, _ := startHTTPSProbeServer(t)

	result, perr := svc.HTTPSStatus(HTTPSStatusRequest{
		Domain: "127.0.0.1", HTTPPort: httpPort, HTTPSPort: httpsPort,
	})
	if perr != nil {
		t.Fatalf("判定失败: %v", perr)
	}
	if result.Verdict != VerdictHTTPSNoRedirect || result.ForceHTTPS {
		t.Fatalf("判定=%q force_https=%v，期望 https-without-redirect / false", result.Verdict, result.ForceHTTPS)
	}
	if result.HTTP.RedirectsToHTTPS || result.HTTP.Location != "" {
		t.Fatalf("200 响应不应被判成跳转: %+v", result.HTTP)
	}
	if !strings.Contains(result.Hint, "force_https") || !strings.Contains(result.Hint, "site.bindSSL") {
		t.Fatalf("hint 必须指向站点侧开启跳转：%q", result.Hint)
	}
}

// TestHTTPSStatusHTTPSUnreachable 验证 443 连不上时如实返回 unreachable（不报协议错误）。
func TestHTTPSStatusHTTPSUnreachable(t *testing.T) {
	svc, _ := testService(t)
	httpPort, _ := startHTTPProbeServer(t, true)
	result, perr := svc.HTTPSStatus(HTTPSStatusRequest{
		Domain: "127.0.0.1", HTTPPort: httpPort, HTTPSPort: freeClosedPort(t),
	})
	if perr != nil {
		t.Fatalf("探测失败属于观测值，不应返回协议错误: %v", perr)
	}
	if result.Verdict != VerdictHTTPSUnreachable || result.ForceHTTPS {
		t.Fatalf("判定=%q，期望 https-unreachable", result.Verdict)
	}
	if result.HTTPS.Reachable {
		t.Fatal("443 不可达时 Reachable 应为 false")
	}
	if result.HTTPS.Error == "" {
		t.Fatal("443 不可达时应带 error 观测值")
	}
	if result.HTTP.RedirectsToHTTPS && result.ForceHTTPS {
		t.Fatal("443 不可达时不得判成 force-https")
	}
}

// TestHTTPSStatusNonHTTPSRedirect 验证 302 到 http（非 https）不算强制 HTTPS。
func TestHTTPSStatusNonHTTPSRedirect(t *testing.T) {
	svc, _ := testService(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.test/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	httpsPort, _ := startHTTPSProbeServer(t)
	result, perr := svc.HTTPSStatus(HTTPSStatusRequest{
		Domain: "127.0.0.1", HTTPPort: portFromURL(t, srv.URL), HTTPSPort: httpsPort,
	})
	if perr != nil {
		t.Fatalf("判定失败: %v", perr)
	}
	if result.HTTP.RedirectsToHTTPS {
		t.Fatal("302 到 http:// 不应算作强制 HTTPS")
	}
	if result.Verdict != VerdictHTTPSNoRedirect {
		t.Fatalf("判定=%q，期望 https-without-redirect", result.Verdict)
	}
}

// TestHTTPSStatusValidation 覆盖入参校验：URL / 空域名 / 越界端口。
func TestHTTPSStatusValidation(t *testing.T) {
	svc, _ := testService(t)
	cases := []struct {
		name string
		req  HTTPSStatusRequest
	}{
		{"empty", HTTPSStatusRequest{Domain: ""}},
		{"url", HTTPSStatusRequest{Domain: "https://example.com"}},
		{"bad-http-port", HTTPSStatusRequest{Domain: "example.com", HTTPPort: 70000}},
		{"bad-https-port", HTTPSStatusRequest{Domain: "example.com", HTTPSPort: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, perr := svc.HTTPSStatus(tc.req)
			if result != nil {
				t.Fatalf("非法入参不应返回结果: %+v", result)
			}
			if perr == nil || perr.Code != codeInvalid {
				t.Fatalf("期望 E_INVALID，实际 %+v", perr)
			}
		})
	}
}

// TestNormalizeProbePortDefaults 验证端口缺省口径（80 / 443），避免"默认值随手改"。
func TestNormalizeProbePortDefaults(t *testing.T) {
	if port, perr := normalizeProbePort(0, defaultHTTPPort, "http_port"); perr != nil || port != 80 {
		t.Fatalf("http 缺省端口=%d err=%v，期望 80", port, perr)
	}
	if port, perr := normalizeProbePort(0, defaultHTTPSPort, "https_port"); perr != nil || port != 443 {
		t.Fatalf("https 缺省端口=%d err=%v，期望 443", port, perr)
	}
	if port, perr := normalizeProbePort(8080, defaultHTTPPort, "http_port"); perr != nil || port != 8080 {
		t.Fatalf("显式端口应透传，实际 %d err=%v", port, perr)
	}
}
