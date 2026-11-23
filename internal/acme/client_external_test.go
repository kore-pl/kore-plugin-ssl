package acme_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-ssl/internal/acme"
	"github.com/pengtang1024/kore-plugin-ssl/internal/acme/acmetest"
)

// newClient 构造指向本地 mock CA 的客户端（P-256 账户密钥）。
func newClient(t *testing.T, directoryURL string) *acme.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成账户密钥失败: %v", err)
	}
	client, err := acme.NewClient(context.Background(), acme.Options{DirectoryURL: directoryURL, AccountKey: key})
	if err != nil {
		t.Fatalf("构造客户端失败: %v", err)
	}
	return client
}

// issueCtx 返回 30s 预算的上下文（mock 全在回环，正常 <1s）。
func issueCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// challengeFiles 返回 webroot 下残留的 challenge 文件（应为空）。
func challengeFiles(t *testing.T, webroot string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(webroot, ".well-known", "acme-challenge", "*"))
	if err != nil {
		t.Fatalf("扫描 challenge 目录失败: %v", err)
	}
	return matches
}

// TestIssueEndToEnd 跑完整链路：账号注册 → 订单 → HTTP-01（token 落 webroot）→
// finalize（CSR）→ 下载证书链；并断言临时 token 已清理。
func TestIssueEndToEnd(t *testing.T) {
	webroot := t.TempDir()
	srv := acmetest.New(t, acmetest.Options{Webroot: webroot})
	client := newClient(t, srv.DirectoryURL())

	result, err := client.Issue(issueCtx(t), acme.IssueRequest{
		Domains:      []string{"acme-test.kore.local", "alt.kore.local"},
		Webroot:      webroot,
		SkipPrecheck: true,
	})
	if err != nil {
		t.Fatalf("签发失败: %v（hint=%s）", err, hintOf(err))
	}
	if client.KID() == "" {
		t.Fatal("签发后应已注册账号并持有 KID")
	}
	if result.ChainLength != 2 {
		t.Fatalf("证书链应为 2 张（叶子+中间），实际 %d", result.ChainLength)
	}
	block, _ := pem.Decode(result.CertPEM)
	if block == nil {
		t.Fatal("CertPEM 不是 PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析叶子证书失败: %v", err)
	}
	if strings.Join(leaf.DNSNames, ",") != "acme-test.kore.local,alt.kore.local" {
		t.Fatalf("证书 SAN=%v", leaf.DNSNames)
	}
	if !leaf.NotAfter.After(time.Now().Add(80 * 24 * time.Hour)) {
		t.Fatalf("证书有效期异常: notAfter=%s", leaf.NotAfter)
	}
	if !strings.Contains(string(result.KeyPEM), "BEGIN PRIVATE KEY") {
		t.Fatal("私钥应为 PKCS#8 PEM")
	}
	if !leaf.NotAfter.Equal(result.NotAfter) {
		t.Fatalf("返回的 NotAfter=%s 与证书 %s 不一致", result.NotAfter, leaf.NotAfter)
	}
	if files := challengeFiles(t, webroot); len(files) != 0 {
		t.Fatalf("challenge 文件应被清理，残留 %v", files)
	}
	if srv.ChallengeAttempts() == 0 {
		t.Fatal("mock CA 没收到 challenge 触发")
	}
}

// TestIssueBadNonceRetry 验证收到 badNonce 后换 nonce 重试成功。
func TestIssueBadNonceRetry(t *testing.T) {
	webroot := t.TempDir()
	srv := acmetest.New(t, acmetest.Options{Webroot: webroot, BadNonceOnce: true})
	client := newClient(t, srv.DirectoryURL())
	if _, err := client.Issue(issueCtx(t), acme.IssueRequest{
		Domains: []string{"nonce.kore.local"}, Webroot: webroot, SkipPrecheck: true,
	}); err != nil {
		t.Fatalf("badNonce 重试后应成功: %v（hint=%s）", err, hintOf(err))
	}
}

// TestIssueFailurePaths 覆盖 CA 侧各失败分支的错误分类与可操作 hint。
func TestIssueFailurePaths(t *testing.T) {
	cases := []struct {
		name         string
		opts         acmetest.Options
		wantKind     acme.Kind
		hintContains string
	}{
		{"challenge-invalid", acmetest.Options{ChallengeInvalid: true}, acme.KindInvalid, "HTTP-01"},
		{"finalize-rejected", acmetest.Options{FinalizeReject: true}, acme.KindInvalid, "CSR"},
		{"cert-download-fails", acmetest.Options{CertDownloadFail: true}, acme.KindUpstream, ""},
		{"rate-limited", acmetest.Options{RateLimitOrder: true}, acme.KindRateLimit, "staging"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			webroot := t.TempDir()
			tc.opts.Webroot = webroot
			srv := acmetest.New(t, tc.opts)
			client := newClient(t, srv.DirectoryURL())
			_, err := client.Issue(issueCtx(t), acme.IssueRequest{
				Domains: []string{"fail.kore.local"}, Webroot: webroot, SkipPrecheck: true,
			})
			if err == nil {
				t.Fatal("期望失败，实际成功")
			}
			var acmeErr *acme.Error
			if !errors.As(err, &acmeErr) {
				t.Fatalf("错误类型应为 *acme.Error，实际 %T: %v", err, err)
			}
			if acmeErr.Kind != tc.wantKind {
				t.Fatalf("Kind=%q，期望 %q（detail=%s）", acmeErr.Kind, tc.wantKind, acmeErr.Detail)
			}
			if acmeErr.Hint == "" {
				t.Fatal("错误必须带 hint")
			}
			if tc.hintContains != "" && !strings.Contains(acmeErr.Hint, tc.hintContains) {
				t.Fatalf("hint=%q 未包含 %q", acmeErr.Hint, tc.hintContains)
			}
			if files := challengeFiles(t, webroot); len(files) != 0 {
				t.Fatalf("失败路径也应清理 challenge 文件，残留 %v", files)
			}
		})
	}
}

// TestEABRequired 覆盖 LiteSSL 这类强制 EAB 的 CA：
// 缺 EAB → 明确错误；EAB 正确 → 成功；EAB key 错 → 鉴权错误。
func TestEABRequired(t *testing.T) {
	const (
		kid = "eab-kid-1"
		key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	)
	t.Run("missing", func(t *testing.T) {
		webroot := t.TempDir()
		srv := acmetest.New(t, acmetest.Options{Webroot: webroot, RequireEAB: true, EABKid: kid, EABHMACKey: key})
		client := newClient(t, srv.DirectoryURL())
		_, err := client.Issue(issueCtx(t), acme.IssueRequest{
			Domains: []string{"eab.kore.local"}, Webroot: webroot, SkipPrecheck: true,
		})
		if err == nil {
			t.Fatal("强制 EAB 的 CA 在缺 EAB 时应失败")
		}
		var acmeErr *acme.Error
		if !errors.As(err, &acmeErr) || acmeErr.Kind != acme.KindInvalid {
			t.Fatalf("期望 KindInvalid，实际 %v", err)
		}
		if !strings.Contains(acmeErr.Hint, "EAB") || !strings.Contains(acmeErr.Hint, "eab_kid") {
			t.Fatalf("hint 应引导填写 EAB：%q", acmeErr.Hint)
		}
	})
	t.Run("accepted", func(t *testing.T) {
		webroot := t.TempDir()
		srv := acmetest.New(t, acmetest.Options{Webroot: webroot, RequireEAB: true, EABKid: kid, EABHMACKey: key})
		client := newClient(t, srv.DirectoryURL())
		if _, err := client.Issue(issueCtx(t), acme.IssueRequest{
			Domains: []string{"eab.kore.local"}, Webroot: webroot, SkipPrecheck: true,
			EAB: &acme.EAB{Kid: kid, HMACKey: key},
		}); err != nil {
			t.Fatalf("EAB 正确时应成功: %v（hint=%s）", err, hintOf(err))
		}
	})
	t.Run("wrong-key", func(t *testing.T) {
		webroot := t.TempDir()
		srv := acmetest.New(t, acmetest.Options{Webroot: webroot, RequireEAB: true, EABKid: kid, EABHMACKey: key})
		client := newClient(t, srv.DirectoryURL())
		_, err := client.Issue(issueCtx(t), acme.IssueRequest{
			Domains: []string{"eab.kore.local"}, Webroot: webroot, SkipPrecheck: true,
			EAB: &acme.EAB{Kid: kid, HMACKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"},
		})
		if err == nil {
			t.Fatal("EAB key 错误时应失败")
		}
		var acmeErr *acme.Error
		if !errors.As(err, &acmeErr) || acmeErr.Kind != acme.KindAuth {
			t.Fatalf("EAB 被拒应为 KindAuth，实际 %v", err)
		}
	})
}

// TestPrecheckFailureAbortsBeforeChallenge 验证预检失败即在本地报错、不触发 CA challenge。
func TestPrecheckFailureAbortsBeforeChallenge(t *testing.T) {
	webroot := t.TempDir()
	srv := acmetest.New(t, acmetest.Options{Webroot: webroot})
	client := newClient(t, srv.DirectoryURL())
	_, err := client.Issue(issueCtx(t), acme.IssueRequest{
		Domains: []string{"precheck-fail.invalid"}, Webroot: webroot,
	})
	if err == nil {
		t.Fatal("预检不可达时应失败")
	}
	if !strings.Contains(hintOf(err), "预检") {
		t.Fatalf("hint 应说明预检失败：%q", hintOf(err))
	}
	if attempts := srv.ChallengeAttempts(); attempts != 0 {
		t.Fatalf("预检失败时不应触发 challenge，实际 %d 次", attempts)
	}
	if files := challengeFiles(t, webroot); len(files) != 0 {
		t.Fatalf("预检失败应清理 token，残留 %v", files)
	}
}

// TestIssueWebrootMissing 验证 webroot 不合法时在联网前就失败。
func TestIssueWebrootMissing(t *testing.T) {
	srv := acmetest.New(t, acmetest.Options{})
	client := newClient(t, srv.DirectoryURL())
	before := srv.Requests()
	_, err := client.Issue(issueCtx(t), acme.IssueRequest{Domains: []string{"x.kore.local"}, Webroot: "/nonexistent/acme-webroot"})
	if err == nil {
		t.Fatal("webroot 不存在应失败")
	}
	if !strings.Contains(hintOf(err), "webroot") {
		t.Fatalf("hint 应指向 webroot：%q", hintOf(err))
	}
	// 目录请求发生在 NewClient；此后不应再有请求。
	if after := srv.Requests(); after != before {
		t.Fatalf("webroot 校验失败时不应继续联网：before=%d after=%d", before, after)
	}
}

// TestPresetsAndResolve 锁死 CA 预设（含 LiteSSL 的 directory 与 EAB 要求）。
func TestPresetsAndResolve(t *testing.T) {
	presets := acme.Presets()
	byID := make(map[string]acme.CAPreset, len(presets))
	for _, p := range presets {
		byID[p.ID] = p
	}
	want := map[string]string{
		acme.CA:        "https://acme-v02.api.letsencrypt.org/directory",
		acme.CAStaging: "https://acme-staging-v02.api.letsencrypt.org/directory",
		acme.CALiteSSL: "https://acme.litessl.com/acme/v2/directory",
	}
	for id, url := range want {
		preset, ok := byID[id]
		if !ok {
			t.Fatalf("缺少 CA 预设 %q", id)
		}
		if preset.DirectoryURL != url {
			t.Fatalf("%s 的 directory=%q，期望 %q", id, preset.DirectoryURL, url)
		}
	}
	if !byID[acme.CALiteSSL].RequiresEAB {
		t.Fatal("LiteSSL 必须标记 RequiresEAB=true")
	}
	if byID[acme.CAStaging].RequiresEAB {
		t.Fatal("Let's Encrypt staging 不应要求 EAB")
	}

	got, err := acme.ResolveDirectoryURL("", "")
	if err != nil || got != want[acme.CAStaging] {
		t.Fatalf("缺省 CA 应为 staging，实际 %q err=%v", got, err)
	}
	if _, err := acme.ResolveDirectoryURL(acme.CACustom, ""); err == nil {
		t.Fatal("custom 缺 directory_url 应报错")
	}
	if _, err := acme.ResolveDirectoryURL("nope", ""); err == nil {
		t.Fatal("未知 CA 应报错")
	}
	if _, err := acme.ResolveDirectoryURL(acme.CACustom, "http://example.com/dir"); err == nil {
		t.Fatal("非回环 http 地址应被拒绝（必须 https）")
	}
	if got, err := acme.ResolveDirectoryURL(acme.CACustom, "https://acme.example.com/directory"); err != nil || got != "https://acme.example.com/directory" {
		t.Fatalf("custom https 地址应放行，实际 %q err=%v", got, err)
	}
}

// hintOf 取 *acme.Error 的 hint（非 acme 错误返回错误文本）。
func hintOf(err error) string {
	var acmeErr *acme.Error
	if errors.As(err, &acmeErr) {
		return acmeErr.Hint + " | " + acmeErr.Detail
	}
	if err == nil {
		return ""
	}
	return err.Error()
}
