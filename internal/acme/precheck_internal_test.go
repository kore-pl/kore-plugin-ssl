package acme

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// precheckTestServer 起一个按 webroot 提供静态文件的回环服务，返回端口。
func precheckTestServer(t *testing.T, webroot string) int {
	t.Helper()
	server := httptest.NewServer(http.FileServer(http.Dir(webroot)))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("解析测试服务地址失败: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("取端口失败: %v", err)
	}
	return port
}

// TestPrecheckSucceeds 验证预检能读到 keyAuthorization。
func TestPrecheckSucceeds(t *testing.T) {
	webroot := t.TempDir()
	const token = "tok-abcdef123"
	const keyAuth = token + ".thumbprint"
	path, err := writeChallenge(webroot, token, keyAuth)
	if err != nil {
		t.Fatalf("写 challenge 失败: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	client := &Client{}
	if err := client.precheck("127.0.0.1", token, keyAuth, precheckTestServer(t, webroot)); err != nil {
		t.Fatalf("预检应成功: %v（hint=%v）", err, err)
	}
}

// TestPrecheckMismatch 验证内容不匹配时给出"webroot 配错"提示。
func TestPrecheckMismatch(t *testing.T) {
	webroot := t.TempDir()
	const token = "tok-abcdef123"
	if _, err := writeChallenge(webroot, token, "wrong.content"); err != nil {
		t.Fatalf("写 challenge 失败: %v", err)
	}
	client := &Client{}
	err := client.precheck("127.0.0.1", token, "expected.content", precheckTestServer(t, webroot))
	if err == nil {
		t.Fatal("内容不匹配应失败")
	}
	var acmeErr *Error
	if !errors.As(err, &acmeErr) {
		t.Fatalf("错误应为 *Error，实际 %T", err)
	}
	if !strings.Contains(acmeErr.Detail, "不匹配") || !strings.Contains(acmeErr.Hint, "webroot") {
		t.Fatalf("错误应说明 webroot 配错：detail=%s hint=%s", acmeErr.Detail, acmeErr.Hint)
	}
}

// TestPrecheckUnreachable 验证连不上时把"域名/端口/webroot"三个可能原因写进 hint。
func TestPrecheckUnreachable(t *testing.T) {
	client := &Client{}
	err := client.precheck("127.0.0.1", "tok-abcdef123", "x", 1)
	if err == nil {
		t.Fatal("不可达端口应失败")
	}
	var acmeErr *Error
	if !errors.As(err, &acmeErr) {
		t.Fatalf("错误应为 *Error，实际 %T", err)
	}
	if !strings.Contains(acmeErr.Hint, "80 端口") || !strings.Contains(acmeErr.Hint, "webroot") {
		t.Fatalf("hint 应覆盖可达性与 webroot：%s", acmeErr.Hint)
	}
}

// TestWriteChallengeRejectsToken 验证 token 白名单挡路径穿越。
func TestWriteChallengeRejectsToken(t *testing.T) {
	webroot := t.TempDir()
	for _, token := range []string{"../../etc/passwd", "a b", "short", "x/y"} {
		if _, err := writeChallenge(webroot, token, "k"); err == nil {
			t.Fatalf("token %q 应被拒绝", token)
		}
	}
	// 合法 token 落在 .well-known/acme-challenge 下。
	path, err := writeChallenge(webroot, "abcdefgh1234", "k")
	if err != nil {
		t.Fatalf("合法 token 应写入成功: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join(".well-known", "acme-challenge", "abcdefgh1234")) {
		t.Fatalf("token 路径不符: %s", path)
	}
	if err := removeChallenge(path); err != nil {
		t.Fatalf("删除 token 失败: %v", err)
	}
	if err := removeChallenge(path); err != nil {
		t.Fatalf("重复删除应幂等: %v", err)
	}
}
