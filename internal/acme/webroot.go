package acme

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// HTTP-01 webroot 处理。
//
// 边界（G-31 零侵入）：token 文件只写进**用户显式配置的 webroot**（站点根，属于用户
// 自己管理的目录），位于 `.well-known/acme-challenge/<token>`，一次性使用、用完立即删除；
// 插件自身的持久化状态仍在 <KORE_STATE_DIR>/ssl/acme 下。
const (
	// challengeSubdir 是 ACME 规定的 HTTP-01 路径（相对站点根）。
	challengeSubdir = ".well-known/acme-challenge"
	// challengeTokenMaxLen 是 RFC 8555 token 的实际上限（base64url，通常 43 字符）。
	challengeTokenMaxLen = 256
)

// challengeTokenRE 限定 token 字符集：token 会拼进文件路径，必须裸白名单防穿越。
var challengeTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,256}$`)

// ensureWebroot 校验 webroot 是绝对路径下的可写目录，并确保 challenge 子目录存在。
func ensureWebroot(root string) error {
	if strings.TrimSpace(root) == "" {
		return errf(KindInvalid, "在 ssl.acme.auto 里配置 webroot（站点根目录，如 /install/data/sites/example.com）", "缺少 webroot：HTTP-01 需要把校验文件写进站点根")
	}
	if !filepath.IsAbs(root) {
		return errf(KindInvalid, "webroot 必须是绝对路径", "webroot 不是绝对路径: %q", root)
	}
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errf(KindInvalid, "webroot 指向已存在的站点根目录；站点尚未创建时先到站点页建站", "webroot 目录不存在: %s", root)
		}
		return errf(KindInvalid, "确认插件进程对 webroot 有读权限", "无法访问 webroot: %v", err)
	}
	if !info.IsDir() {
		return errf(KindInvalid, "webroot 要指向目录（站点根），不是文件", "webroot 不是目录: %s", root)
	}
	dir := filepath.Join(root, challengeSubdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errf(KindInvalid, "确认插件进程对 webroot 有写权限（站点用户与插件用户需可写同一目录）", "创建 %s 失败: %v", dir, err)
	}
	// 真实写一次探针再删掉：只 stat 看不出来目录是否可写。
	probe, err := os.CreateTemp(dir, ".kore-acme-probe-*")
	if err != nil {
		return errf(KindInvalid, "给站点根目录授予插件用户写权限（或改 webroot 到可写目录）", "webroot 不可写: %v", err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// EnsureWebroot 供上层（certs）在真正下单前做本地预检：目录存在、可写、可建 challenge 子目录。
func EnsureWebroot(root string) error { return ensureWebroot(root) }

// writeChallenge 写入 HTTP-01 token 文件，返回绝对路径（调用方负责用完删除）。
func writeChallenge(webroot, token, keyAuth string) (string, error) {
	if !challengeTokenRE.MatchString(token) || len(token) > challengeTokenMaxLen {
		return "", errf(KindInvalid, "该 CA 返回的 token 不符合 RFC 8555，换一个 CA 或稍后重试", "challenge token 非法: %q", token)
	}
	dir := filepath.Join(webroot, challengeSubdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", errf(KindInvalid, "确认 webroot 可写", "创建 challenge 目录失败: %v", err)
	}
	path := filepath.Join(dir, token)
	if err := os.WriteFile(path, []byte(keyAuth), 0o644); err != nil {
		return "", errf(KindInvalid, "确认 webroot 可写", "写入 challenge 文件失败: %v", err)
	}
	return path, nil
}

// removeChallenge 删除 token 文件；不存在不算错误（幂等清理）。
func removeChallenge(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// precheck 在通知 CA 之前自己先访问一次 token URL：把"域名不可达 / webroot 配错 / 80 未监听"
// 这类问题在本地暴露成可操作错误，而不是等 CA 回一个笼统的 unauthorized。
func (c *Client) precheck(domain, token, keyAuth string, port int) error {
	if port == 0 {
		port = 80
	}
	target := "http://" + hostPort(domain, port) + "/" + challengeSubdir + "/" + token
	hc := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := hc.Get(target)
	if err != nil {
		return errf(KindInvalid,
			"预检访问不到 %s：确认域名解析到本机、80 端口由站点监听、webroot 就是该站点的根目录。"+
				"若本机无法回环访问自己的公网域名，可显式 skip_precheck=true（不推荐）",
			"HTTP-01 预检失败（%s）：%v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	got := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK || got != keyAuth {
		return errf(KindInvalid,
			"webroot 配错了或站点没把 .well-known 目录暴露出去：预检请求返回 HTTP "+strconv.Itoa(resp.StatusCode)+
				"，内容不是本次 challenge。"+
				"确认 webroot 指向该域名的站点根目录、站点未拦截 .well-known/acme-challenge 路径",
			"HTTP-01 预检内容不匹配（%s）：期望 keyAuthorization，实际 %q", target, truncate(got, 80))
	}
	return nil
}

// hostPort 拼 host:port（IPv6 自动加方括号）。
func hostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}
