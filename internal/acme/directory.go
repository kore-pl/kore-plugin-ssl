package acme

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 支持的 CA 预设。目录 URL 是唯一需要"换一个 CA"的配置——ACME 本身与 CA 无关。
const (
	// CA 是 Let's Encrypt 生产环境。
	CA = "letsencrypt"
	// CAStaging 是 Let's Encrypt 测试环境（不占生产配额，默认推荐）。
	CAStaging = "letsencrypt-staging"
	// CALiteSSL 是 TrustAsia 的公益免费证书服务（90 天，强制 EAB）。
	CALiteSSL = "litessl"
	// CACustom 让用户自带任意 RFC 8555 CA。
	CACustom = "custom"
)

// CAPreset 是内置 CA 预设（对前端只读展示，便于用户知道每个 CA 要什么）。
type CAPreset struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DirectoryURL string `json:"directory_url"`
	RequiresEAB  bool   `json:"requires_eab"`
	Notes        string `json:"notes"`
}

// presets 是内置 CA 清单。
//
// LiteSSL 的目录地址来自 lego 官方 CA 清单（go-acme/lego docs: caservers），
// 并于 2026-11-23 直接请求验证：返回 200 + 合法 RFC 8555 directory，
// 其中 meta.externalAccountRequired=true（必须 EAB）。
var presets = []CAPreset{
	{
		ID: CAStaging, Name: "Let's Encrypt（测试环境）",
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		Notes:        "默认推荐：不占生产配额、证书不被浏览器信任，用于先验证域名可达与 webroot 配置",
	},
	{
		ID: CA, Name: "Let's Encrypt",
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Notes:        "生产：90 天有效期，有严格的签发频率限制",
	},
	{
		ID: CALiteSSL, Name: "LiteSSL（TrustAsia 公益证书）",
		DirectoryURL: "https://acme.litessl.com/acme/v2/directory",
		RequiresEAB:  true,
		Notes:        "90 天免费 DV 证书；强制 EAB——在 FreeSSL 控制台「证书自动化 → ACME 账户管理」创建账号取得 eab_kid 与 eab_hmac_key",
	},
	{
		ID: CACustom, Name: "自定义 ACME CA",
		DirectoryURL: "",
		Notes:        "填任意 RFC 8555 directory URL（如 ZeroSSL / Sectigo / 企业自建）；需要 EAB 时同时填 eab_kid 与 eab_hmac_key",
	},
}

// Presets 返回内置 CA 清单的副本（调用方不得修改）。
func Presets() []CAPreset {
	out := make([]CAPreset, len(presets))
	copy(out, presets)
	return out
}

// Preset 按 id 查预设。
func Preset(id string) (CAPreset, bool) {
	for _, p := range presets {
		if p.ID == id {
			return p, true
		}
	}
	return CAPreset{}, false
}

// ResolveDirectoryURL 把 (ca, customURL) 解析成实际目录地址。
// custom 必须显式给 URL；已知预设忽略 customURL。
func ResolveDirectoryURL(ca, customURL string) (string, error) {
	id := strings.TrimSpace(ca)
	if id == "" {
		id = CAStaging
	}
	if id == CACustom {
		target := strings.TrimSpace(customURL)
		if target == "" {
			return "", errf(KindInvalid, "自定义 CA 需要 directory_url", "ca=custom 时必须提供 directory_url（如 https://acme.example.com/directory）")
		}
		if err := validateDirectoryURL(target); err != nil {
			return "", err
		}
		return target, nil
	}
	preset, ok := Preset(id)
	if !ok {
		return "", errf(KindInvalid, "可选的 ca 见 ssl.acme.builtin.status 的 presets", "未知的 ca=%q：可用 letsencrypt-staging / letsencrypt / litessl / custom", ca)
	}
	if preset.DirectoryURL == "" {
		return "", errf(KindInvalid, "该 CA 需要 directory_url", "ca=%q 没有内置地址，请改用 ca=custom 并提供 directory_url", id)
	}
	return preset.DirectoryURL, nil
}

// validateDirectoryURL 只接受 https；仅回环地址允许 http（本地测试替身）。
func validateDirectoryURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errf(KindInvalid, "填完整的 https://... 地址", "directory_url 解析失败: %v", err)
	}
	if parsed.Host == "" || parsed.Path == "" {
		return errf(KindInvalid, "填完整的 https://... 地址", "directory_url 必须是带主机与路径的绝对地址: %q", raw)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if loopbackHost(parsed.Hostname()) {
			return nil
		}
		return errf(KindInvalid, "把地址改成 https://", "directory_url 必须是 https（仅回环地址允许 http，用于本地测试）: %q", raw)
	default:
		return errf(KindInvalid, "把地址改成 https://", "directory_url 只支持 https: %q", raw)
	}
}

// Directory 是 RFC 8555 §7.1.1 的目录资源；只保留客户端会用到的字段。
type Directory struct {
	NewNonce    string `json:"newNonce"`
	NewAccount  string `json:"newAccount"`
	NewOrder    string `json:"newOrder"`
	RevokeCert  string `json:"revokeCert"`
	KeyChange   string `json:"keyChange"`
	RenewalInfo string `json:"renewalInfo,omitempty"`
	Meta        struct {
		TermsOfService          string   `json:"termsOfService"`
		Website                 string   `json:"website"`
		CAAIdentities           []string `json:"caaIdentities"`
		ExternalAccountRequired bool     `json:"externalAccountRequired"`
	} `json:"meta"`
}

// fetchDirectory 拉取并校验目录（缺 newNonce/newAccount/newOrder 一律视为不是 ACME v2）。
func fetchDirectory(ctx context.Context, hc *http.Client, directoryURL string) (*Directory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL, nil)
	if err != nil {
		return nil, errf(KindInvalid, "检查 directory_url 是否拼写正确", "构造目录请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, errf(KindUpstream, "确认本机能访问该 CA（DNS/出站 443/代理）", "访问 ACME 目录失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errf(KindUpstream, "重试；持续失败检查网络是否被中断", "读取 ACME 目录响应失败: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errf(KindUpstream, "确认 directory_url 指向 ACME v2 目录（不是首页/文档页）", "ACME 目录返回 HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var dir Directory
	if err := json.Unmarshal(body, &dir); err != nil {
		return nil, errf(KindInvalid, "确认填的是 ACME directory 地址（返回 JSON 的那个）", "ACME 目录不是合法 JSON: %v", err)
	}
	if dir.NewNonce == "" || dir.NewAccount == "" || dir.NewOrder == "" {
		return nil, errf(KindInvalid, "确认填的是 ACME directory 地址", "ACME 目录缺少 newNonce/newAccount/newOrder：该地址不是 RFC 8555 目录")
	}
	return &dir, nil
}

// truncate 截断用于错误消息的外部内容。
func truncate(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= limit {
		return raw
	}
	return raw[:limit] + "..."
}

// loopbackHost 判断域名是否回环（测试用）。
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// defaultHTTPTimeout 是单次 ACME HTTP 请求的默认超时。
const defaultHTTPTimeout = 30 * time.Second

// newHTTPClient 返回内置 ACME 客户端使用的 HTTP 客户端（仅显式调用时创建）。
func newHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultHTTPTimeout}
}
