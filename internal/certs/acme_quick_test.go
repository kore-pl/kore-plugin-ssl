package certs

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/acme/acmetest"
)

// newQuickIssueService 构造"站点根可通过回环 HTTP 访问"的服务：
// sites_root 下建好 example.com 站点目录，返回值里的 service 已把预检指向本地文件服务。
func newQuickIssueService(t *testing.T) (*Service, string, string) {
	t.Helper()
	sitesRoot := filepath.Join(t.TempDir(), "sites")
	siteDir := filepath.Join(sitesRoot, "example.com")
	if err := os.MkdirAll(siteDir, 0o755); err != nil {
		t.Fatalf("建站点目录失败: %v", err)
	}
	fileServer := httptest.NewServer(http.FileServer(http.Dir(siteDir)))
	t.Cleanup(fileServer.Close)
	parsed, err := url.Parse(fileServer.URL)
	if err != nil {
		t.Fatalf("解析测试服务地址失败: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("取端口失败: %v", err)
	}
	svc := NewService(Options{Dir: t.TempDir(), ACMEPrecheckPort: port, ACMEPrecheckHost: "127.0.0.1"})
	return svc, sitesRoot, siteDir
}

// TestQuickIssueZeroFieldUsesSiteContext 是主验收：只给站点域名 + 确认，
// 域名 / webroot / 邮箱 / CA / 密钥类型全部自动带出，并用 mock CA 真实签发。
func TestACMEIssueQuickZeroParamFromSiteContext(t *testing.T) {
	svc, sitesRoot, siteDir := newQuickIssueService(t)
	mock := acmetest.New(t, acmetest.Options{Webroot: siteDir})
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{
		CA: "custom", DirectoryURL: mock.DirectoryURL(), SitesRoot: sitesRoot,
		Email: "ops@example.com", Confirm: true,
	}); perr != nil {
		t.Fatalf("配置 mock CA 失败: %v（hint=%s）", perr, perr.Hint)
	}

	// 用户只做一次点击：给出站点域名 + confirm，其余零填写。
	result, perr := svc.ACMEIssueQuick(QuickIssueRequest{Site: "example.com", Confirm: true})
	if perr != nil {
		t.Fatalf("一键签发失败: %v（hint=%s）", perr, perr.Hint)
	}
	if result.Engine != IssueEngineBuiltin {
		t.Fatalf("默认引擎应为内置 ACME，实际 %q", result.Engine)
	}
	if result.Resolved.DomainSource != "site" || result.Resolved.Domain != "example.com" {
		t.Fatalf("域名应从 site 推断，实际 %+v", result.Resolved)
	}
	if result.Resolved.WebrootSource != "sites_root" || result.Resolved.Webroot != siteDir {
		t.Fatalf("webroot 应从站点根约定推断，实际 %+v", result.Resolved)
	}
	if result.Resolved.EmailSource != "settings" || result.Resolved.Email != "ops@example.com" {
		t.Fatalf("邮箱应从已存配置推断，实际 %+v", result.Resolved)
	}
	if result.Resolved.CASource != "settings" || result.Resolved.CA != "custom" {
		t.Fatalf("CA 应从已存配置读取，实际 %+v", result.Resolved)
	}
	if result.CertPath == "" || result.DaysLeft <= 0 || result.NotAfter == "" {
		t.Fatalf("签发结果缺证书元数据: %+v", result)
	}
	if _, err := os.Stat(result.CertPath); err != nil {
		t.Fatalf("证书未落盘: %v", err)
	}
	if _, err := os.Stat(result.KeyPath); err != nil {
		t.Fatalf("私钥未落盘: %v", err)
	}
	if !strings.Contains(result.Hint, "ssl.bind.set") || !strings.Contains(result.Hint, "site.bindSSL") {
		t.Fatalf("成功后必须给下一步（绑定链路），实际 %q", result.Hint)
	}
	if mock.ChallengeAttempts() == 0 {
		t.Fatal("mock CA 未收到 challenge（签发没有真实走 HTTP-01）")
	}
}

// TestQuickIssueConfirmGateZeroNetwork 是反例：不给 confirm 必须拒绝，且一次网络请求都不发。
func TestQuickIssueConfirmGateZeroNetwork(t *testing.T) {
	svc, sitesRoot, _ := newQuickIssueService(t)
	mock := acmetest.New(t, acmetest.Options{Webroot: filepath.Join(sitesRoot, "example.com")})
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{
		CA: "custom", DirectoryURL: mock.DirectoryURL(), SitesRoot: sitesRoot, Confirm: true,
	}); perr != nil {
		t.Fatalf("配置 mock CA 失败: %v", perr)
	}
	before := mock.Requests()
	_, perr := svc.ACMEIssueQuick(QuickIssueRequest{Site: "example.com"})
	if perr == nil || perr.Code != codeInvalid {
		t.Fatalf("confirm=false 应 E_INVALID，实际 %+v", perr)
	}
	if !strings.Contains(perr.Hint, "confirm=true") {
		t.Fatalf("必须告诉用户怎么确认，实际 %q", perr.Hint)
	}
	if got := mock.Requests() - before; got != 0 {
		t.Fatalf("未确认时不得联网，实际发了 %d 个请求", got)
	}
}

// TestACMEIssueQuickZeroParamSingleSite 是真零参数：不传站点，sites_root 下只有一个站点时自动采用。
func TestACMEIssueQuickZeroParamSingleSite(t *testing.T) {
	svc, sitesRoot, siteDir := newQuickIssueService(t)
	mock := acmetest.New(t, acmetest.Options{Webroot: siteDir})
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{
		CA: "custom", DirectoryURL: mock.DirectoryURL(), SitesRoot: sitesRoot,
		Email: "ops@example.com", Confirm: true,
	}); perr != nil {
		t.Fatalf("配置 mock CA 失败: %v（hint=%s）", perr, perr.Hint)
	}
	result, perr := svc.ACMEIssueQuick(QuickIssueRequest{Confirm: true})
	if perr != nil {
		t.Fatalf("单站点零参数签发失败: %v（hint=%s）", perr, perr.Hint)
	}
	if result.Resolved.DomainSource != "inferred_single_site" || result.Resolved.Domain != "example.com" {
		t.Fatalf("单站点应自动推断域名，实际 %+v", result.Resolved)
	}
	if result.CertPath == "" {
		t.Fatalf("零参数签发未落盘: %+v", result)
	}
}

// TestQuickIssueMultipleSitesNeedsSite 是反例：多站点时不得猜，必须列出候选要求指定。
func TestQuickIssueMultipleSitesNeedsSite(t *testing.T) {
	svc, sitesRoot, _ := newQuickIssueService(t)
	second := filepath.Join(sitesRoot, "shop.example.com")
	if err := os.MkdirAll(second, 0o755); err != nil {
		t.Fatalf("建第二个站点失败: %v", err)
	}
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{
		CA: "custom", DirectoryURL: "http://127.0.0.1:1/directory", SitesRoot: sitesRoot, Confirm: true,
	}); perr != nil {
		t.Fatalf("配置 sites_root 失败: %v", perr)
	}
	_, perr := svc.ACMEIssueQuick(QuickIssueRequest{Confirm: true})
	if perr == nil || perr.Code != codeInvalid {
		t.Fatalf("多站点应拒绝自动推断，实际 %+v", perr)
	}
	if !strings.Contains(perr.Hint, "example.com") || !strings.Contains(perr.Hint, "shop.example.com") {
		t.Fatalf("必须列出候选站点，实际 %q", perr.Hint)
	}
}

// TestQuickIssueMissingDomainActionable 是反例：只有 confirm 时必须指出缺什么、怎么补。
func TestQuickIssueMissingDomainActionable(t *testing.T) {
	svc, _, _ := newQuickIssueService(t)
	_, perr := svc.ACMEIssueQuick(QuickIssueRequest{Confirm: true})
	if perr == nil || perr.Code != codeInvalid {
		t.Fatalf("缺域名应 E_INVALID，实际 %+v", perr)
	}
	if !strings.Contains(perr.Message, "站点域名") || !strings.Contains(perr.Hint, "site") {
		t.Fatalf("提示必须点明缺站点域名并给出 site 字段：message=%q hint=%q", perr.Message, perr.Hint)
	}
}

// TestQuickIssuePrecheckFailureHintIsActionable 是反例：预检不通时提示必须含 dig 与防火墙。
func TestQuickIssuePrecheckFailureHintIsActionable(t *testing.T) {
	sitesRoot := filepath.Join(t.TempDir(), "sites")
	siteDir := filepath.Join(sitesRoot, "example.com")
	if err := os.MkdirAll(siteDir, 0o755); err != nil {
		t.Fatalf("建站点目录失败: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	svc := NewService(Options{Dir: t.TempDir(), ACMEPrecheckPort: closedPort, ACMEPrecheckHost: "127.0.0.1"})
	mock := acmetest.New(t, acmetest.Options{Webroot: siteDir})
	if _, perr := svc.ACMEAuto(ACMEAutoRequest{
		CA: "custom", DirectoryURL: mock.DirectoryURL(), SitesRoot: sitesRoot, Confirm: true,
	}); perr != nil {
		t.Fatalf("配置 mock CA 失败: %v", perr)
	}
	_, perr := svc.ACMEIssueQuick(QuickIssueRequest{Site: "example.com", Confirm: true})
	if perr == nil {
		t.Fatal("预检不通应失败")
	}
	if !strings.Contains(perr.Hint, "dig +short A example.com") {
		t.Fatalf("提示必须给出 dig 检查命令，实际 %q", perr.Hint)
	}
	if !strings.Contains(perr.Hint, "80 端口") || !strings.Contains(perr.Hint, "防火墙") {
		t.Fatalf("提示必须说明 80 端口与防火墙，实际 %q", perr.Hint)
	}
}

// TestEnrichIssueErrorRateLimit 是反例：限流错误必须指向 staging，而不是让用户干等。
func TestEnrichIssueErrorRateLimit(t *testing.T) {
	perr := enrichIssueError(&CertError{Code: codeRatelimit, Message: "too many certificates"}, "example.com")
	if !strings.Contains(perr.Hint, "letsencrypt-staging") || !strings.Contains(perr.Hint, "5") {
		t.Fatalf("限流提示应给 staging 与配额口径，实际 %q", perr.Hint)
	}
	other := enrichIssueError(&CertError{Code: codeUpstream, Message: "boom"}, "example.com")
	if strings.Contains(other.Hint, "dig +short A") {
		t.Fatalf("与域名/端口无关的错误不应塞 DNS 提示，实际 %q", other.Hint)
	}
}

// TestQuickIssueDefaultCAIsProduction 验证未配置过 ACME 时一键路径默认生产 CA，
// 配置过之后尊重用户选择——"默认值"与"用户覆盖"必须可区分。
func TestQuickIssueDefaultCAIsProduction(t *testing.T) {
	svc, sitesRoot, siteDir := newQuickIssueService(t)
	settings, perr := svc.loadACMESettings()
	if perr != nil {
		t.Fatalf("读默认设置失败: %v", perr)
	}
	plan, perr := svc.resolveIssuePlan(QuickIssueRequest{Site: "example.com", Webroot: siteDir}, settings)
	if perr != nil {
		t.Fatalf("解析计划失败: %v", perr)
	}
	if plan.ca != issueProductionCA || plan.resolved.CASource != "default" {
		t.Fatalf("未配置时默认应为生产 CA，实际 ca=%q source=%q", plan.ca, plan.resolved.CASource)
	}
	if plan.resolved.WebrootSource != "param" {
		t.Fatalf("显式 webroot 应优先，实际 %q", plan.resolved.WebrootSource)
	}

	if _, perr := svc.ACMEAuto(ACMEAutoRequest{
		CA: issueStagingCA, SitesRoot: sitesRoot, Confirm: true,
	}); perr != nil {
		t.Fatalf("配置 staging 失败: %v", perr)
	}
	settings, perr = svc.loadACMESettings()
	if perr != nil {
		t.Fatalf("重读设置失败: %v", perr)
	}
	plan, perr = svc.resolveIssuePlan(QuickIssueRequest{Site: "example.com"}, settings)
	if perr != nil {
		t.Fatalf("解析计划失败: %v", perr)
	}
	if plan.ca != issueStagingCA || plan.resolved.CASource != "settings" {
		t.Fatalf("用户配置后应尊重 settings，实际 ca=%q source=%q", plan.ca, plan.resolved.CASource)
	}
	if plan.resolved.WebrootSource != "sites_root" {
		t.Fatalf("未给 webroot 时应从 sites_root 推断，实际 %q", plan.resolved.WebrootSource)
	}
}

// TestQuickIssueExternalEngineKeepsLegacyPath 验证 engine=external 仍走外部客户端通道：
// 本机没有 certbot/acme.sh 时必须如实 E_UNSUPPORTED 并给安装指引，不静默改走内置。
func TestQuickIssueExternalEngineKeepsLegacyPath(t *testing.T) {
	svc, _, _ := newQuickIssueService(t)
	_, perr := svc.ACMEIssueQuick(QuickIssueRequest{
		Site: "example.com", Email: "ops@example.com", Engine: IssueEngineExternal, Confirm: true,
	})
	if perr == nil || perr.Code != codeUnsupported {
		t.Fatalf("无外部客户端应 E_UNSUPPORTED，实际 %+v", perr)
	}
	if !strings.Contains(perr.Message, "certbot") || perr.Hint == "" {
		t.Fatalf("必须点明缺什么并给指引：%+v", perr)
	}
}
