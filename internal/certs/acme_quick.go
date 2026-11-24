package certs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	acmeproto "github.com/pengtang1024/kore-plugin-ssl/internal/acme"
)

// 一键签发（0.7.0）：把「站点页申请免费证书」从"填 5 个 ACME 字段 + 装外部客户端"
// 收敛为「一个站点域名 + 一次确认」。
//
// 设计要点：
//   - 引擎默认内置 ACME（internal/acme），不再依赖本机 certbot / acme.sh——
//     外部客户端只是可选通道（engine=external），不是唯一入口；
//   - 域名从 site 带出，webroot 从站点根约定带出，邮箱 / CA / 密钥类型从已存配置带出；
//   - 仍要求 confirm=true：G-10 的"联网必须由用户显式触发"不变，一次点击就是确认；
//   - 失败一律给「怎么办」：域名解析、80 端口、webroot、限流各有可执行提示。
const (
	// IssueEngineBuiltin 是默认引擎：内置 ACME 客户端，零外部依赖。
	IssueEngineBuiltin = "builtin"
	// IssueEngineExternal 是显式选择的老通道：调用本机 certbot / acme.sh。
	IssueEngineExternal = "external"
	// issueSitesDirEnv 是站点根父目录的运维覆盖（安装器可注入）。
	issueSitesDirEnv = "KORE_SITES_DIR"
	// issueDefaultSiteSubdir 与 site 插件的默认站点根布局一致：
	// <KORE_STATE_DIR>/plugin-data/site/sites/<domain>。
	issueDefaultSiteSubdir = "plugin-data/site/sites"
	// issueStagingCA 是不占生产配额的验证 CA（测试与首次联调用）。
	issueStagingCA = "letsencrypt-staging"
	// issueProductionCA 是一键签发的默认 CA：站点页的目标是拿到浏览器信任的证书。
	//
	// 为什么默认生产而不是 staging：一键申请若默认 staging，用户拿到的证书浏览器不信任，
	// 等于"点了也没用"；生产配额风险由签发前的本地预检（HTTP-01 预检 + 域名可达性）
	// 拦住——失败的校验才会消耗配额，预检就是在消耗之前把问题暴露出来。
	issueProductionCA = "letsencrypt"
)

// QuickIssueRequest 是 ssl.acme.issue 的归一入参：全部字段都有默认值来源。
type QuickIssueRequest struct {
	Domain       string
	Site         string
	AltNames     []string
	Webroot      string
	Email        string
	CA           string
	DirectoryURL string
	KeyType      string
	Engine       string
	Confirm      bool
	SkipPrecheck bool
}

// IssueResolved 记录每个字段是怎么来的（domain_source 等），让调用方能解释"为什么没让用户填"。
type IssueResolved struct {
	Domain        string `json:"domain"`
	DomainSource  string `json:"domain_source"`
	Webroot       string `json:"webroot"`
	WebrootSource string `json:"webroot_source"`
	Email         string `json:"email,omitempty"`
	EmailSource   string `json:"email_source,omitempty"`
	CA            string `json:"ca"`
	CASource      string `json:"ca_source"`
	KeyType       string `json:"key_type"`
	Engine        string `json:"engine"`
}

// QuickIssueResult 复用内置签发结果（前端已按 not_after / cert_path 渲染），
// 额外给出解析来源与引擎，便于排障与"为什么零填写"的解释。
type QuickIssueResult struct {
	ACMEBuiltinIssueResult
	Engine   string        `json:"engine"`
	Resolved IssueResolved `json:"resolved"`
}

// issuePlan 是解析后的执行计划。
type issuePlan struct {
	domains      []string
	webroot      string
	email        string
	ca           string
	directoryURL string
	keyType      string
	resolved     IssueResolved
}

// resolveIssuePlan 按 param → 站点约定 → 已存配置 的顺序推断全部字段。
// 只读、零联网，可单独测试（默认值是否合理不需要真的签一张证书）。
func (s *Service) resolveIssuePlan(req QuickIssueRequest, settings acmeSettings) (*issuePlan, *CertError) {
	plan := &issuePlan{}

	// 1) 域名：domain 优先，其次 site（站点页只需给站点）。
	domain := strings.TrimSpace(req.Domain)
	domainSource := "param"
	if domain == "" {
		domain = strings.TrimSpace(req.Site)
		domainSource = "site"
	}
	if domain == "" {
		// 真零参数：sites_root 下恰好一个站点时直接采用（单站点部署的常见形态）。
		inferred, ierr := s.inferSiteDomain(settings)
		if ierr != nil {
			return nil, ierr
		}
		if inferred != "" {
			domain, domainSource = inferred, "inferred_single_site"
		}
	}
	if domain == "" {
		return nil, newCertHintError(codeInvalid,
			"缺少站点域名：一键签发至少要能从上下文拿到一个域名",
			"传 site（站点页已选中的站点域名）或 domain；若本机只有一个站点，"+
				"用 ssl.acme.auto {sites_root:\"<站点根父目录>\", confirm:true} 配置后可不传站点")
	}
	domains, perr := normalizeIssueDomains(domain, req.AltNames)
	if perr != nil {
		return nil, perr
	}
	plan.domains = domains
	plan.resolved.Domain = domains[0]
	plan.resolved.DomainSource = domainSource

	// 2) webroot：显式 > <sites_root>/<domain> > 已存 webroot。
	webroot, webrootSource, perr := s.resolveIssueWebroot(req.Webroot, settings, domains[0])
	if perr != nil {
		return nil, perr
	}
	plan.webroot = webroot
	plan.resolved.Webroot = webroot
	plan.resolved.WebrootSource = webrootSource

	// 3) 邮箱：显式 > 已存配置；两者都空也允许（CA 联系邮箱可选）。
	plan.email = strings.TrimSpace(req.Email)
	plan.resolved.EmailSource = "param"
	if plan.email == "" {
		plan.email = strings.TrimSpace(settings.Email)
		plan.resolved.EmailSource = "settings"
	}
	if plan.email != "" {
		if !acmeEmailRE.MatchString(plan.email) {
			return nil, invalidParam("email 非法：" + plan.email)
		}
		plan.resolved.Email = plan.email
	}

	// 4) CA：显式 > 已存配置（用户改过才尊重）> 一键默认生产 CA。
	plan.ca = strings.TrimSpace(req.CA)
	plan.resolved.CASource = "param"
	if plan.ca == "" {
		if settings.UpdatedAt != "" && strings.TrimSpace(settings.CA) != "" {
			plan.ca = settings.CA
			plan.resolved.CASource = "settings"
		} else {
			plan.ca = issueProductionCA
			plan.resolved.CASource = "default"
		}
	}
	plan.directoryURL = strings.TrimSpace(req.DirectoryURL)
	if plan.directoryURL == "" && plan.resolved.CASource == "settings" {
		plan.directoryURL = settings.DirectoryURL
	}
	plan.resolved.CA = plan.ca

	// 5) 密钥类型：显式 > 已存 > 默认 ECDSA P-256。
	plan.keyType = acmeKeyTypeOrDefault(firstNonEmpty(req.KeyType, settings.KeyType))
	plan.resolved.KeyType = plan.keyType

	plan.resolved.Engine = IssueEngineBuiltin
	return plan, nil
}

// inferSiteDomain 在零参数调用时从 sites_root 枚举站点：恰好一个才采用。
// 多个站点必须让调用方指定 site——猜错站点会把 challenge 写进别人的站点根。
func (s *Service) inferSiteDomain(settings acmeSettings) (string, *CertError) {
	root := s.resolveSitesRoot(settings)
	if root == "" {
		return "", nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		names = append(names, entry.Name())
	}
	switch len(names) {
	case 0:
		return "", nil
	case 1:
		return names[0], nil
	default:
		sort.Strings(names)
		shown := names
		if len(shown) > 5 {
			shown = shown[:5]
		}
		return "", newCertHintError(codeInvalid,
			"sites_root 下有多个站点，无法自动判断给哪个站点签证书",
			"请带 site 指定站点域名（候选："+strings.Join(shown, "、")+"）")
	}
}

// resolveIssueWebroot 决定 HTTP-01 校验文件写到哪个目录。
func (s *Service) resolveIssueWebroot(param string, settings acmeSettings, domain string) (string, string, *CertError) {
	if webroot := strings.TrimSpace(param); webroot != "" {
		if !filepath.IsAbs(webroot) {
			return "", "", invalidParam("webroot 必须是绝对路径（站点根目录）")
		}
		return filepath.Clean(webroot), "param", nil
	}
	if root := s.resolveSitesRoot(settings); root != "" {
		candidate := filepath.Join(root, domain)
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate, "sites_root", nil
		}
	}
	if stored := strings.TrimSpace(settings.Webroot); stored != "" && filepath.IsAbs(stored) {
		return filepath.Clean(stored), "settings", nil
	}
	root := s.resolveSitesRoot(settings)
	hint := "先确认站点已创建（站点根应存在），或直接带 webroot 指定站点根目录"
	if root != "" {
		hint = "站点根 " + filepath.Join(root, domain) + " 不存在：先在站点页创建该站点，或带 webroot 指定站点根目录；" +
			"也可用 ssl.acme.auto {sites_root:\"<站点根父目录>\", confirm:true} 一次性告诉插件站点都放在哪"
	}
	return "", "", newCertHintError(codeInvalid, "无法确定站点根目录（HTTP-01 需要把校验文件写进站点根）", hint)
}

// resolveSitesRoot 解析站点根父目录：环境变量 > 已存配置 > 站点插件默认布局。
func (s *Service) resolveSitesRoot(settings acmeSettings) string {
	if dir := strings.TrimSpace(os.Getenv(issueSitesDirEnv)); dir != "" {
		return filepath.Clean(dir)
	}
	if dir := strings.TrimSpace(settings.SitesRoot); dir != "" {
		return filepath.Clean(dir)
	}
	if state := strings.TrimSpace(os.Getenv(kernelStateEnv)); state != "" {
		return filepath.Join(state, issueDefaultSiteSubdir)
	}
	return ""
}

// ACMEIssueQuick 是一键签发入口：推断字段 → 确认 → 预检 → 签发 → 验证落盘。
func (s *Service) ACMEIssueQuick(req QuickIssueRequest) (*QuickIssueResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	settings, perr := s.loadACMESettings()
	if perr != nil {
		return nil, perr
	}
	if strings.TrimSpace(req.Engine) == IssueEngineExternal {
		return s.quickIssueExternal(req, settings)
	}
	plan, perr := s.resolveIssuePlan(req, settings)
	if perr != nil {
		return nil, perr
	}
	if !req.Confirm {
		return nil, newCertHintError(codeInvalid,
			"申请证书会联网向 CA 提交订单，必须显式确认（其余字段已自动带出，无需填写）",
			"带 confirm=true 重新调用：域名 "+plan.domains[0]+"、"+
				"站点根 "+plan.webroot+"、CA "+plan.ca+" 都已推断完成")
	}
	if err := acmeproto.EnsureWebroot(plan.webroot); err != nil {
		return nil, acmeErrorToCertError(err)
	}
	sessionSettings := settings
	sessionSettings.CA = plan.ca
	sessionSettings.DirectoryURL = plan.directoryURL
	sessionSettings.Webroot = plan.webroot
	sessionSettings.Email = plan.email
	sessionSettings.KeyType = plan.keyType
	session, perr := s.prepareACMESession(sessionSettings)
	if perr != nil {
		return nil, perr
	}
	result, certFileName, perr := s.issueWithSettings(session, plan.domains, plan.webroot, plan.keyType, req.SkipPrecheck, "")
	if perr != nil {
		s.appendACMEAudit(acmeAuditEntry{
			Action: "issue", CA: session.settings.CA, Directory: session.dirURL,
			Domain: plan.domains[0], Result: "failed", Reason: perr.Message,
		})
		return nil, enrichIssueError(perr, plan.domains[0])
	}
	out, perr := s.persistIssued(session, result, certFileName, plan.domains, "")
	if perr != nil {
		s.appendACMEAudit(acmeAuditEntry{
			Action: "issue", CA: session.settings.CA, Directory: session.dirURL,
			Domain: plan.domains[0], Result: "failed", Reason: perr.Message,
		})
		return nil, perr
	}
	s.appendACMEAudit(acmeAuditEntry{
		Action: "issue", CA: session.settings.CA, Directory: session.dirURL,
		Domain: plan.domains[0], Result: "ok",
	})
	out.Hint = acmeIssueNextStepHint(out.Staging)
	if !out.Staging {
		out.Hint += "；自动续期用 ssl.acme.auto {enabled:true, confirm:true} 开启（默认关闭，G-10）"
	}
	return &QuickIssueResult{
		ACMEBuiltinIssueResult: *out,
		Engine:                 IssueEngineBuiltin,
		Resolved:               plan.resolved,
	}, nil
}

// quickIssueExternal 保留外部客户端通道：域名/邮箱同样支持从 site 与配置推断。
func (s *Service) quickIssueExternal(req QuickIssueRequest, settings acmeSettings) (*QuickIssueResult, *CertError) {
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		domain = strings.TrimSpace(req.Site)
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = strings.TrimSpace(settings.Email)
	}
	result, perr := s.ACMEIssue(ACMEIssueRequest{Domain: domain, Email: email, Confirm: req.Confirm})
	if perr != nil {
		return nil, perr
	}
	out := &ACMEBuiltinIssueResult{
		Domain: result.Domain, Domains: []string{result.Domain},
		CertPath: result.CertPath, KeyPath: result.KeyPath,
		NotAfter: result.NotAfter, DaysLeft: result.DaysLeft,
		Hint: "已用外部客户端 " + result.Tool + " 签发；" + acmeIssueNextStepHint(false),
	}
	return &QuickIssueResult{
		ACMEBuiltinIssueResult: *out,
		Engine:                 IssueEngineExternal,
		Resolved: IssueResolved{
			Domain: result.Domain, DomainSource: ternary(domain != "", "param", "site"),
			Email: email, EmailSource: "settings", Engine: IssueEngineExternal,
		},
	}, nil
}

// enrichIssueError 给失败补上「怎么办」：域名解析 / 80 端口 / 限流是三类高频原因。
func enrichIssueError(perr *CertError, domain string) *CertError {
	if perr == nil {
		return nil
	}
	if perr.Code == codeRatelimit {
		perr.Hint = "Let's Encrypt 限流：同一组域名每周最多 5 张、校验失败每小时 5 次。" +
			"先用 ca=\"letsencrypt-staging\" 跑通流程（不占生产配额），或等窗口重置后再试"
		return perr
	}
	text := perr.Message + " " + perr.Hint
	dnsBroken := containsAny(text, "解析", "no such host", "i/o timeout", "dial tcp", "预检访问不到", "connection refused")
	portBroken := containsAny(text, "80", "connection refused", "timeout", "预检")
	switch {
	case dnsBroken || portBroken:
		parts := []string{}
		if dnsBroken {
			parts = append(parts, "请确认 "+domain+" 的 A 记录已指向本机公网 IP：dig +short A "+domain+"（解析未生效时等 TTL 过期再试）")
		}
		if portBroken {
			parts = append(parts, "Let's Encrypt 需要从公网访问 80 端口：检查防火墙/安全组是否放行 tcp/80，"+
				"并确认站点已监听：curl -I http://"+domain+"/.well-known/acme-challenge/ping")
		}
		parts = append(parts, "webroot 必须是该域名的站点根目录（当前可用 resolved.webroot 核对）")
		perr.Hint = strings.Join(parts, "；")
	}
	if len(perr.Hint) > issueHintMaxLen {
		perr.Hint = perr.Hint[:issueHintMaxLen]
	}
	return perr
}

// issueHintMaxLen 是 hint 上限：错误体不进日志正文，但也不能无限长。
const issueHintMaxLen = 1200

// containsAny 判断文本是否包含任一关键词。
func containsAny(text string, keywords ...string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

// firstNonEmpty 返回第一个非空字符串（默认值链）。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// issueSitesRootHint 用于状态与错误提示，说明站点根父目录是怎么来的。
func (s *Service) issueSitesRootHint(settings acmeSettings) string {
	if dir := strings.TrimSpace(os.Getenv(issueSitesDirEnv)); dir != "" {
		return fmt.Sprintf("%s（环境变量 %s）", filepath.Clean(dir), issueSitesDirEnv)
	}
	if dir := strings.TrimSpace(settings.SitesRoot); dir != "" {
		return filepath.Clean(dir) + "（ssl.acme.auto sites_root）"
	}
	if state := strings.TrimSpace(os.Getenv(kernelStateEnv)); state != "" {
		return filepath.Join(state, issueDefaultSiteSubdir) + "（站点插件默认布局）"
	}
	return "未确定（安装器需注入 KORE_STATE_DIR，或用 ssl.acme.auto 配置 sites_root）"
}
