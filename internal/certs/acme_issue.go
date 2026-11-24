package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	acmeproto "github.com/pengtang1024/kore-plugin-ssl/internal/acme"
)

// 内置 ACME 签发 / 自动续期（0.5.0）。
//
// 设计要点：
//   - 用户显式调用（acme.builtin.issue）+ confirm=true 才联网（G-10）；
//   - 自动续期默认关闭，只有 acme.auto 显式开启后内核 scheduler 才会调 acme.builtin.renew；
//   - 续期顺序固定：到期判定 → 备份旧证书 → 签发 → 验证（密钥/域名/链完整性/TLS 自检）
//     → 落盘 + .acme 标记；任一步失败都保留旧证书，绝不半覆盖；
//   - 账户密钥 / 设置 / 审计全在 <证书目录>/acme（0600），删安装目录即清零（G-31）。
const (
	// acmeIssueBudget 是单次签发的总预算（含 CA 校验与轮询）。
	acmeIssueBudget = 5 * time.Minute
	// acmeTLSProbeBudget 是"新证书本地 TLS 自检"的预算。
	acmeTLSProbeBudget = 5 * time.Second
	// acmeAutoTaskHour 是自动续期任务的每日执行时刻（本地时区）。
	acmeAutoTaskHour = 3
	// acmeAutoTaskSchedule 是推荐 cron（每天 03:00，与 renew.set 同一口径）。
	acmeAutoTaskSchedule = "0 3 * * *"
	// acmeAutoTaskNameMaxLen 与内核 scheduler 的 name ≤64 对齐。
	acmeAutoTaskNameMaxLen = 64
)

// acmeSession 是一次 ACME 会话的准备结果（客户端 + 账号配置 + 审计上下文）。
type acmeSession struct {
	client   *acmeproto.Client
	caID     string
	dirURL   string
	contact  []string
	eab      *acmeproto.EAB
	settings acmeSettings
}

// finish 在签发成功后持久化账号 KID（下次复用，避免每次 newAccount）。
func (s *Service) finishACMEAccount(session *acmeSession) {
	kid := session.client.KID()
	if kid == "" {
		return
	}
	existing, ok := s.loadACMEAccount(session.caID)
	if ok && existing.KID == kid && existing.Directory == session.dirURL {
		return
	}
	contact := ""
	if len(session.contact) > 0 {
		contact = strings.TrimPrefix(session.contact[0], "mailto:")
	}
	_ = s.saveACMEAccount(session.caID, acmeAccount{
		KID: kid, Directory: session.dirURL, Contact: contact,
		CreatedAt: nowOr(s.now).UTC().Format(time.RFC3339),
	})
}

// prepareACMESession 校验配置并构造客户端；不发起任何签发请求（目录 GET 除外）。
func (s *Service) prepareACMESession(settings acmeSettings) (*acmeSession, *CertError) {
	dirURL, err := acmeproto.ResolveDirectoryURL(settings.CA, settings.DirectoryURL)
	if err != nil {
		return nil, acmeErrorToCertError(err)
	}
	caID := sanitizeCAID(settings.CA)
	key, keyErr := s.accountKey(caID)
	if keyErr != nil {
		return nil, internalErr("读取/创建 ACME 账户密钥失败: " + keyErr.Error())
	}
	kid := ""
	if acct, ok := s.loadACMEAccount(caID); ok && acct.Directory == dirURL {
		kid = acct.KID
	}
	ctx, cancel := context.WithTimeout(context.Background(), acmeIssueBudget)
	defer cancel()
	client, clientErr := acmeproto.NewClient(ctx, acmeproto.Options{
		DirectoryURL: dirURL, AccountKey: key, KID: kid,
	})
	if clientErr != nil {
		return nil, acmeErrorToCertError(clientErr)
	}
	session := &acmeSession{client: client, caID: caID, dirURL: dirURL, settings: settings}
	if email := strings.TrimSpace(settings.Email); email != "" {
		session.contact = []string{"mailto:" + email}
	}
	if settings.EABKid != "" && settings.EABHMACKey != "" {
		session.eab = &acmeproto.EAB{Kid: settings.EABKid, HMACKey: settings.EABHMACKey}
	} else if settings.EABKid != "" || settings.EABHMACKey != "" {
		return nil, newCertHintError(codeInvalid,
			"EAB 配置不完整：eab_kid 与 eab_hmac_key 必须同时提供",
			"到 CA 控制台复制同一对 eab_kid / eab_hmac_key，用 ssl.acme.auto 一次性写入")
	}
	return session, nil
}

// issueWithSettings 是签发/续期共用的执行体：调协议层 → 验证 → 落盘（可选备份）。
//
// 返回值里的 certFileName 是最终落盘的文件名（续期时沿用原文件后缀）。
func (s *Service) issueWithSettings(session *acmeSession, domains []string, webroot, keyType string,
	skipPrecheck bool, backupName string) (*acmeproto.IssueResult, string, *CertError) {
	ctx, cancel := context.WithTimeout(context.Background(), acmeIssueBudget)
	defer cancel()
	result, err := session.client.Issue(ctx, acmeproto.IssueRequest{
		Domains: domains, Webroot: webroot, KeyType: keyType,
		Contact: session.contact, EAB: session.eab, SkipPrecheck: skipPrecheck,
		PrecheckPort: s.acmePrecheckPort, PrecheckHost: s.acmePrecheckHost,
	})
	if err != nil {
		return nil, "", acmeErrorToCertError(err)
	}
	s.finishACMEAccount(session)
	return result, filepath.Base(domains[0] + certSuffix), nil
}

// persistIssued 验证并落盘签出的证书，返回证书/私钥/链路径与元数据。
func (s *Service) persistIssued(session *acmeSession, result *acmeproto.IssueResult,
	certFileName string, domains []string, backupName string) (*ACMEBuiltinIssueResult, *CertError) {
	now := nowOr(s.now)
	if _, _, perr := verifyACMEIssued(result.CertPEM, result.KeyPEM, domains, now); perr != nil {
		return nil, perr
	}
	leafPEM, chainPEM, _, splitErr := splitCertChain(result.CertPEM)
	if splitErr != nil {
		return nil, internalErr("拆分证书链失败: " + splitErr.Error())
	}
	backupPath := ""
	if backupName != "" {
		path, backupErr := s.store.backupPair(backupName, now)
		if backupErr != nil {
			return nil, newCertHintError(codeInternal,
				"续期前备份旧证书失败，已中止（不覆盖旧证书）: "+backupErr.Error(),
				"检查证书目录可写与磁盘空间后重试")
		}
		backupPath = path
	}
	if err := s.store.writePair(certFileName, leafPEM, result.KeyPEM, chainPEM); err != nil {
		return nil, internalErr("写入 ACME 证书失败: " + err.Error())
	}
	if err := s.store.writeACMEMarker(certFileName, "builtin:"+session.caID, now); err != nil {
		return nil, newCertHintError(codeInternal,
			"证书已写入但归属标记写入失败: "+err.Error(),
			"重试一次；若持续失败检查证书目录权限（需可写）")
	}
	base := trimCertSuffix(certFileName)
	out := &ACMEBuiltinIssueResult{
		Domain:       domains[0],
		Domains:      domains,
		CA:           session.settings.CA,
		DirectoryURL: session.dirURL,
		Staging:      session.settings.CA == acmeproto.CAStaging,
		CertPath:     s.store.certAbsPath(certFileName),
		KeyPath:      s.store.certAbsPath(base + keySuffix),
		ChainPath:    s.store.certAbsPath(base + chainSuffix),
		NotAfter:     result.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:     daysLeft(result.NotAfter, now),
		ChainLength:  result.ChainLength,
		BackupPath:   backupPath,
		OrderURL:     result.OrderURL,
	}
	if len(chainPEM) == 0 {
		out.ChainPath = ""
	}
	return out, nil
}

// ACMEBuiltinIssueRequest 是 ssl.acme.builtin.issue 的入参。
type ACMEBuiltinIssueRequest struct {
	Domain       string
	AltNames     []string
	Email        string
	CA           string
	DirectoryURL string
	Webroot      string
	KeyType      string
	Confirm      bool
	SkipPrecheck bool
}

// ACMEBuiltinIssueResult 是签发结果（不含私钥内容，只有路径与元数据）。
type ACMEBuiltinIssueResult struct {
	Domain       string   `json:"domain"`
	Domains      []string `json:"domains"`
	CA           string   `json:"ca"`
	DirectoryURL string   `json:"directory_url"`
	Staging      bool     `json:"staging"`
	CertPath     string   `json:"cert_path"`
	KeyPath      string   `json:"key_path"`
	ChainPath    string   `json:"chain_path,omitempty"`
	NotAfter     string   `json:"not_after"`
	DaysLeft     int      `json:"days_left"`
	ChainLength  int      `json:"chain_length"`
	BackupPath   string   `json:"backup_path,omitempty"`
	OrderURL     string   `json:"order_url,omitempty"`
	Hint         string   `json:"hint"`
}

// ACMEBuiltinIssue 用内置 ACME 客户端签发证书（显式调用 + confirm）。
func (s *Service) ACMEBuiltinIssue(req ACMEBuiltinIssueRequest) (*ACMEBuiltinIssueResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	if !req.Confirm {
		return nil, newCertHintError(codeInvalid,
			"ACME 签发会联网向 CA 申请证书，必须显式确认",
			"带 confirm=true 重新调用；首次建议 ca=letsencrypt-staging（不占生产配额），并确认 webroot 指向站点根")
	}
	settings, perr := s.loadACMESettings()
	if perr != nil {
		return nil, perr
	}
	settings = applyIssueOverrides(settings, req)
	domains, perr := normalizeIssueDomains(req.Domain, req.AltNames)
	if perr != nil {
		return nil, perr
	}
	if strings.TrimSpace(settings.Webroot) == "" {
		return nil, newCertHintError(codeInvalid,
			"缺少 webroot：HTTP-01 需要把校验文件写进站点根目录",
			"用 ssl.acme.auto {webroot:\"/install/data/sites/<域名>\", confirm:true} 配置，或本次调用直接传 webroot")
	}
	if err := acmeproto.EnsureWebroot(settings.Webroot); err != nil {
		return nil, acmeErrorToCertError(err)
	}
	session, perr := s.prepareACMESession(settings)
	if perr != nil {
		return nil, perr
	}
	result, certFileName, perr := s.issueWithSettings(session, domains, settings.Webroot, acmeKeyTypeOrDefault(settings.KeyType), req.SkipPrecheck, "")
	if perr != nil {
		s.appendACMEAudit(acmeAuditEntry{
			Action: "issue", CA: session.settings.CA, Directory: session.dirURL,
			Domain: domains[0], Result: "failed", Reason: perr.Message,
		})
		return nil, perr
	}
	out, perr := s.persistIssued(session, result, certFileName, domains, "")
	if perr != nil {
		s.appendACMEAudit(acmeAuditEntry{
			Action: "issue", CA: session.settings.CA, Directory: session.dirURL,
			Domain: domains[0], Result: "failed", Reason: perr.Message,
		})
		return nil, perr
	}
	s.appendACMEAudit(acmeAuditEntry{
		Action: "issue", CA: session.settings.CA, Directory: session.dirURL,
		Domain: domains[0], Result: "ok",
	})
	out.Hint = acmeIssueNextStepHint(out.Staging)
	return out, nil
}

// acmeIssueNextStepHint 是签发成功后的下一步文案（单点维护，一键签发复用）。
// 站点绑定是 site 侧动作：本仓只给建议载荷，绝不代执行。
func acmeIssueNextStepHint(staging bool) string {
	if staging {
		return "这是 Let's Encrypt staging 证书（浏览器不信任）：把 ca 换成 letsencrypt 或 litessl 再签一次即可上线"
	}
	return "证书已落盘；到站点页用 ssl.bind.set 登记归属，再用 site.bindSSL 绑定（本仓不写站点配置）"
}

// applyIssueOverrides 把本次调用的覆盖项叠加到已存设置上（不持久化）。
func applyIssueOverrides(settings acmeSettings, req ACMEBuiltinIssueRequest) acmeSettings {
	if ca := strings.TrimSpace(req.CA); ca != "" {
		settings.CA = ca
	}
	if dir := strings.TrimSpace(req.DirectoryURL); dir != "" {
		settings.DirectoryURL = dir
	}
	if webroot := strings.TrimSpace(req.Webroot); webroot != "" {
		settings.Webroot = webroot
	}
	if email := strings.TrimSpace(req.Email); email != "" {
		settings.Email = email
	}
	if keyType := strings.TrimSpace(req.KeyType); keyType != "" {
		settings.KeyType = keyType
	}
	return settings
}

// acmeKeyTypeOrDefault 收敛密钥类型（与 selfsign 的取值一致）。
func acmeKeyTypeOrDefault(keyType string) string {
	switch strings.TrimSpace(keyType) {
	case acmeproto.KeyTypeRSA2048:
		return acmeproto.KeyTypeRSA2048
	default:
		return acmeproto.KeyTypeECDSA256
	}
}

// normalizeIssueDomains 校验主域名 + 附加域名并归一化。
func normalizeIssueDomains(domain string, altNames []string) ([]string, *CertError) {
	primary := strings.TrimSpace(domain)
	if primary == "" {
		return nil, invalidParam("缺少必填字段 domain")
	}
	input := append([]string{primary}, altNames...)
	domains, err := acmeproto.NormalizeDomains(input)
	if err != nil {
		return nil, acmeErrorToCertError(err)
	}
	return domains, nil
}

// ACMERenewEntry 是单张证书的续期结果。
type ACMERenewEntry struct {
	Name       string `json:"name"`
	Action     string `json:"action"`
	Reason     string `json:"reason,omitempty"`
	BackupPath string `json:"backup_path,omitempty"`
	CertPath   string `json:"cert_path,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	DaysLeft   int    `json:"days_left"`
}

// ACMEBuiltinRenewRequest 是 ssl.acme.builtin.renew 的入参：可只续一张（name），缺省续全部。
type ACMEBuiltinRenewRequest struct {
	Name string
}

// ACMEBuiltinRenewResult 是批量续期结果。
type ACMEBuiltinRenewResult struct {
	AutoRenew  bool             `json:"auto_renew"`
	DaysBefore int              `json:"days_before"`
	Checked    int              `json:"checked"`
	Due        int              `json:"due"`
	Renewed    int              `json:"renewed"`
	Skipped    int              `json:"skipped"`
	Failed     int              `json:"failed"`
	Certs      []ACMERenewEntry `json:"certs"`
	NextRunAt  string           `json:"next_run_at"`
	Hint       string           `json:"hint"`
}

// ACMEBuiltinRenew 是 scheduler 入口：自动续期开启时才工作，续期所有到期 ACME 证书。
func (s *Service) ACMEBuiltinRenew(req ACMEBuiltinRenewRequest) (*ACMEBuiltinRenewResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	settings, perr := s.loadACMESettings()
	if perr != nil {
		return nil, perr
	}
	if !settings.AutoRenew {
		return nil, newCertHintError(codeUnsupported,
			"自动续期未开启：本方法只在内核 scheduler 到点调用时工作",
			"用 ssl.acme.auto {enabled:true, confirm:true} 显式开启（默认关闭是为了 G-10：不开启就不联网）")
	}
	now := nowOr(s.now)
	infos, scanErr := s.store.scan(now)
	if scanErr != nil {
		return nil, internalErr("扫描证书目录失败: " + scanErr.Error())
	}
	result := &ACMEBuiltinRenewResult{
		AutoRenew: true, DaysBefore: settings.DaysBefore,
		Certs:     []ACMERenewEntry{},
		NextRunAt: nextDailyRun(now, acmeAutoTaskHour).UTC().Format(time.RFC3339),
	}
	name := strings.TrimSpace(req.Name)
	due := make([]CertInfo, 0, len(infos))
	for _, info := range infos {
		if name != "" && info.Domain != name {
			continue
		}
		if info.Error != "" || info.Source != "acme" {
			continue
		}
		result.Checked++
		if info.DaysLeft >= settings.DaysBefore {
			result.Skipped++
			result.Certs = append(result.Certs, ACMERenewEntry{
				Name: info.Domain, Action: "skipped", Reason: "未到续期窗口", DaysLeft: info.DaysLeft,
				CertPath: s.store.certAbsPath(info.File), NotAfter: info.NotAfter,
			})
			continue
		}
		due = append(due, info)
	}
	if len(due) == 0 {
		result.Hint = fmt.Sprintf("已检查 %d 张 ACME 证书，没有需要续期的（提前量 %d 天）", result.Checked, settings.DaysBefore)
		return result, nil
	}
	if strings.TrimSpace(settings.Webroot) == "" {
		return nil, newCertHintError(codeInvalid,
			"有到期证书但未配置 webroot，无法执行 HTTP-01",
			"用 ssl.acme.auto {webroot:\"/install/data/sites/<域名>\", confirm:true} 配置站点根目录")
	}
	result.Due = len(due)
	for _, info := range due {
		entry := s.renewOneACMECert(info, settings)
		switch entry.Action {
		case "renewed":
			result.Renewed++
		case "failed":
			result.Failed++
		default:
			result.Skipped++
		}
		result.Certs = append(result.Certs, entry)
	}
	result.Hint = fmt.Sprintf("到期 %d 张：成功 %d / 失败 %d（失败项保留旧证书，旧证书未被覆盖）",
		result.Due, result.Renewed, result.Failed)
	if result.Failed > 0 && result.Renewed == 0 {
		return result, newCertHintError(codeUpstream,
			fmt.Sprintf("%d 张到期证书全部续期失败，旧证书保持不变", result.Failed),
			"看 certs[].reason 与 <证书目录>/acme/audit.jsonl；常见原因：域名不可达、webroot 配错、CA 限流")
	}
	return result, nil
}

// renewOneACMECert 续期单张证书：到期判定已在外层完成，这里负责备份→签发→验证→落盘。
func (s *Service) renewOneACMECert(info CertInfo, settings acmeSettings) ACMERenewEntry {
	entry := ACMERenewEntry{
		Name: info.Domain, DaysLeft: info.DaysLeft,
		CertPath: s.store.certAbsPath(info.File), NotAfter: info.NotAfter,
	}
	domains, perr := certRenewDomains(info)
	if perr != nil {
		entry.Action = "failed"
		entry.Reason = perr.Message
		s.appendACMEAudit(acmeAuditEntry{Action: "renew", CA: settings.CA, Domain: info.Domain, Result: "failed", Reason: perr.Message})
		return entry
	}
	session, perr := s.prepareACMESession(settings)
	if perr != nil {
		entry.Action = "failed"
		entry.Reason = perr.Message
		s.appendACMEAudit(acmeAuditEntry{Action: "renew", CA: settings.CA, Domain: info.Domain, Result: "failed", Reason: perr.Message})
		return entry
	}
	keyType := acmeproto.KeyTypeECDSA256
	if info.KeyType == "rsa" {
		keyType = acmeproto.KeyTypeRSA2048
	}
	result, _, perr := s.issueWithSettings(session, domains, settings.Webroot, keyType, false, "")
	if perr != nil {
		entry.Action = "failed"
		entry.Reason = perr.Message
		s.appendACMEAudit(acmeAuditEntry{Action: "renew", CA: settings.CA, Directory: session.dirURL, Domain: info.Domain, Result: "failed", Reason: perr.Message})
		return entry
	}
	// 沿用原文件名（保持用户已绑定的路径不变），并在覆盖前备份。
	out, perr := s.persistIssued(session, result, info.File, domains, info.File)
	if perr != nil {
		entry.Action = "failed"
		entry.Reason = perr.Message
		s.appendACMEAudit(acmeAuditEntry{Action: "renew", CA: settings.CA, Directory: session.dirURL, Domain: info.Domain, Result: "failed", Reason: perr.Message})
		return entry
	}
	entry.Action = "renewed"
	entry.BackupPath = out.BackupPath
	entry.CertPath = out.CertPath
	entry.NotAfter = out.NotAfter
	entry.DaysLeft = out.DaysLeft
	s.appendACMEAudit(acmeAuditEntry{Action: "renew", CA: settings.CA, Directory: session.dirURL, Domain: info.Domain, Result: "ok"})
	return entry
}

// certRenewDomains 从已有证书取续期域名：只取 DNS 名，拒通配符（HTTP-01 不支持）。
func certRenewDomains(info CertInfo) ([]string, *CertError) {
	candidates := make([]string, 0, len(info.Domains)+1)
	candidates = append(candidates, info.Domain)
	for _, domain := range info.Domains {
		if domain == "" || domain == info.Domain {
			continue
		}
		candidates = append(candidates, domain)
	}
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, domain := range candidates {
		if strings.HasPrefix(domain, "*.") {
			return nil, newCertHintError(codeUnsupported,
				"通配符证书不能用 HTTP-01 自动续期（需 DNS-01，本客户端未实现）",
				"为这张证书手工导入新证书，或改用具体域名再开启自动续期")
		}
		if net.ParseIP(domain) != nil {
			continue
		}
		if _, dup := seen[domain]; dup {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	if len(out) == 0 {
		return nil, invalidParam("证书里没有可续期的 DNS 域名")
	}
	return out, nil
}

// verifyACMEIssued 验证新证书可用：密钥匹配、域名覆盖、链完整性、本地 TLS 握手。
// 只有全部通过才允许覆盖旧证书（失败即保留旧证书）。
func verifyACMEIssued(certPEM, keyPEM []byte, domains []string, now time.Time) (*x509.Certificate, int, *CertError) {
	_, _, certs, err := splitCertChain(certPEM)
	if err != nil {
		return nil, 0, newCertHintError(codeUpstream,
			"CA 返回的证书无法解析: "+err.Error(),
			"重试一次；持续失败换一个 CA（或用 letsencrypt-staging 验证链路）")
	}
	leaf := certs[0]
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore.Add(-5*time.Minute)) {
		return nil, 0, newCertHintError(codeUpstream,
			"CA 返回的证书有效期异常（not_before/not_after 与当前时间不匹配）",
			"确认本机时钟正确（NTP）；时钟偏差会导致 CA 校验失败")
	}
	for _, domain := range domains {
		if !certCoversDomain(leaf, domain) {
			return nil, 0, newCertHintError(codeUpstream,
				"CA 签出的证书不含域名 "+domain,
				"确认订单里的域名与 CSR 一致；这通常意味着 CA 侧标识符被改写，换 CA 重试")
		}
	}
	// 链完整性：逐级签名关联，最后一张必须是 CA（不依赖系统根证书库，测试 CA 也可验证）。
	for index := 0; index < len(certs)-1; index++ {
		if err := certs[index].CheckSignatureFrom(certs[index+1]); err != nil {
			return nil, 0, newCertHintError(codeUpstream,
				"证书链签名关联不成立（第 "+fmt.Sprint(index+1)+" 级）: "+err.Error(),
				"该 CA 返回的链不完整或不匹配：换一个 CA，或确认中间链没有被截断")
		}
	}
	if len(certs) > 1 && !certs[len(certs)-1].IsCA {
		return nil, 0, newCertHintError(codeUpstream,
			"证书链最后一张不是 CA 证书，链不完整",
			"该 CA 返回的链不完整：换一个 CA，或手工补链后再用 ssl.import 导入")
	}
	pair, pairErr := tls.X509KeyPair(certPEM, keyPEM)
	if pairErr != nil {
		return nil, 0, newCertHintError(codeUpstream,
			"新证书与私钥不匹配: "+pairErr.Error(),
			"这是签发异常：重试；连续出现请换 CA 并保留审计证据")
	}
	pair.Leaf = leaf
	if err := tlsSelfCheck(pair, leaf); err != nil {
		return nil, 0, newCertHintError(codeUpstream,
			"新证书本地 TLS 握手自检失败: "+err.Error(),
			"重试；连续失败说明签出的证书不可用于 TLS，请换 CA 或核对密钥算法")
	}
	return leaf, len(certs), nil
}

// tlsSelfCheck 用新证书起一个回环 TLS 服务并完成一次真实握手：
// 这是"证书能用于 TLS"的最直接验证，不依赖站点是否已 reload。
func tlsSelfCheck(pair tls.Certificate, leaf *x509.Certificate) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("起本地 TLS 监听失败: %w", err)
	}
	defer func() { _ = listener.Close() }()
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
		serverErr <- tlsConn.Handshake()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), acmeTLSProbeBudget)
	defer cancel()
	dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	conn, dialErr := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if dialErr != nil {
		_ = listener.Close()
		select {
		case <-serverErr:
		case <-time.After(time.Second):
		}
		return fmt.Errorf("本地 TLS 握手失败: %w", dialErr)
	}
	state := conn.(*tls.Conn).ConnectionState()
	_ = conn.Close()
	select {
	case handshakeErr := <-serverErr:
		if handshakeErr != nil {
			return fmt.Errorf("本地 TLS 握手失败: %w", handshakeErr)
		}
	case <-time.After(acmeTLSProbeBudget):
		return errors.New("本地 TLS 握手超时")
	}
	if len(state.PeerCertificates) == 0 {
		return errors.New("本地 TLS 握手未取到对端证书")
	}
	if fingerprint(state.PeerCertificates[0]) != fingerprint(leaf) {
		return errors.New("本地 TLS 握手拿到的不是新证书")
	}
	return nil
}

// splitCertChain 把 fullchain 拆成"叶子 PEM + 中间链 PEM + 解析后的证书列表"。
func splitCertChain(raw []byte) (leafPEM, chainPEM []byte, certs []*x509.Certificate, err error) {
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, nil, nil, parseErr
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
		if len(certs) == 0 {
			leafPEM = encoded
		} else {
			chainPEM = append(chainPEM, encoded...)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, nil, errors.New("证书链里没有 CERTIFICATE 块")
	}
	return leafPEM, chainPEM, certs, nil
}

// acmeErrorToCertError 把协议层错误映射成插件错误码，保留可操作 hint。
func acmeErrorToCertError(err error) *CertError {
	var acmeErr *acmeproto.Error
	if !errors.As(err, &acmeErr) {
		return internalErr("ACME 请求失败: " + err.Error())
	}
	code := codeUpstream
	switch acmeErr.Kind {
	case acmeproto.KindInvalid, acmeproto.KindAuth:
		code = codeInvalid
	case acmeproto.KindRateLimit:
		code = codeRatelimit
	case acmeproto.KindUnsupported:
		code = codeUnsupported
	}
	message := acmeErr.Detail
	if message == "" {
		message = "ACME 请求失败"
	}
	hint := acmeErr.Hint
	if hint == "" {
		hint = "查看 <证书目录>/acme/audit.jsonl 的最近记录"
	}
	return newCertHintError(code, "ACME："+message, hint)
}
