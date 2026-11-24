package certs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	acmeproto "github.com/pengtang1024/kore-plugin-ssl/internal/acme"
)

// ACME 自动续期开关与只读状态（0.5.0）。
//
// 两侧分开是刻意的：
//   - ssl.acme.auto 是**写**方法（admin），改配置/开关，必须 confirm=true；
//   - ssl.acme.builtin.status 是**只读**方法（read），返回脱敏后的状态，绝不联网。
// 这样"看一眼现状"不会进管理审计，也不会因为误点就触发联网。

// ACMEBuiltinStatus 是 ssl.acme.builtin.status 的结果（脱敏：不含任何密钥）。
type ACMEBuiltinStatus struct {
	CertDir        string               `json:"cert_dir"`
	CertDirSource  string               `json:"cert_dir_source"`
	KernelStateDir string               `json:"kernel_state_dir,omitempty"`
	ACMEDir        string               `json:"acme_dir"`
	CA             string               `json:"ca"`
	DirectoryURL   string               `json:"directory_url"`
	Staging        bool                 `json:"staging"`
	Webroot        string               `json:"webroot,omitempty"`
	SitesRoot      string               `json:"sites_root,omitempty"`
	SitesRootHint  string               `json:"sites_root_hint,omitempty"`
	Email          string               `json:"email,omitempty"`
	KeyType        string               `json:"key_type"`
	EABConfigured  bool                 `json:"eab_configured"`
	AutoRenew      bool                 `json:"auto_renew"`
	DaysBefore     int                  `json:"days_before"`
	AccountExists  bool                 `json:"account_exists"`
	AccountKID     string               `json:"account_kid,omitempty"`
	Presets        []acmeproto.CAPreset `json:"presets"`
	Storage        StorageInfo          `json:"storage"`
	LastAudit      []acmeAuditEntry     `json:"last_audit"`
	LegacyDirSeen  bool                 `json:"legacy_dir_seen"`
	Hint           string               `json:"hint"`
}

// ACMEBuiltinStatus 返回内置 ACME 的配置与最近审计；只读、零网络。
func (s *Service) ACMEBuiltinStatus() (*ACMEBuiltinStatus, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	settings, perr := s.loadACMESettings()
	if perr != nil {
		return nil, perr
	}
	dir, source := ResolveCertDir()
	dirURL := ""
	if resolved, err := acmeproto.ResolveDirectoryURL(settings.CA, settings.DirectoryURL); err == nil {
		dirURL = resolved
	}
	out := &ACMEBuiltinStatus{
		CertDir:        dir,
		CertDirSource:  string(source),
		KernelStateDir: stateDir(),
		ACMEDir:        filepath.Join(dir, acmeDirName),
		CA:             settings.CA,
		DirectoryURL:   dirURL,
		Staging:        settings.CA == acmeproto.CAStaging,
		Webroot:        settings.Webroot,
		SitesRoot:      s.resolveSitesRoot(settings),
		SitesRootHint:  s.issueSitesRootHint(settings),
		Email:          settings.Email,
		KeyType:        acmeKeyTypeOrDefault(settings.KeyType),
		EABConfigured:  settings.EABKid != "" && settings.EABHMACKey != "",
		AutoRenew:      settings.AutoRenew,
		DaysBefore:     settings.DaysBefore,
		Presets:        acmeproto.Presets(),
		Storage:        s.storageInfo(),
		LastAudit:      s.acmeAuditTail(acmeAuditTailMax),
		LegacyDirSeen:  legacyCertDirHasCerts(),
	}
	caID := sanitizeCAID(settings.CA)
	if acct, ok := s.loadACMEAccount(caID); ok && acct.Directory == dirURL {
		out.AccountExists = true
		out.AccountKID = acct.KID
	}
	switch {
	case dirURL == "":
		out.Hint = "ACME 配置有问题：ca=" + settings.CA + " 无法解析出 directory_url，用 ssl.acme.auto 配置 ca/directory_url"
	case settings.CA == acmeproto.CALiteSSL && !out.EABConfigured:
		out.Hint = "LiteSSL 强制 EAB：到 FreeSSL「证书自动化 → ACME 账户管理」创建账号，把 eab_kid/eab_hmac_key 用 ssl.acme.auto 写入"
	case !out.AutoRenew:
		out.Hint = "自动续期默认关闭：用 ssl.acme.auto {enabled:true, confirm:true} 开启后内核 scheduler 才会每天检查（当前目录 " + dir + "）"
	case out.Staging:
		out.Hint = "当前是 Let's Encrypt staging（浏览器不信任）：验证域名可达后把 ca 换成 letsencrypt 或 litessl"
	default:
		out.Hint = "自动续期已开启；续期结果见 last_audit 与 <证书目录>/acme/audit.jsonl"
	}
	return out, nil
}

// ACMEAutoTaskParams 是自动续期任务传给 ssl.acme.builtin.renew 的参数。
type ACMEAutoTaskParams struct {
	DaysBefore int `json:"days_before,omitempty"`
}

// ACMEAutoTask 是"待创建的内核任务"描述（字段与 scheduler.CreateInput 对齐）。
type ACMEAutoTask struct {
	Name     string             `json:"name"`
	Plugin   string             `json:"plugin"`
	Method   string             `json:"method"`
	Params   ACMEAutoTaskParams `json:"params"`
	Schedule string             `json:"schedule"`
}

// ACMEAutoRequest 是 ssl.acme.auto 的入参：改配置 / 开关自动续期，必须 confirm=true。
type ACMEAutoRequest struct {
	Enabled      *bool
	DaysBefore   int
	CA           string
	DirectoryURL string
	Webroot      string
	SitesRoot    string
	Email        string
	KeyType      string
	EABKid       string
	EABHMACKey   string
	ClearEAB     bool
	Confirm      bool
}

// ACMEAutoResult 是 ssl.acme.auto 的结果（脱敏：不回显 hmac key）。
type ACMEAutoResult struct {
	CA            string       `json:"ca"`
	DirectoryURL  string       `json:"directory_url"`
	Webroot       string       `json:"webroot,omitempty"`
	SitesRoot     string       `json:"sites_root,omitempty"`
	Email         string       `json:"email,omitempty"`
	KeyType       string       `json:"key_type"`
	EABConfigured bool         `json:"eab_configured"`
	AutoRenew     bool         `json:"auto_renew"`
	DaysBefore    int          `json:"days_before"`
	UpdatedAt     string       `json:"updated_at"`
	NextRunAt     string       `json:"next_run_at"`
	Task          ACMEAutoTask `json:"task"`
	Warning       string       `json:"warning,omitempty"`
	Hint          string       `json:"hint"`
}

// ACMEAuto 修改 ACME 配置与自动续期开关；开启自动续期必须显式 confirm。
func (s *Service) ACMEAuto(req ACMEAutoRequest) (*ACMEAutoResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	if !req.Confirm {
		return nil, newCertHintError(codeInvalid,
			"修改 ACME 配置（尤其开启自动续期）会允许后台联网，必须显式确认",
			"带 confirm=true 重新调用；当前状态可用 ssl.acme.builtin.status 查看（只读、不联网）")
	}
	settings, perr := s.loadACMESettings()
	if perr != nil {
		return nil, perr
	}
	wasEnabled := settings.AutoRenew
	if ca := strings.TrimSpace(req.CA); ca != "" {
		settings.CA = ca
	}
	if dir := strings.TrimSpace(req.DirectoryURL); dir != "" {
		settings.DirectoryURL = dir
	}
	if sitesRoot := strings.TrimSpace(req.SitesRoot); sitesRoot != "" {
		if !filepath.IsAbs(sitesRoot) {
			return nil, invalidParam("sites_root 必须是绝对路径（站点根父目录）")
		}
		sitesRoot = filepath.Clean(sitesRoot)
		if err := os.MkdirAll(sitesRoot, 0o755); err != nil {
			return nil, newCertHintError(codeInternal,
				"创建 sites_root 失败: "+err.Error(),
				"确认该目录可写（需在安装目录内，G-31 零侵入）")
		}
		settings.SitesRoot = sitesRoot
	}
	if webroot := strings.TrimSpace(req.Webroot); webroot != "" {
		if !filepath.IsAbs(webroot) {
			return nil, invalidParam("webroot 必须是绝对路径（站点根目录）")
		}
		if err := acmeproto.EnsureWebroot(webroot); err != nil {
			return nil, acmeErrorToCertError(err)
		}
		settings.Webroot = webroot
	}
	if email := strings.TrimSpace(req.Email); email != "" {
		if !acmeEmailRE.MatchString(email) {
			return nil, invalidParam("email 格式非法（CA 用它联系证书责任人，可选但建议填）")
		}
		settings.Email = email
	}
	if keyType := strings.TrimSpace(req.KeyType); keyType != "" {
		if keyType != acmeproto.KeyTypeECDSA256 && keyType != acmeproto.KeyTypeRSA2048 {
			return nil, invalidParam("key_type 只支持 ecdsa256 / rsa2048")
		}
		settings.KeyType = keyType
	}
	if req.ClearEAB {
		settings.EABKid, settings.EABHMACKey = "", ""
	}
	if kid := strings.TrimSpace(req.EABKid); kid != "" {
		settings.EABKid = kid
	}
	if hmac := strings.TrimSpace(req.EABHMACKey); hmac != "" {
		settings.EABHMACKey = hmac
	}
	if (settings.EABKid == "") != (settings.EABHMACKey == "") {
		return nil, newCertHintError(codeInvalid,
			"EAB 配置不完整：eab_kid 与 eab_hmac_key 必须同时提供",
			"从 CA 控制台复制同一对凭据；要清空用 clear_eab=true")
	}
	if req.DaysBefore != 0 {
		if req.DaysBefore < 1 || req.DaysBefore > daysMax {
			return nil, invalidParam(fmt.Sprintf("days_before 必须在 1..%d", daysMax))
		}
		settings.DaysBefore = req.DaysBefore
	}
	if req.Enabled != nil {
		settings.AutoRenew = *req.Enabled
	}
	dirURL, err := acmeproto.ResolveDirectoryURL(settings.CA, settings.DirectoryURL)
	if err != nil {
		return nil, acmeErrorToCertError(err)
	}
	// 开启时做完整性校验：没有 webroot 或 CA 要求 EAB 但没配，宁可现在拦住。
	if settings.AutoRenew {
		if strings.TrimSpace(settings.Webroot) == "" {
			return nil, newCertHintError(codeInvalid,
				"开启自动续期前必须先配置 webroot（HTTP-01 校验文件要写进站点根）",
				"用 ssl.acme.auto {webroot:\"/install/data/sites/<域名>\", confirm:true} 配置后再开启")
		}
		if preset, ok := acmeproto.Preset(settings.CA); ok && preset.RequiresEAB && (settings.EABKid == "" || settings.EABHMACKey == "") {
			return nil, newCertHintError(codeInvalid,
				settings.CA+" 强制 EAB：没有 EAB 凭据无法签发，开启自动续期也会全部失败",
				"这是 EAB 凭据缺失：到 FreeSSL 控制台创建 ACME 账号，填入 eab_kid 与 eab_hmac_key 后再开启")
		}
	}
	if perr := s.saveACMESettings(settings); perr != nil {
		return nil, perr
	}
	action := "config"
	switch {
	case settings.AutoRenew && !wasEnabled:
		action = "auto-enable"
	case !settings.AutoRenew && wasEnabled:
		action = "auto-disable"
	}
	s.appendACMEAudit(acmeAuditEntry{
		Action: action, CA: settings.CA, Directory: dirURL,
		Result: "ok",
	})
	out := &ACMEAutoResult{
		CA: settings.CA, DirectoryURL: dirURL,
		Webroot: settings.Webroot, SitesRoot: s.resolveSitesRoot(settings), Email: settings.Email,
		KeyType:       acmeKeyTypeOrDefault(settings.KeyType),
		EABConfigured: settings.EABKid != "" && settings.EABHMACKey != "",
		AutoRenew:     settings.AutoRenew, DaysBefore: settings.DaysBefore,
		UpdatedAt: settings.UpdatedAt,
		NextRunAt: nextDailyRun(nowOr(s.now), acmeAutoTaskHour).UTC().Format("2006-01-02T15:04:05Z"),
		Task: ACMEAutoTask{
			Name: acmeAutoTaskPrefix, Plugin: RenewTaskPlugin,
			Method:   "ssl.acme.builtin.renew",
			Params:   ACMEAutoTaskParams{DaysBefore: settings.DaysBefore},
			Schedule: acmeAutoTaskSchedule,
		},
	}
	switch {
	case settings.AutoRenew && !wasEnabled:
		out.Warning = "自动续期已开启：内核 scheduler 每天 03:00 会调用一次 ssl.acme.builtin.renew，届时会联网到 " + dirURL +
			"（到期前 " + fmt.Sprint(settings.DaysBefore) + " 天内才真正续期）。关闭请 enabled=false。"
		out.Hint = "把 task 原样 POST 到 /api/v1/scheduler/tasks 才会真正定时执行；插件不自己起 ticker（G-19）"
	case !settings.AutoRenew && wasEnabled:
		out.Hint = "自动续期已关闭：scheduler 到点调用 ssl.acme.builtin.renew 会返回 E_UNSUPPORTED，且不会发起任何网络请求"
	default:
		out.Hint = "配置已保存；" + ternary(settings.AutoRenew, "自动续期处于开启状态", "自动续期仍关闭")
	}
	return out, nil
}

// ternary 是字符串三元（保持表达式简洁）。
func ternary(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
