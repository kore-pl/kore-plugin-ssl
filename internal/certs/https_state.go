package certs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 强制 HTTPS 的**期望状态登记**（0.6.0）。
//
// 选 (b)「只登记期望状态 + 返回 apply_hint」，不写 nginx 配置，理由（详见 CHANGELOG）：
//   - 写 drop-in 片段需要新增 root_action 形状，而形状表在 kore 的 pkg/pluginapi（ADR-0022），
//     改内核超出本任务写域（kore-plugin-ssl）；
//   - 站点配置（server 块 / reload）的唯一归属方是 site 插件（G-13）：本仓另写一份独立片段
//     再自行 reload，会与 site 的站点状态脱节（site 认为 force_https=false，下次 apply 覆盖），
//     两个写入方各管一半配置正是 0.4.0 已否决的路；
//   - 登记期望状态后，实际下发走 site.bindSSL 的 force_https（默认 true），由内核正常
//     鉴权路径执行；本仓只做"记账 + 给出载荷 + 事后只读判定"。
//
// 落盘：<元数据目录>/https-state.json（0600，与 bindings.json 同级，可迁）。
const (
	// httpsStateFileName 是强制 HTTPS 期望状态文件名。
	httpsStateFileName = "https-state.json"
	// httpsStateSchema 是文件 schema 版本。
	httpsStateSchema = 1
)

// httpsStateEntry 是单域名的期望状态（source 恒为 plugin：这是本仓登记的）。
type httpsStateEntry struct {
	Domain    string `json:"domain"`
	Enforced  bool   `json:"enforced"`
	UpdatedAt string `json:"updated_at"`
}

// httpsStateFile 是落盘形状（显式字段，不用 map）。
type httpsStateFile struct {
	Schema  int               `json:"schema"`
	Entries []httpsStateEntry `json:"entries"`
}

// httpsEnforceResult 是 ssl.https.enforce 的结果：登记事实 + 站点侧载荷 + 事后判定入口。
type httpsEnforceResult struct {
	Domain    string      `json:"domain"`
	Enforced  bool        `json:"enforced"`
	Created   bool        `json:"created"`
	Changed   bool        `json:"changed"`
	Source    string      `json:"source"`
	UpdatedAt string      `json:"updated_at"`
	ApplyHint SiteAction  `json:"apply_hint"`
	Storage   StorageInfo `json:"storage"`
	Hint      string      `json:"hint"`
}

// httpsUnenforceResult 是 ssl.https.unenforce 的结果。
type httpsUnenforceResult struct {
	Domain    string      `json:"domain"`
	Enforced  bool        `json:"enforced"`
	Removed   bool        `json:"removed"`
	UpdatedAt string      `json:"updated_at"`
	ApplyHint SiteAction  `json:"apply_hint"`
	Storage   StorageInfo `json:"storage"`
	Hint      string      `json:"hint"`
}

// httpsStatePath 返回期望状态文件路径（元数据目录）。
func (s *certStore) httpsStatePath() string {
	return filepath.Join(s.metaDir, httpsStateFileName)
}

// loadHTTPSState 读取期望状态；不存在返回空集合。
func (s *certStore) loadHTTPSState() (httpsStateFile, error) {
	file := httpsStateFile{Schema: httpsStateSchema, Entries: []httpsStateEntry{}}
	raw, err := os.ReadFile(s.httpsStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return httpsStateFile{}, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return file, nil
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return httpsStateFile{}, err
	}
	if file.Entries == nil {
		file.Entries = []httpsStateEntry{}
	}
	if file.Schema == 0 {
		file.Schema = httpsStateSchema
	}
	return file, nil
}

// saveHTTPSState 原子写入期望状态（0600，路径必须在元数据目录内）。
func (s *certStore) saveHTTPSState(file httpsStateFile) error {
	if err := ensurePrivateDir(s.metaDir); err != nil {
		return err
	}
	path := s.httpsStatePath()
	if err := s.withinWritable(path); err != nil {
		return err
	}
	file.Schema = httpsStateSchema
	sort.SliceStable(file.Entries, func(i, j int) bool { return file.Entries[i].Domain < file.Entries[j].Domain })
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(raw, '\n'), keyFileMode)
}

// httpsEnforced 返回该域名的期望状态（未登记返回 false）。
func (s *Service) httpsEnforced(domain string) (bool, bool) {
	file, err := s.store.loadHTTPSState()
	if err != nil {
		return false, false
	}
	for _, entry := range file.Entries {
		if entry.Domain == domain {
			return entry.Enforced, true
		}
	}
	return false, false
}

// HTTPSEnforce 登记"该域名应强制 HTTPS"的期望状态（幂等，不写任何站点配置）。
//
// 校验：域名合法 + 本仓已有该域名的证书（没有证书时站点不可能有 443，先拒绝并提示绑证书）。
func (s *Service) HTTPSEnforce(domain string) (*httpsEnforceResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	host := strings.TrimSpace(domain)
	if perr := validateDomain(host); perr != nil {
		return nil, perr
	}
	now := nowOr(s.now)
	if _, _, err := s.store.findCert(host, now); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, newCertHintError(codeInvalid,
				"该域名还没有证书：没有证书的站点不可能有 443 server 块",
				"先到站点页用 site.bindSSL 绑定证书（或 ssl.selfsign / ssl.import），再开启强制 HTTPS")
		}
		return nil, internalErr("定位证书失败: " + err.Error())
	}
	s.bindMu.Lock()
	defer s.bindMu.Unlock()
	file, err := s.store.loadHTTPSState()
	if err != nil {
		return nil, internalErr("读取强制 HTTPS 期望状态失败: " + err.Error())
	}
	stamp := now.UTC().Format(time.RFC3339)
	created := true
	changed := false
	updated := make([]httpsStateEntry, 0, len(file.Entries)+1)
	for _, entry := range file.Entries {
		if entry.Domain == host {
			created = false
			if !entry.Enforced {
				changed = true
			}
			entry.Enforced = true
			entry.UpdatedAt = stamp
		}
		updated = append(updated, entry)
	}
	if created {
		changed = true
		updated = append(updated, httpsStateEntry{Domain: host, Enforced: true, UpdatedAt: stamp})
	}
	file.Entries = updated
	if err := s.store.saveHTTPSState(file); err != nil {
		return nil, internalErr("写入强制 HTTPS 期望状态失败: " + err.Error())
	}
	s.appendACMEAudit(acmeAuditEntry{Action: "https-enforce", Domain: host, Result: "ok"})
	certPath, info, _ := s.store.findCert(host, now)
	keyPath := s.store.certAbsPath(trimCertSuffix(filepath.Base(certPath)) + keySuffix)
	_ = info
	forceHTTPS := true
	result := &httpsEnforceResult{
		Domain: host, Enforced: true, Created: created, Changed: changed,
		Source: "plugin", UpdatedAt: stamp,
		ApplyHint: SiteAction{
			Plugin: sitePluginID, Method: siteBindSSLMethod,
			Params: SiteActionParams{Domain: host, CertPath: s.store.certAbsPath(filepath.Base(certPath)), KeyPath: keyPath, ForceHTTPS: &forceHTTPS},
			Note:   "本仓不写站点配置：把 apply_hint 原样交给站点页执行（site.bindSSL 的 force_https=true 才是真正的 80→443 跳转）",
		},
		Storage: s.storageInfo(),
		Hint:    "期望状态已登记；实际下发请在站点页应用 apply_hint，再用 ssl.https.status 复核（source 会从 plugin 变为 plugin 且 redirect_code=301/308）",
	}
	return result, nil
}

// HTTPSUnenforce 清除本仓登记的期望状态（只删自己的登记，不碰站点配置与其它域名）。
func (s *Service) HTTPSUnenforce(domain string) (*httpsUnenforceResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	host := strings.TrimSpace(domain)
	if perr := validateDomain(host); perr != nil {
		return nil, perr
	}
	s.bindMu.Lock()
	defer s.bindMu.Unlock()
	file, err := s.store.loadHTTPSState()
	if err != nil {
		return nil, internalErr("读取强制 HTTPS 期望状态失败: " + err.Error())
	}
	kept := make([]httpsStateEntry, 0, len(file.Entries))
	removed := false
	for _, entry := range file.Entries {
		if entry.Domain == host {
			removed = true
			continue
		}
		kept = append(kept, entry)
	}
	stamp := nowOr(s.now).UTC().Format(time.RFC3339)
	if removed {
		file.Entries = kept
		if err := s.store.saveHTTPSState(file); err != nil {
			return nil, internalErr("写入强制 HTTPS 期望状态失败: " + err.Error())
		}
		s.appendACMEAudit(acmeAuditEntry{Action: "https-unenforce", Domain: host, Result: "ok"})
	}
	forceHTTPS := false
	result := &httpsUnenforceResult{
		Domain: host, Enforced: false, Removed: removed, UpdatedAt: stamp,
		ApplyHint: SiteAction{
			Plugin: sitePluginID, Method: siteBindSSLMethod,
			Params: SiteActionParams{Domain: host, ForceHTTPS: &forceHTTPS},
			Note:   "关闭跳转同样归 site 插件：重新 site.bindSSL 时 force_https=false（或用 site.unsetRedirect 撤掉点路径规则）",
		},
		Storage: s.storageInfo(),
		Hint:    "只清除了本仓的期望状态；站点侧跳转仍需在站点页按 apply_hint 关闭",
	}
	if !removed {
		result.Hint = "本仓没有该域名的强制 HTTPS 登记（无需清理）；若站点仍有跳转，说明是手工配置的，请到站点页确认"
	}
	return result, nil
}
