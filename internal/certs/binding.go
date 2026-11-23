package certs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 站点归属登记（0.4.0）：本仓只登记「证书 → 站点域名」的归属关系，**不写任何 web
// 服务器配置**。
//
// 边界（G-13 仓库边界 + 插件能力边界）：
//   - 唯一负责把证书写进站点配置、监听 443、做 80→443 跳转的是 site 插件
//     （`site.bindSSL` / `site.unbindSSL` / `site.setRedirect`）；
//   - 本仓把「这张证书属于这个站点」记在自己的证书目录里，并给出 `site.bindSSL`
//     的推荐载荷（含证书 / 私钥绝对路径），由用户到站点页完成实际绑定；
//   - 协议层不存在插件间直连（PLUGIN-PROTOCOL §2：插件 A 不得连接插件 B 的 socket，
//     跨插件调用一律经内核 bus 转发），因此本仓既不 dial site 的 socket，
//     也不假装能替它写配置——被否决的「本仓直写站点配置」与「本仓直调 site」两条路
//     都写进 CHANGELOG 的边界决策。
const (
	// bindingsFileName 是归属登记文件名，落在证书目录内（目录 0700）。
	bindingsFileName = "bindings.json"
	// bindingsSchema 是登记文件的 schema 版本，便于后续兼容升级。
	bindingsSchema = 1
	// bindingsFileMode 是登记文件权限：只含域名与时间戳，仍按 0600 收紧。
	bindingsFileMode = 0o600
	// maxBindings 是登记条数上限，避免无界增长。
	maxBindings = 512
	// bindingNoteMaxLen 是备注长度上限。
	bindingNoteMaxLen = 200
)

// bindingRecord 是落盘形状：只存归属事实，不存派生路径（路径随证书目录变化）。
type bindingRecord struct {
	Cert      string `json:"cert"`
	Site      string `json:"site"`
	Note      string `json:"note,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// bindingFile 是 bindings.json 的完整形状（显式 schema，不用 map / any）。
type bindingFile struct {
	Schema   int             `json:"schema"`
	Bindings []bindingRecord `json:"bindings"`
}

// SiteBinding 是归属登记的单条视图：落盘字段 + 按当前证书目录派生的路径与存在性。
// CertExists=false 表示证书已不在目录里（陈旧归属），需要重新绑定或解除。
type SiteBinding struct {
	Cert       string `json:"cert"`
	Site       string `json:"site"`
	Note       string `json:"note,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	CertExists bool   `json:"cert_exists"`
}

// BindingsResult 是 ssl.bind.list 的结果。
type BindingsResult struct {
	Bindings []SiteBinding `json:"bindings"`
	Count    int           `json:"count"`
	Hint     string        `json:"hint"`
}

// BindingsRequest 是 ssl.bind.list 的入参（无字段，保留形状校验）。
type BindingsRequest struct{}

// BindingProbeRequest 是登记时附带的一次只读 HTTPS 判定参数。
// 只有显式给出 probe 才发起探测：登记本身不产生隐式出站（G-10）。
type BindingProbeRequest struct {
	HTTPPort  int `json:"http_port"`
	HTTPSPort int `json:"https_port"`
}

// SetBindingRequest 是 ssl.bind.set 的入参：cert 为本仓证书主域名，site 为站点域名。
type SetBindingRequest struct {
	Cert  string
	Site  string
	Note  string
	Probe *BindingProbeRequest
}

// RemoveBindingRequest 是 ssl.bind.remove 的入参：cert / site 至少给一个。
type RemoveBindingRequest struct {
	Cert string
	Site string
}

// SiteActionParams 是站点侧动作的入参形状（本仓只生成建议，不执行）。
type SiteActionParams struct {
	Domain     string `json:"domain"`
	CertPath   string `json:"cert_path,omitempty"`
	KeyPath    string `json:"key_path,omitempty"`
	ForceHTTPS *bool  `json:"force_https,omitempty"`
}

// SiteAction 是「站点侧要做的事」的建议载荷：plugin / method / params 与内核
// `POST /api/v1/invoke/{plugin}/{method}` 的形态一致，用户在站点页或前端发起。
type SiteAction struct {
	Plugin string           `json:"plugin"`
	Method string           `json:"method"`
	Params SiteActionParams `json:"params"`
	Note   string           `json:"note"`
}

// SetBindingResult 是 ssl.bind.set 的结果：登记事实 + 站点侧推荐动作 + 可选判定。
type SetBindingResult struct {
	Binding  SiteBinding        `json:"binding"`
	Created  bool               `json:"created"`
	SiteBind SiteAction         `json:"site_bind"`
	HTTPS    *HTTPSStatusResult `json:"https,omitempty"`
	Hint     string             `json:"hint"`
}

// RemoveBindingResult 是 ssl.bind.remove 的结果。
type RemoveBindingResult struct {
	Removed int         `json:"removed"`
	Binding SiteBinding `json:"binding"`
	Hint    string      `json:"hint"`
}

// 站点侧动作口径：实际写站点配置的是 site 插件，本仓只给载荷。
const (
	sitePluginID      = "site"
	siteBindSSLMethod = "site.bindSSL"
	bindingListHint   = "site.bindSSL 的 cert_path / key_path 直接取本条的这两个字段；实际绑定请在站点页操作"
)

// bindingsPath 返回登记文件路径（落在元数据目录：$KORE_PLUGIN_DATA/ssl 或旧证书目录）。
func (s *certStore) bindingsPath() string {
	return filepath.Join(s.metaDir, bindingsFileName)
}

// loadBindings 读取登记文件；文件不存在等价于空登记（首次绑定不报错）。
func (s *certStore) loadBindings() (bindingFile, error) {
	file := bindingFile{Schema: bindingsSchema, Bindings: []bindingRecord{}}
	path := s.bindingsPath()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return bindingFile{}, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return file, nil
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return bindingFile{}, err
	}
	if file.Bindings == nil {
		file.Bindings = []bindingRecord{}
	}
	if file.Schema == 0 {
		file.Schema = bindingsSchema
	}
	return file, nil
}

// saveBindings 原子写入登记文件：路径必须在证书目录内，权限 0600。
func (s *certStore) saveBindings(file bindingFile) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	path := s.bindingsPath()
	if err := s.withinWritable(path); err != nil {
		return err
	}
	file.Schema = bindingsSchema
	if file.Bindings == nil {
		file.Bindings = []bindingRecord{}
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(raw, '\n'), bindingsFileMode)
}

// SetBinding 登记「证书 → 站点」归属。
//
// 冲突口径（一对一）：一张证书只能属于一个站点；一个站点也只能挂一张证书。
// 同对重复登记是幂等的（Created=false，只刷新 note / updated_at）。
func (s *Service) SetBinding(req SetBindingRequest) (*SetBindingResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	cert, perr := normalizeBindingCert(req.Cert)
	if perr != nil {
		return nil, perr
	}
	site, perr := normalizeBindingSite(req.Site)
	if perr != nil {
		return nil, perr
	}
	note, perr := normalizeBindingNote(req.Note)
	if perr != nil {
		return nil, perr
	}
	now := nowOr(s.now)
	_, _, err := s.store.findCert(cert, now)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, newCertHintError(codeNotFound,
				"证书目录中没有 domain "+cert+" 的证书",
				"先用 ssl.selfsign 创建或 ssl.import 导入，再登记站点归属")
		}
		return nil, internalErr("定位证书失败: " + err.Error())
	}

	s.bindMu.Lock()
	defer s.bindMu.Unlock()
	file, err := s.store.loadBindings()
	if err != nil {
		return nil, internalErr("读取站点归属登记失败: " + err.Error())
	}
	for _, rec := range file.Bindings {
		if rec.Cert == cert && rec.Site != site {
			return nil, newCertHintError(codeConflict,
				"证书 "+cert+" 已归属站点 "+rec.Site+"（一张证书只能属于一个站点）",
				"先 ssl.bind.remove 解除旧归属，再登记新站点")
		}
		if rec.Site == site && rec.Cert != cert {
			return nil, newCertHintError(codeConflict,
				"站点 "+site+" 已绑定证书 "+rec.Cert+"（一个站点只能挂一张证书）",
				"先 ssl.bind.remove 解除旧归属，或直接给该站点换绑这张证书")
		}
	}

	created := true
	stamp := now.UTC().Format(time.RFC3339)
	updated := make([]bindingRecord, 0, len(file.Bindings)+1)
	for _, rec := range file.Bindings {
		if rec.Cert == cert && rec.Site == site {
			created = false
			rec.Note = note
			rec.UpdatedAt = stamp
			updated = append(updated, rec)
			continue
		}
		updated = append(updated, rec)
	}
	if created {
		if len(updated) >= maxBindings {
			return nil, newCertHintError(codeConflict,
				"站点归属登记已达上限 "+strconv.Itoa(maxBindings)+" 条",
				"先 ssl.bind.remove 清理不再使用的归属")
		}
		updated = append(updated, bindingRecord{
			Cert: cert, Site: site, Note: note, CreatedAt: stamp, UpdatedAt: stamp,
		})
	}
	sortBindings(updated)
	file.Bindings = updated
	if err := s.store.saveBindings(file); err != nil {
		return nil, internalErr("写入站点归属登记失败: " + err.Error())
	}

	binding := s.toSiteBinding(bindingRecord{Cert: cert, Site: site, Note: note, CreatedAt: stamp, UpdatedAt: stamp}, now)
	for _, rec := range updated {
		if rec.Cert == cert && rec.Site == site {
			binding = s.toSiteBinding(rec, now)
			break
		}
	}
	result := &SetBindingResult{
		Binding: binding,
		Created: created,
		SiteBind: SiteAction{
			Plugin: sitePluginID,
			Method: siteBindSSLMethod,
			Params: SiteActionParams{
				Domain: site, CertPath: binding.CertPath, KeyPath: binding.KeyPath, ForceHTTPS: boolPtr(true),
			},
			Note: "本仓不写 web 服务器配置：把 site_bind 原样交给站点页执行，实际绑定与跳转由 site 插件完成",
		},
		Hint: "归属已在 ssl 侧登记；实际绑定请在站点页用 site_bind 的载荷操作（force_https=true 同时开启 80→443 跳转）",
	}
	if req.Probe != nil {
		status, perr := s.HTTPSStatus(HTTPSStatusRequest{
			Domain: site, HTTPPort: req.Probe.HTTPPort, HTTPSPort: req.Probe.HTTPSPort,
		})
		if perr != nil {
			return nil, perr
		}
		result.HTTPS = status
	}
	return result, nil
}

// RemoveBinding 解除归属：cert / site 至少给一个，两者都给时必须命中同一条。
func (s *Service) RemoveBinding(req RemoveBindingRequest) (*RemoveBindingResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	cert := strings.TrimSpace(req.Cert)
	site := strings.TrimSpace(req.Site)
	if cert == "" && site == "" {
		return nil, invalidParam("cert 与 site 至少给一个")
	}
	if cert != "" {
		if perr := validateDomain(cert); perr != nil {
			return nil, perr
		}
	}
	if site != "" {
		if perr := validateDomain(site); perr != nil {
			return nil, perr
		}
	}

	s.bindMu.Lock()
	defer s.bindMu.Unlock()
	file, err := s.store.loadBindings()
	if err != nil {
		return nil, internalErr("读取站点归属登记失败: " + err.Error())
	}
	now := nowOr(s.now)
	kept := make([]bindingRecord, 0, len(file.Bindings))
	var matched *bindingRecord
	removed := 0
	for i := range file.Bindings {
		rec := file.Bindings[i]
		hit := (cert == "" || rec.Cert == cert) && (site == "" || rec.Site == site)
		if hit {
			removed++
			copied := rec
			matched = &copied
			continue
		}
		kept = append(kept, rec)
	}
	if removed == 0 {
		return nil, newCertHintError(codeNotFound,
			"没有匹配的站点归属登记",
			"用 ssl.bind.list 查看当前登记；cert / site 至少给一个且需与登记值一致")
	}
	file.Bindings = kept
	if err := s.store.saveBindings(file); err != nil {
		return nil, internalErr("写入站点归属登记失败: " + err.Error())
	}
	result := &RemoveBindingResult{
		Removed: removed,
		Hint:    "只解除了 ssl 侧的归属登记；站点侧的证书绑定请到站点页用 site.unbindSSL 解除",
	}
	if matched != nil {
		result.Binding = s.toSiteBinding(*matched, now)
	}
	return result, nil
}

// Bindings 返回全部归属登记（按 cert、site 排序，输出确定）。
// 不发起任何网络探测：HTTPS 判定是独立的只读方法 ssl.https.status。
func (s *Service) Bindings() (*BindingsResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	file, err := s.store.loadBindings()
	if err != nil {
		return nil, internalErr("读取站点归属登记失败: " + err.Error())
	}
	now := nowOr(s.now)
	sortBindings(file.Bindings)
	result := &BindingsResult{Bindings: make([]SiteBinding, 0, len(file.Bindings)), Hint: bindingListHint}
	for _, rec := range file.Bindings {
		result.Bindings = append(result.Bindings, s.toSiteBinding(rec, now))
	}
	result.Count = len(result.Bindings)
	return result, nil
}

// toSiteBinding 把落盘记录转成对外视图：补齐当前证书目录下的路径与存在性。
func (s *Service) toSiteBinding(rec bindingRecord, now time.Time) SiteBinding {
	binding := SiteBinding{
		Cert: rec.Cert, Site: rec.Site, Note: rec.Note,
		CreatedAt: rec.CreatedAt, UpdatedAt: rec.UpdatedAt,
	}
	path, _, err := s.store.findCert(rec.Cert, now)
	if err != nil {
		// 证书已不在目录：仍返回按命名规则推导的期望路径，供提示用户补回证书。
		binding.CertPath = s.store.certAbsPath(rec.Cert + certSuffix)
		binding.KeyPath = s.store.certAbsPath(rec.Cert + keySuffix)
		return binding
	}
	binding.CertExists = true
	binding.CertPath = s.store.certAbsPath(filepath.Base(path))
	base := trimCertSuffix(filepath.Base(path))
	binding.KeyPath = s.store.certAbsPath(base + keySuffix)
	return binding
}

// normalizeBindingCert 校验证书标识：与 ssl.list / ssl.renew 的 domain 同口径。
func normalizeBindingCert(raw string) (string, *CertError) {
	cert := strings.TrimSpace(raw)
	if perr := validateDomain(cert); perr != nil {
		return "", perr
	}
	return cert, nil
}

// normalizeBindingSite 校验站点域名：同一套域名白名单（拒绝路径与伪协议）。
func normalizeBindingSite(raw string) (string, *CertError) {
	site := strings.TrimSpace(raw)
	if perr := validateDomain(site); perr != nil {
		return "", perr
	}
	return site, nil
}

// normalizeBindingNote 校验备注：可选、去首尾空白、限长、拒绝控制字符。
func normalizeBindingNote(raw string) (string, *CertError) {
	note := strings.TrimSpace(raw)
	if note == "" {
		return "", nil
	}
	if len(note) > bindingNoteMaxLen {
		return "", invalidParam("note 超过 " + strconv.Itoa(bindingNoteMaxLen) + " 字符")
	}
	for _, r := range note {
		if r < 0x20 || r == 0x7f {
			return "", invalidParam("note 含控制字符")
		}
	}
	return note, nil
}

// sortBindings 按 cert、site 升序排序，保证登记文件与 list 输出确定。
func sortBindings(records []bindingRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Cert != records[j].Cert {
			return records[i].Cert < records[j].Cert
		}
		return records[i].Site < records[j].Site
	})
}

// boolPtr 返回 bool 指针（用于生成建议载荷里的 force_https）。
func boolPtr(v bool) *bool { return &v }
