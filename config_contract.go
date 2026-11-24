package main

// config_contract.go 实现统一配置面板契约（kore docs/PLUGIN-CONFIG.md）：
// ssl.config.get / ssl.config.set。字段全部锚定本仓真实能力——证书目录与
// acme/settings.json 里的 ACME 配置，不臆造不存在的开关。
//
// 存储分层：
//   - <KORE_STATE_DIR>/config.json 是契约真相文件（面板值、0600 原子写）。
//   - ACME 字段在 config.set 时同步桥接进 <meta>/acme/settings.json，让业务
//     下一次签发/续期读盘即生效（真热生效，不是只改面板显示值）。
//   - cert_dir 变更需要重建 Service（新目录/新白名单），标 restart_required=true。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	acmeproto "github.com/pengtang1024/kore-plugin-ssl/internal/acme"
	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore-plugin-ssl/internal/plugincfg"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 环境变量覆盖（文件不存在时才生效；优先级 config.json > env > default，§4）。
const (
	EnvCertDir       = "KORE_SSL_CERT_DIR"
	EnvACMECA        = "KORE_SSL_ACME_CA"
	EnvACMEDays      = "KORE_SSL_ACME_DAYS_BEFORE"
	EnvACMEAutoRenew = "KORE_SSL_ACME_AUTO_RENEW"
)

// configState 是所有 config 值拷贝共享的可变状态。dispatch/serve 收 config 值，
// 若把字段直接放 config 上，config.set 的更新在下一次 dispatch 会丢——用指针
// 承载即可让"保存后下一次业务调用即生效"（§10）成立。
type configState struct {
	mu     sync.RWMutex
	store  *plugincfg.Store
	values cfgValues
	source string
}

// cfgValues 是 config.json 的显式落盘形状（G-24：不用 object/any）。
// ACME 字段与 acme/settings.json 一一对应；cert_dir 覆盖证书目录。
type cfgValues struct {
	CertDir          string `json:"cert_dir"`
	ACMECA           string `json:"acme_ca"`
	ACMEDirectoryURL string `json:"acme_directory_url"`
	ACMEWebroot      string `json:"acme_webroot"`
	ACMESitesRoot    string `json:"acme_sites_root"`
	ACMEEmail        string `json:"acme_email"`
	ACMEKeyType      string `json:"acme_key_type"`
	ACMEEABKid       string `json:"acme_eab_kid"`
	ACMEEABHMACKey   string `json:"acme_eab_hmac_key"`
	ClearEAB         bool   `json:"clear_eab,omitempty"`
	ACMEAutoRenew    bool   `json:"acme_auto_renew"`
	ACMEDaysBefore   int    `json:"acme_days_before"`
}

// defaultCfgValues 是代码默认值，锚定本仓 acme/settings.json 出厂默认：
// staging CA + 30 天提前量 + 自动续期关闭（G-10）；证书目录留空表示沿用
// certs.ResolveCertDir 的契约解析（<install>/data/ssl）。
func defaultCfgValues() cfgValues {
	return cfgValues{
		ACMECA:         acmeproto.CAStaging,
		ACMEKeyType:    acmeproto.KeyTypeECDSA256,
		ACMEDaysBefore: 30,
	}
}

// configSchema 返回 config.get 的表单描述（PLUGIN-CONFIG §2）。
// 字段类型显式枚举，中文 label/help/default/required，禁 object/any（G-24）。
// EAB HMAC 密钥与账户密钥标 sensitive（G-30）。
func configSchema() plugincfg.Schema {
	d := defaultCfgValues()
	intPtr := func(v int) *int { return &v }
	return plugincfg.Schema{
		Title: "SSL 证书与 ACME 配置",
		Fields: []plugincfg.Field{
			{
				Key: "cert_dir", Label: "证书目录", Type: plugincfg.TypeString,
				Default: mustJSON(d.CertDir), Required: false,
				Help: "证书与私钥的落盘目录，必须是绝对路径；留空则沿用安装目录 data/ssl。修改后需重启 kored 生效。",
			},
			{
				Key: "acme_ca", Label: "默认 ACME 供应商", Type: plugincfg.TypeSelect,
				Default: mustJSON(d.ACMECA), Required: true,
				Help:    "签发证书使用的 ACME CA；staging 不占生产配额、证书浏览器不信任，验证通过后再切生产。",
				Options: []string{acmeproto.CAStaging, acmeproto.CA, acmeproto.CALiteSSL, acmeproto.CACustom},
			},
			{
				Key: "acme_days_before", Label: "续期提前天数", Type: plugincfg.TypeInt,
				Default: mustJSON(d.ACMEDaysBefore), Required: true,
				Help: "证书剩余天数不超过该值时才真正续期，范围 1–3650。",
				Min:  intPtr(1), Max: intPtr(3650),
			},
			{
				Key: "acme_auto_renew", Label: "自动续期", Type: plugincfg.TypeBool,
				Default: mustJSON(d.ACMEAutoRenew), Required: false,
				Help: "开启后内核 scheduler 每天检查续期；必须同时配置 webroot，LiteSSL 还必须有 EAB 凭据。",
			},
			{
				Key: "acme_webroot", Label: "webroot 根目录", Type: plugincfg.TypeString,
				Default: mustJSON(d.ACMEWebroot), Required: false,
				Help: "HTTP-01 校验文件写入的站点根目录，必须是绝对路径；开启自动续期前必填。",
			},
			{
				Key: "acme_sites_root", Label: "站点根父目录", Type: plugincfg.TypeString,
				Default: mustJSON(d.ACMESitesRoot), Required: false,
				Help: "自动推断站点 webroot 的父目录，必须是绝对路径；留空则用默认约定。",
			},
			{
				Key: "acme_email", Label: "ACME 联系邮箱", Type: plugincfg.TypeString,
				Default: mustJSON(d.ACMEEmail), Required: false,
				Help: "CA 用于联系证书责任人，可选但建议填写；留空表示不修改已有值。",
			},
			{
				Key: "acme_key_type", Label: "账户密钥类型", Type: plugincfg.TypeSelect,
				Default: mustJSON(d.ACMEKeyType), Required: true,
				Help:    "ACME 账户与证书密钥算法：ecdsa256（默认）或 rsa2048。",
				Options: []string{acmeproto.KeyTypeECDSA256, acmeproto.KeyTypeRSA2048},
			},
			{
				Key: "acme_directory_url", Label: "自定义 CA 目录地址", Type: plugincfg.TypeString,
				Default: mustJSON(d.ACMEDirectoryURL), Required: false,
				Help: "仅当供应商选 custom 时必填，必须是 https:// 开头的 RFC 8555 directory URL。",
			},
			{
				Key: "acme_eab_kid", Label: "EAB 账户 ID", Type: plugincfg.TypeString,
				Default: mustJSON(d.ACMEEABKid), Required: false,
				Help:      "CA 签发的 External Account Binding 账户 ID；必须与 EAB 密钥成对填写，config.get 只回掩码。",
				Sensitive: true,
			},
			{
				Key: "acme_eab_hmac_key", Label: "EAB 密钥", Type: plugincfg.TypeString,
				Default: mustJSON(d.ACMEEABHMACKey), Required: false,
				Help:      "EAB HMAC 密钥（敏感），只存本机 0600 文件；config.get 不回明文，填 *** 表示不修改。",
				Sensitive: true,
			},
		},
	}
}

// initConfigState 在 loadConfig 之后调用：构造共享状态、按优先级解析初值。
// 配置损坏时返回明确错误，不静默回退默认（§3）。
func initConfigState(stateDir string) (*configState, error) {
	store := plugincfg.NewStore(stateDir)
	values, source, err := resolveCfgValues(store)
	if err != nil {
		return nil, err
	}
	return &configState{store: store, values: values, source: source}, nil
}

// resolveCfgValues 实现优先级 config.json > 环境变量 > 代码默认值（§4）。
func resolveCfgValues(store *plugincfg.Store) (cfgValues, string, error) {
	if store.Exists() {
		raw, _, err := store.Read()
		if err != nil {
			return cfgValues{}, "", err
		}
		var values cfgValues
		if err := json.Unmarshal(raw, &values); err != nil {
			return cfgValues{}, "", fmt.Errorf("解析插件配置 %s: %w", store.Path(), err)
		}
		normalized := fillCfgDefaults(values)
		return normalized, plugincfg.SourceFile, nil
	}
	values := defaultCfgValues()
	source := plugincfg.SourceDefault
	if certDir := strings.TrimSpace(os.Getenv(EnvCertDir)); certDir != "" {
		values.CertDir = certDir
		source = plugincfg.SourceEnv
	}
	if ca := strings.TrimSpace(os.Getenv(EnvACMECA)); ca != "" {
		values.ACMECA = ca
		source = plugincfg.SourceEnv
	}
	if raw := strings.TrimSpace(os.Getenv(EnvACMEDays)); raw != "" {
		var days int
		if _, err := fmt.Sscanf(raw, "%d", &days); err != nil || days <= 0 {
			return cfgValues{}, "", fmt.Errorf("%s=%q 非法：必须是正整数天数", EnvACMEDays, raw)
		}
		values.ACMEDaysBefore = days
		source = plugincfg.SourceEnv
	}
	if raw := strings.TrimSpace(os.Getenv(EnvACMEAutoRenew)); raw == "true" || raw == "1" {
		values.ACMEAutoRenew = true
		source = plugincfg.SourceEnv
	}
	return values, source, nil
}

// fillCfgDefaults 把零值字段补成默认（config.json 允许只写关心字段）。
func fillCfgDefaults(v cfgValues) cfgValues {
	d := defaultCfgValues()
	if v.ACMECA == "" {
		v.ACMECA = d.ACMECA
	}
	if v.ACMEKeyType == "" {
		v.ACMEKeyType = d.ACMEKeyType
	}
	if v.ACMEDaysBefore == 0 {
		v.ACMEDaysBefore = d.ACMEDaysBefore
	}
	return v
}

// validateCfgValues 对面板值做全量校验（不校验 ACME 语义，那层交给
// Service.ApplyACMEConfig，与 ssl.acme.auto 同源）。
func validateCfgValues(v cfgValues) *pluginapi.Error {
	if v.CertDir != "" {
		if !filepath.IsAbs(v.CertDir) {
			return invalidConfig("cert_dir 必须是绝对路径")
		}
	}
	switch v.ACMECA {
	case acmeproto.CAStaging, acmeproto.CA, acmeproto.CALiteSSL, acmeproto.CACustom:
	default:
		return invalidConfig("acme_ca 只支持 letsencrypt-staging / letsencrypt / litessl / custom")
	}
	if v.ACMEKeyType != acmeproto.KeyTypeECDSA256 && v.ACMEKeyType != acmeproto.KeyTypeRSA2048 {
		return invalidConfig("acme_key_type 只支持 ecdsa256 / rsa2048")
	}
	if v.ACMEDaysBefore < 1 || v.ACMEDaysBefore > 3650 {
		return invalidConfig("acme_days_before 必须在 1..3650")
	}
	for _, field := range []struct{ name, value string }{
		{"acme_webroot", v.ACMEWebroot},
		{"acme_sites_root", v.ACMESitesRoot},
	} {
		if field.value != "" && !filepath.IsAbs(field.value) {
			return invalidConfig(field.name + " 必须是绝对路径")
		}
	}
	if v.ACMEDirectoryURL != "" && !strings.HasPrefix(v.ACMEDirectoryURL, "https://") {
		return invalidConfig("acme_directory_url 必须是 https:// 开头的 URL")
	}
	if (v.ACMEEABKid == "") != (v.ACMEEABHMACKey == "") {
		return invalidConfig("acme_eab_kid 与 acme_eab_hmac_key 必须同时提供；要清空用 clear_eab=true")
	}
	return nil
}

// configGet 组装 config.get 结果：schema + 当前值（sensitive 掩码）+ 来源。
// config.json 是契约 §3 的唯一真相；acme/settings.json 只是 config.set 时同步
// 落盘的业务生效副本。只读 config.json 内存镜像，避免两处文件互相覆盖导致
// 面板值漂移（重载后值与设置不一致）。
func configGet(cfg config, svc *certs.Service) (json.RawMessage, *pluginapi.Error) {
	_ = svc // 保留签名以便未来核对业务生效状态；当前值以 config.json 为准。
	state := cfg.state
	if state == nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "配置状态未初始化"}
	}
	state.mu.RLock()
	values := state.values
	source := state.source
	state.mu.RUnlock()

	raw, err := json.Marshal(values)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化当前配置失败: " + err.Error()}
	}
	// §6：有值时 sensitive 回 "***"，无值时回空串（MaskValues 会对存在的键一律
	// 回 "***"，所以先把空串敏感字段从 JSON 中剔除再掩码）。
	masked, err := maskSensitiveValues(configSchema(), raw)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "掩码敏感字段失败: " + err.Error()}
	}
	encoded, err := json.Marshal(plugincfg.GetResult{Schema: configSchema(), Values: masked, Source: source})
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化 config.get 结果失败: " + err.Error()}
	}
	return encoded, nil
}

// maskSensitiveValues 按 schema 掩码 sensitive 字段：空串保留空串（未配置），
// 非空值替换为 SensitivePlaceholder。返回合法 JSON 对象。
func maskSensitiveValues(schema plugincfg.Schema, values json.RawMessage) (json.RawMessage, error) {
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(values, &decoded); err != nil {
		return nil, err
	}
	for _, field := range schema.Fields {
		if !field.Sensitive {
			continue
		}
		raw, ok := decoded[field.Key]
		if !ok {
			continue
		}
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			continue
		}
		if text == "" || text == plugincfg.SensitivePlaceholder {
			decoded[field.Key] = json.RawMessage(`""`)
		} else {
			decoded[field.Key] = json.RawMessage(`"` + plugincfg.SensitivePlaceholder + `"`)
		}
	}
	return json.Marshal(decoded)
}

// configSetParams 是 config.set 的入参形状。
type configSetParams struct {
	Values json.RawMessage `json:"values"`
}

// configSet 按「校验 → ACME 桥接写 → 原子写 config.json → 更新内存 → 返回」
// 顺序保存（§3）。ACME 字段写回 settings.json 后下一次签发即生效；cert_dir
// 变更需重建 Service，标 restart_required=true。
func configSet(raw json.RawMessage, cfg config, svc *certs.Service) (json.RawMessage, *pluginapi.Error) {
	state := cfg.state
	if state == nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "配置状态未初始化"}
	}
	var params configSetParams
	if len(raw) == 0 || string(raw) == "null" || raw[0] != '{' {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "params 必须是含 values 的 JSON 对象"}
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "params 解析失败: " + err.Error()}
	}
	if len(params.Values) == 0 || string(params.Values) == "null" || params.Values[0] != '{' {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "values 必须是 JSON 对象"}
	}

	state.mu.RLock()
	base := state.values
	state.mu.RUnlock()

	var incoming cfgValues
	if err := json.Unmarshal(params.Values, &incoming); err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "values 解析失败: " + err.Error()}
	}
	candidate := mergeCfgValues(base, incoming, params.Values)
	if perr := validateCfgValues(candidate); perr != nil {
		return nil, perr
	}
	// sensitive 字段收到 "***" 表示不修改，保留已存值。
	patch := acmePatch(candidate, incoming, params.Values, base)
	if perr := svc.ApplyACMEConfig(patch); perr != nil {
		return nil, toProtocolError(perr)
	}
	if state.store.Path() == "" {
		return nil, &pluginapi.Error{
			Code:    pluginapi.E_INTERNAL,
			Message: "KORE_STATE_DIR 未设置，无法保存插件配置",
			Detail:  json.RawMessage(`{"hint":"插件由内核启动时会注入 KORE_STATE_DIR；本地单独调试请先设置该环境变量。"}`),
		}
	}
	payload, err := json.Marshal(candidate)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化配置失败: " + err.Error()}
	}
	if err := state.store.Write(payload); err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "保存插件配置失败: " + err.Error()}
	}
	state.mu.Lock()
	state.values = candidate
	state.source = plugincfg.SourceFile
	state.mu.Unlock()

	restart := incoming.CertDir != "" && incoming.CertDir != base.CertDir
	result := plugincfg.SetResult{Saved: true, Applied: !restart, RestartRequired: restart, Warnings: []string{}}
	if restart {
		result.Warnings = append(result.Warnings, "证书目录已变更，需重启 kored 生效")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化 config.set 结果失败: " + err.Error()}
	}
	return encoded, nil
}

// mergeCfgValues 以当前值为基线做局部更新：调用方未提供的 key 保持原值。
// 用原始 JSON 判断是否提供，避免零值（如 false/""）被误判为"未提供"。
func mergeCfgValues(base, incoming cfgValues, raw json.RawMessage) cfgValues {
	var present map[string]json.RawMessage
	_ = json.Unmarshal(raw, &present)
	out := base
	for key, val := range present {
		switch key {
		case "cert_dir":
			_ = json.Unmarshal(val, &out.CertDir)
		case "acme_ca":
			_ = json.Unmarshal(val, &out.ACMECA)
		case "acme_directory_url":
			_ = json.Unmarshal(val, &out.ACMEDirectoryURL)
		case "acme_webroot":
			_ = json.Unmarshal(val, &out.ACMEWebroot)
		case "acme_sites_root":
			_ = json.Unmarshal(val, &out.ACMESitesRoot)
		case "acme_email":
			_ = json.Unmarshal(val, &out.ACMEEmail)
		case "acme_key_type":
			_ = json.Unmarshal(val, &out.ACMEKeyType)
		case "acme_eab_kid":
			if !plugincfg.IsSensitivePlaceholder(val) {
				_ = json.Unmarshal(val, &out.ACMEEABKid)
			}
		case "acme_eab_hmac_key":
			if !plugincfg.IsSensitivePlaceholder(val) {
				_ = json.Unmarshal(val, &out.ACMEEABHMACKey)
			}
		case "clear_eab":
			_ = json.Unmarshal(val, &out.ClearEAB)
		case "acme_auto_renew":
			_ = json.Unmarshal(val, &out.ACMEAutoRenew)
		case "acme_days_before":
			_ = json.Unmarshal(val, &out.ACMEDaysBefore)
		}
	}
	// 不在这里补默认值：调用方显式给的 0 是非法的 days_before，必须留给
	// validateCfgValues 判 E_INVALID（§8），fillDefaults 只用于启动/文件加载。
	return out
}

// acmePatch 把面板值转成 Service 可应用的局部补丁；sensitive 占位 "***" 不修改。
func acmePatch(candidate, incoming cfgValues, raw json.RawMessage, base cfgValues) certs.ACMEConfigPatch {
	var present map[string]json.RawMessage
	_ = json.Unmarshal(raw, &present)
	patch := certs.ACMEConfigPatch{ClearEAB: candidate.ClearEAB}
	strPtr := func(key string, value string) *string {
		if _, ok := present[key]; !ok {
			return nil
		}
		v := value
		return &v
	}
	patch.CA = strPtr("acme_ca", candidate.ACMECA)
	patch.DirectoryURL = strPtr("acme_directory_url", candidate.ACMEDirectoryURL)
	patch.Webroot = strPtr("acme_webroot", candidate.ACMEWebroot)
	patch.SitesRoot = strPtr("acme_sites_root", candidate.ACMESitesRoot)
	patch.Email = strPtr("acme_email", candidate.ACMEEmail)
	patch.KeyType = strPtr("acme_key_type", candidate.ACMEKeyType)
	if v, ok := present["acme_eab_kid"]; ok && !plugincfg.IsSensitivePlaceholder(v) {
		val := candidate.ACMEEABKid
		patch.EABKid = &val
	}
	if v, ok := present["acme_eab_hmac_key"]; ok && !plugincfg.IsSensitivePlaceholder(v) {
		val := candidate.ACMEEABHMACKey
		patch.EABHMACKey = &val
	}
	if _, ok := present["acme_auto_renew"]; ok {
		val := candidate.ACMEAutoRenew
		patch.AutoRenew = &val
	}
	if _, ok := present["acme_days_before"]; ok {
		val := candidate.ACMEDaysBefore
		patch.DaysBefore = &val
	}
	return patch
}

// invalidConfig 构造配置校验错误（E_INVALID，PLUGIN-CONFIG §8）。
func invalidConfig(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: message}
}

// mustJSON 把标量/数组编成 json.RawMessage（schema 的 default 字段）。
func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return encoded
}
