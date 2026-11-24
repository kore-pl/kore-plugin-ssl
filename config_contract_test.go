package main

// config_contract_test.go 覆盖 PLUGIN-CONFIG §1/§2/§3/§4/§5/§6/§8 的契约：
// get schema 齐、source 三态、set 校验正反、持久化读回、sensitive 掩码与
// "*** 不修改"、热生效桥接、dispatch 命中 ssl.config.get/set。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore-plugin-ssl/internal/plugincfg"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// contractFixture 是契约测试夹具：临时 state 目录（config.json 落点）+ 临时
// 证书目录（acme/settings.json 落点），service 用固定 Dir 构造避免读环境变量。
type contractFixture struct {
	cfg      config
	svc      *certs.Service
	stateDir string
	certDir  string
}

func newContractFixture(t *testing.T) contractFixture {
	t.Helper()
	stateDir := t.TempDir()
	certDir := t.TempDir()
	state, err := initConfigState(stateDir)
	if err != nil {
		t.Fatalf("初始化配置状态失败: %v", err)
	}
	cfg := config{id: "ssl", version: "0.8.0", state: state, startedAt: testConfig().startedAt}
	return contractFixture{
		cfg:      cfg,
		svc:      certs.NewService(certs.Options{Dir: certDir}),
		stateDir: stateDir,
		certDir:  certDir,
	}
}

// TestConfigGetSchemaContract 逐条核对 PLUGIN-CONFIG §2：
// schema 固定 title+fields；字段类型仅在 string/int/bool/select/list 枚举内；
// 每个字段 key/label/type/default/required/help 必填（required 是 bool，有无即算声明）；
// select options 非空；label/help 中文、不含内部术语；EAB 敏感字段标 sensitive。
func TestConfigGetSchemaContract(t *testing.T) {
	schema := configSchema()
	if strings.TrimSpace(schema.Title) == "" {
		t.Fatal("schema.title 不能为空")
	}
	if len(schema.Fields) == 0 {
		t.Fatal("schema.fields 不能为空")
	}
	if err := plugincfg.ValidateSchema(schema); err != nil {
		t.Fatalf("schema 自检失败（§2 枚举/必填）: %v", err)
	}

	seen := map[string]bool{}
	sensitiveCount := 0
	for _, field := range schema.Fields {
		seen[field.Key] = true
		switch field.Type {
		case plugincfg.TypeString, plugincfg.TypeInt, plugincfg.TypeBool, plugincfg.TypeSelect, plugincfg.TypeList:
		default:
			t.Fatalf("字段 %s type=%q 不在 §2 枚举内（禁 object/any，G-24）", field.Key, field.Type)
		}
		if field.Key == "" || field.Label == "" || field.Help == "" {
			t.Fatalf("字段缺 key/label/help: %+v", field)
		}
		if strings.Contains(field.Label, "instance") || strings.Contains(field.Label, "revision") {
			t.Fatalf("字段 %s label 含内部术语: %q", field.Key, field.Label)
		}
		if len(field.Default) == 0 || !json.Valid(field.Default) {
			t.Fatalf("字段 %s default 非法", field.Key)
		}
		if field.Type == plugincfg.TypeSelect && len(field.Options) == 0 {
			t.Fatalf("select 字段 %s 缺 options", field.Key)
		}
		if field.Sensitive {
			sensitiveCount++
		}
	}
	// 必备真实能力字段都在。
	for _, key := range []string{"cert_dir", "acme_ca", "acme_days_before", "acme_webroot", "acme_eab_hmac_key"} {
		if !seen[key] {
			t.Fatalf("缺少真实能力字段 %q", key)
		}
	}
	// G-30：ACME EAB 密钥/账户密钥敏感项必须标 sensitive。
	if sensitiveCount < 1 {
		t.Fatalf("sensitive 字段数=%d，EAB HMAC 密钥必须标 sensitive（G-30）", sensitiveCount)
	}
}

// TestConfigGetResultShape 核对 §1：返回 {schema, values, source}。
func TestConfigGetResultShape(t *testing.T) {
	f := newContractFixture(t)
	raw, perr := configGet(f.cfg, f.svc)
	if perr != nil {
		t.Fatalf("config.get 失败: %v", perr)
	}
	var result struct {
		Schema json.RawMessage `json:"schema"`
		Values json.RawMessage `json:"values"`
		Source string          `json:"source"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("结果非 JSON: %v", err)
	}
	if len(result.Schema) == 0 || len(result.Values) == 0 {
		t.Fatalf("结果缺 schema/values: %s", raw)
	}
	switch result.Source {
	case plugincfg.SourceFile, plugincfg.SourceEnv, plugincfg.SourceDefault:
	default:
		t.Fatalf("source=%q 不在 file/env/default 枚举", result.Source)
	}
}

// TestConfigSetValidation 核对 §8：非法值 E_INVALID 且旧配置仍可用。
func TestConfigSetValidation(t *testing.T) {
	f := newContractFixture(t)
	cases := []struct {
		name   string
		values string
	}{
		{"acme_ca 枚举越界", `{"acme_ca":"unknown-ca"}`},
		{"days_before 超上限", `{"acme_days_before":0}`},
		{"days_before 负数", `{"acme_days_before":-5}`},
		{"cert_dir 非绝对", `{"cert_dir":"relative/path"}`},
		{"webroot 非绝对", `{"acme_webroot":"www"}`},
		{"key_type 越界", `{"acme_key_type":"rsa4096"}`},
		{"EAB 不成对", `{"acme_eab_kid":"kid-only"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := json.RawMessage(`{"values":` + tc.values + `}`)
			_, perr := configSet(params, f.cfg, f.svc)
			if perr == nil {
				t.Fatalf("非法值却通过校验: %s", tc.values)
			}
			if perr.Code != pluginapi.E_INVALID {
				t.Fatalf("错误码=%q，期望 E_INVALID（%s）", perr.Code, perr.Message)
			}
			if perr.Message == "" || strings.Contains(perr.Message, "stack") {
				t.Fatalf("错误消息应写清哪一项错，不含堆栈: %q", perr.Message)
			}
		})
	}
	// 非法 set 后旧配置仍可用（§10）。
	if _, perr := configGet(f.cfg, f.svc); perr != nil {
		t.Fatalf("非法 set 破坏了旧配置: %v", perr)
	}
}

// TestConfigSetPersistReadback 核对 §3/§4：合法 set 原子落盘、内存更新、
// config.get 读回且 source=file，重载仍读到（持久化）。
func TestConfigSetPersistReadback(t *testing.T) {
	f := newContractFixture(t)
	params := json.RawMessage(`{"values":{"acme_ca":"letsencrypt","acme_days_before":14,"acme_email":"ops@example.com"}}`)
	raw, perr := configSet(params, f.cfg, f.svc)
	if perr != nil {
		t.Fatalf("config.set 失败: %v", perr)
	}
	var setResult plugincfg.SetResult
	if err := json.Unmarshal(raw, &setResult); err != nil {
		t.Fatal(err)
	}
	if !setResult.Saved || !setResult.Applied || setResult.RestartRequired {
		t.Fatalf("set 结果异常: %+v", setResult)
	}
	// 文件存在且权限 0600（§3）。
	path := filepath.Join(f.stateDir, "config.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("config.json 未落盘: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config.json 权限=%o，期望 600", info.Mode().Perm())
	}
	// config.get 读回。
	getRaw, perr := configGet(f.cfg, f.svc)
	if perr != nil {
		t.Fatal(perr)
	}
	var got struct {
		Values cfgValues `json:"values"`
		Source string    `json:"source"`
	}
	if err := json.Unmarshal(getRaw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Values.ACMECA != "letsencrypt" || got.Values.ACMEDaysBefore != 14 || got.Values.ACMEEmail != "ops@example.com" {
		t.Fatalf("读回值不符: %+v", got.Values)
	}
	if got.Source != plugincfg.SourceFile {
		t.Fatalf("set 后 source=%q，期望 file（§4）", got.Source)
	}
	// 模拟新进程：同一 stateDir 重新加载，值仍读到（持久化）。
	state2, err := initConfigState(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg2 := config{id: "ssl", state: state2}
	get2, perr := configGet(cfg2, certs.NewService(certs.Options{Dir: t.TempDir()}))
	if perr != nil {
		t.Fatal(perr)
	}
	var got2 struct {
		Values cfgValues `json:"values"`
	}
	_ = json.Unmarshal(get2, &got2)
	if got2.Values.ACMEDaysBefore != 14 || got2.Values.ACMECA != "letsencrypt" {
		t.Fatalf("重载后值丢失: %+v", got2.Values)
	}
}

// TestConfigSetSensitive 核对 §6：config.get 不回明文；set 收到 *** 不改已存值。
func TestConfigSetSensitive(t *testing.T) {
	f := newContractFixture(t)
	// 先写入 EAB 凭据（sensitive）。
	params := json.RawMessage(`{"values":{"acme_eab_kid":"kid-123","acme_eab_hmac_key":"secret-hmac"}}`)
	if _, perr := configSet(params, f.cfg, f.svc); perr != nil {
		t.Fatalf("写 EAB 失败: %v", perr)
	}
	settingsPath := filepath.Join(f.certDir, "acme", "settings.json")
	before, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("ACME settings 未落盘: %v", err)
	}
	if !strings.Contains(string(before), "secret-hmac") {
		t.Fatalf("EAB 密钥未写入 0600 文件: %s", before)
	}
	// config.get 必须掩码，不回明文。
	getRaw, perr := configGet(f.cfg, f.svc)
	if perr != nil {
		t.Fatal(perr)
	}
	if strings.Contains(string(getRaw), "secret-hmac") {
		t.Fatalf("config.get 回传了敏感明文（G-30）: %s", getRaw)
	}
	var got struct {
		Values map[string]any `json:"values"`
	}
	if err := json.Unmarshal(getRaw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Values["acme_eab_hmac_key"] != plugincfg.SensitivePlaceholder {
		t.Fatalf("敏感字段未掩码: %v", got.Values["acme_eab_hmac_key"])
	}
	// *** 表示不修改：提交掩码后底层文件不能被覆盖成 ***。
	params2 := json.RawMessage(`{"values":{"acme_eab_hmac_key":"***"}}`)
	if _, perr := configSet(params2, f.cfg, f.svc); perr != nil {
		t.Fatalf("提交 *** 失败: %v", perr)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "secret-hmac") || strings.Contains(string(after), `"eab_hmac_key": "***"`) {
		t.Fatalf("提交 *** 覆盖了已存密钥（G-30）: %s", after)
	}
}

// TestConfigSetHotApply 核对 §5：ACME 字段保存后业务下一次读盘即生效。
func TestConfigSetHotApply(t *testing.T) {
	f := newContractFixture(t)
	params := json.RawMessage(`{"values":{"acme_ca":"letsencrypt-staging","acme_days_before":7}}`)
	if _, perr := configSet(params, f.cfg, f.svc); perr != nil {
		t.Fatal(perr)
	}
	vals, perr := f.svc.GetACMEConfig()
	if perr != nil {
		t.Fatal(perr)
	}
	if vals.DaysBefore != 7 || vals.CA != "letsencrypt-staging" {
		t.Fatalf("ACME 未热生效: %+v", vals)
	}
}

// TestConfigSetRestartRequired 核对 §5：cert_dir 变更需重启。
func TestConfigSetRestartRequired(t *testing.T) {
	f := newContractFixture(t)
	params := json.RawMessage(`{"values":{"cert_dir":"/tmp/new-cert-dir"}}`)
	raw, perr := configSet(params, f.cfg, f.svc)
	if perr != nil {
		t.Fatal(perr)
	}
	var result plugincfg.SetResult
	_ = json.Unmarshal(raw, &result)
	if result.Saved != true || result.RestartRequired != true || result.Applied != false {
		t.Fatalf("cert_dir 变更应 restart_required=true/applied=false: %+v", result)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("需重启时 warnings 必须写清原因")
	}
}

// TestConfigDispatchHit 核对 §1/要求④：config.get/set 能被 ssl.config.* 命中。
func TestConfigDispatchHit(t *testing.T) {
	f := newContractFixture(t)
	f.cfg.capabilities = []string{"system:admin"}
	for _, method := range []string{"ssl.config.get", "config.get"} {
		req := &pluginapi.Request{Type: pluginapi.TypeRequest, ID: "1", ReqID: "r1", Method: method, Params: json.RawMessage(`{}`)}
		resp, shutdown := dispatch(req, f.cfg, f.svc, testLogger())
		if shutdown {
			t.Fatalf("%s 不应触发 shutdown", method)
		}
		if resp.Error != nil {
			t.Fatalf("%s 命中失败: %v", method, resp.Error)
		}
		if len(resp.Result) == 0 || !strings.Contains(string(resp.Result), "schema") {
			t.Fatalf("%s 结果缺 schema: %s", method, resp.Result)
		}
	}
	req := &pluginapi.Request{Type: pluginapi.TypeRequest, ID: "2", ReqID: "r2", Method: "ssl.config.set",
		Params: json.RawMessage(`{"values":{"acme_days_before":21}}`)}
	resp, _ := dispatch(req, f.cfg, f.svc, testLogger())
	if resp.Error != nil {
		t.Fatalf("ssl.config.set 命中失败: %v", resp.Error)
	}
	if !strings.Contains(string(resp.Result), `"saved":true`) {
		t.Fatalf("set 结果异常: %s", resp.Result)
	}
}
