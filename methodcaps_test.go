package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// expectedMethods 是本仓全部业务方法（含 config 契约）的能力分类，作为 info.json.method_capabilities
// 的验收依据（与 site / waf / db-mysql 的 methodcaps_test 同一口径）。
//
// 只读方法只能 system:read；其余必须 system:admin——把写方法误降为 read 会让只读
// 会话拿到写权限，把读方法标成 admin 则会让只读操作进审计并要管理权。
var expectedMethods = map[string]string{
	// 只读：只读磁盘上的证书目录 / 只探测本机客户端 / 只探测 80-443 行为。
	"list":                "system:read",
	"verify":              "system:read",
	"expiring":            "system:read",
	"acme.status":         "system:read",
	"bind.list":           "system:read",
	"https.status":        "system:read",
	"acme.builtin.status": "system:read",
	// 写 / 管理：落盘证书、签发、覆盖续期、调用外部客户端、登记归属。
	"import":             "system:admin",
	"selfsign":           "system:admin",
	"renew":              "system:admin",
	"issue":              "system:admin",
	"renew.set":          "system:admin",
	"acme.issue":         "system:admin",
	"bind.set":           "system:admin",
	"bind.remove":        "system:admin",
	"https.enforce":      "system:admin",
	"https.unenforce":    "system:admin",
	"acme.builtin.issue": "system:admin",
	"acme.builtin.renew": "system:admin",
	"acme.auto":          "system:admin",
	// 统一配置面板契约（config.get 只读、config.set 管理）。
	"config.get": "system:read",
	"config.set": "system:admin",
}

// configContract 是配置面板通用契约（PLUGIN-CONFIG.md）：config.get 只读、config.set 管理。
//
// 本仓当前**没有**实现这两个方法（配置只来自环境变量 + 内嵌 manifest），但契约必须
// 被测试覆盖：内核的调用期校验是"方法级命中即生效，否则回退插件级 capabilities"，
// 一旦有人加上 config.get 却忘了声明，配置读取会回退到插件级 system:admin 并进审计。
// 这是在各仓反复踩过的坑，所以这里做双向断言：
//   - 实现了但没声明 → 失败（回退 admin 审计）；
//   - 声明了但没实现 → 失败（声明漂移，调用必然 E_NOTFOUND）；
//   - 声明了且实现 → 能力值必须是 read / admin 对应项。
var configContract = map[string]string{
	"config.get": "system:read",
	"config.set": "system:admin",
}

// privilegedCapabilitySet 是内核唯一白名单（internal/core/registry/validate.go）：
// 6 项特权能力，插件不得声明白名单之外的值。
var privilegedCapabilitySet = map[string]struct{}{
	"system:read": {}, "system:admin": {},
	"net:read": {}, "net:write": {},
	"proc:read": {}, "proc:write": {},
}

// manifestDeclFields 是 info.json / manifest.json 中与版本同步和能力声明相关的字段子集。
type manifestDeclFields struct {
	ID                 string            `json:"id"`
	Version            string            `json:"version"`
	Capabilities       []string          `json:"capabilities"`
	MethodCapabilities map[string]string `json:"method_capabilities"`
}

// loadManifestDecl 读取仓根 JSON（go test 的工作目录就是包目录 = 仓根）。
func loadManifestDecl(t *testing.T, path string) manifestDeclFields {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	var decl manifestDeclFields
	if err := json.Unmarshal(raw, &decl); err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	return decl
}

// TestMethodCapabilitiesBidirectional 防「声明」与「实现」漂移，双向都查：
//   - 实现 ⊆ 声明：businessVerb 认得的每个方法都必须在 info.json 里分类，
//     否则调用期回退插件级 capabilities（system:admin），只读方法也进管理审计；
//   - 声明 ⊆ 实现：info.json 声明的每个方法都必须真的被分发，否则声明即谎言。
func TestMethodCapabilitiesBidirectional(t *testing.T) {
	info := loadManifestDecl(t, "info.json")
	if info.ID != "ssl" {
		t.Fatalf("info.json id=%q，期望 ssl", info.ID)
	}
	if len(info.MethodCapabilities) != len(expectedMethods) {
		t.Fatalf("method_capabilities 声明 %d 条，期望 %d 条（新增/删除方法必须同步声明与分类）",
			len(info.MethodCapabilities), len(expectedMethods))
	}

	prefix := info.ID + "."
	declared := make(map[string]string, len(info.MethodCapabilities))
	for method, capability := range info.MethodCapabilities {
		action, ok := strings.CutPrefix(method, prefix)
		if !ok || action == "" {
			t.Fatalf("方法键 %q 必须以插件自身 id 为域（应为 %s<action>）", method, prefix)
		}
		if _, ok := privilegedCapabilitySet[capability]; !ok {
			t.Fatalf("%s 的能力值 %q 不是 6 项特权能力之一", method, capability)
		}
		declared[action] = capability
	}

	// 方向一：实现 → 声明（漏声明 = 回退 admin 审计）。
	for action, wantCap := range expectedMethods {
		if _, ok := businessVerb(prefix+action, info.ID); !ok {
			t.Fatalf("测试清单列了 %q，但 businessVerb 不认它（实现清单与测试清单漂移）", prefix+action)
		}
		gotCap, ok := declared[action]
		if !ok {
			t.Fatalf("方法 %q 已实现但未在 info.json 声明：调用期会回退插件级 capabilities（system:admin）", prefix+action)
		}
		if gotCap != wantCap {
			t.Fatalf("方法 %q 的能力=%q，期望 %q（读方法只能 read，写方法必须 admin）", prefix+action, gotCap, wantCap)
		}
	}

	// 方向二：声明 → 实现（多声明 = 调用必然 E_NOTFOUND）。
	for action := range declared {
		if _, ok := expectedMethods[action]; !ok {
			t.Fatalf("info.json 声明了 %q，但它不是本仓业务方法（声明漂移）", prefix+action)
		}
	}

	// 反向哨兵：近义词 / 错拼不得被 businessVerb 放行（防止有人加"差不多"的别名）。
	for _, wrong := range []string{"bind", "https", "config", "renew.setx", "bind.get", "https", "list.all"} {
		if _, ok := businessVerb(prefix+wrong, info.ID); ok {
			t.Fatalf("businessVerb 不应识别 %q", prefix+wrong)
		}
	}
}

// TestConfigMethodContract 单独覆盖 config.get / config.set 契约（见 configContract 注释）。
func TestConfigMethodContract(t *testing.T) {
	info := loadManifestDecl(t, "info.json")
	prefix := info.ID + "."
	for action, wantCap := range configContract {
		_, implemented := businessVerb(prefix+action, info.ID)
		gotCap, declared := info.MethodCapabilities[prefix+action]
		switch {
		case implemented && !declared:
			t.Fatalf("实现了 %q 却未声明：未声明的方法会回退插件级 capabilities（system:admin），"+
				"配置读取按 admin 进审计", prefix+action)
		case implemented && declared && gotCap != wantCap:
			t.Fatalf("%q 的能力=%q，期望 %q（读=read、写=admin）", prefix+action, gotCap, wantCap)
		case !implemented && declared:
			t.Fatalf("声明了 %q 但本仓未实现：调用必然 E_NOTFOUND", prefix+action)
		}
	}
}

// TestManifestVersionSynced 守住 G-17：info.json 与内嵌 manifest.json 的
// id / version / capabilities 必须一致（Makefile dist 也会比对，此处提前在单测拦住）。
func TestManifestVersionSynced(t *testing.T) {
	info := loadManifestDecl(t, "info.json")
	manifest := loadManifestDecl(t, "manifest.json")
	if manifest.ID != info.ID {
		t.Fatalf("manifest.id=%q 与 info.id=%q 不一致", manifest.ID, info.ID)
	}
	if manifest.Version != info.Version {
		t.Fatalf("manifest.version=%q 与 info.version=%q 不一致（发版必须同步 bump）", manifest.Version, info.Version)
	}
	if strings.Join(manifest.Capabilities, ",") != strings.Join(info.Capabilities, ",") {
		t.Fatalf("manifest.capabilities=%v 与 info.capabilities=%v 不一致", manifest.Capabilities, info.Capabilities)
	}
}
