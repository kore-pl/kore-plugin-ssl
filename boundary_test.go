package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本仓架构边界测试（G-13 仓库边界 + 插件能力边界 + G-19 空闲行为）。
//
// 这些断言的作用是"用测试而不是注释"证明 ssl 插件不越权：
//
//  1. 不写 web 服务器配置：证书绑定站点后，写 443 监听 / 证书指令 / 80→443 跳转的
//     唯一归属方是 site 插件的 site.bindSSL；本仓只登记「证书 → 站点」归属并返回
//     推荐载荷。任何人把配置指令、配置目录路径或 reload 命令塞进本仓 Go 代码，
//     TestRepoDoesNotWriteWebServerConfig 立刻失败。
//  2. 不起后台定时器：ACME 自动续期不在本仓做（G-10 无后台联网 + G-19 定时器白名单，
//     调度只归内核 scheduler）。renew.set 只产任务描述。
//  3. 不跨插件直连：协议层禁止插件 A 连插件 B 的 socket（PLUGIN-PROTOCOL §2），
//     本仓唯一允许的 net.Dial 是 main.go 连内核注入的 UDS。
//  4. 外部命令只用于 ACME 客户端（ADR-0020 的显式调用）：不得出现"调个工具改站点配置"。

// forbiddenConfigTokens 是"写 web 服务器配置"的典型片段：配置目录、指令名与静态文件。
//
// 故意用字符串拼接构造，避免本测试文件自身命中扫描（否则只能把断言文件加进例外，
// 留下"把越权代码写进这个文件就绕过检查"的后门）。
var forbiddenConfigTokens = []string{
	"/etc/" + "ngi" + "nx",
	"ngi" + "nx.conf",
	"ssl_" + "certificate ",
	"ssl_" + "certificate_key",
	"listen " + "443",
	"listen " + "80",
	"return " + "301",
	"server_" + "name ",
	"vho" + "st",
	"ngi" + "nx -s reload",
}

// forbiddenSchedulingTokens 是 G-19 定时器白名单禁止的周期来源。
var forbiddenSchedulingTokens = []string{
	"time.New" + "Ticker",
	"time.After" + "Func",
	"time.Tick(",
}

// goSourceFiles 返回仓库内全部 Go 源文件（相对路径 → 内容），跳过构建产物与 .git。
func goSourceFiles(t *testing.T) map[string]string {
	t.Helper()
	files := make(map[string]string)
	skipDirs := map[string]struct{}{".git": {}, "bin": {}, "dist": {}}
	err := filepath.WalkDir(".", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if _, skip := skipDirs[entry.Name()]; skip && path != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files[filepath.ToSlash(path)] = string(body)
		return nil
	})
	if err != nil {
		t.Fatalf("遍历仓库 Go 文件失败: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("没有扫到任何 Go 文件：扫描逻辑失效，断言等于没跑")
	}
	return files
}

// isProductionSource 判断是否为生产代码（排除 _test.go，故障/架构断言只看会被编译进二进制的代码）。
func isProductionSource(path string) bool {
	return !strings.HasSuffix(path, "_test.go")
}

// assertNoToken 在单个文件里查找禁用片段，命中即失败并给出文件与上下文。
func assertNoToken(t *testing.T, path, body string, tokens []string) {
	t.Helper()
	for _, token := range tokens {
		if idx := strings.Index(body, token); idx >= 0 {
			start := idx - 40
			if start < 0 {
				start = 0
			}
			end := idx + len(token) + 40
			if end > len(body) {
				end = len(body)
			}
			t.Fatalf("%s 出现越权片段 %q：\n…%s…\n本仓不写 web 服务器配置、不起后台定时器、不跨插件直连",
				path, token, body[start:end])
		}
	}
}

// TestRepoDoesNotWriteWebServerConfig 断言本仓 Go 代码不含任何 web 服务器配置指令 /
// 配置目录路径 / 静态文件片段——写站点配置是 site 插件的职责（site.bindSSL）。
func TestRepoDoesNotWriteWebServerConfig(t *testing.T) {
	files := goSourceFiles(t)
	for path, body := range files {
		assertNoToken(t, path, body, forbiddenConfigTokens)
	}
}

// TestNoBackgroundTimers 断言生产代码没有周期来源（G-19）：续期只由内核 scheduler
// 到点调 ssl.renew，ACME 不做后台自动签发（ADR-0020）。
func TestNoBackgroundTimers(t *testing.T) {
	files := goSourceFiles(t)
	checked := 0
	for path, body := range files {
		if !isProductionSource(path) {
			continue
		}
		checked++
		assertNoToken(t, path, body, forbiddenSchedulingTokens)
	}
	if checked < 10 {
		t.Fatalf("只扫到 %d 个生产 Go 文件，扫描范围异常（断言可能被绕过）", checked)
	}
}

// TestOnlyKernelSocketDial 断言全仓只有一处 net.Dial，且在 main.go 里连内核 UDS。
// 出现第二处 outbound dial 意味着有人在绕过内核 bus 做插件间直连。
func TestOnlyKernelSocketDial(t *testing.T) {
	dialToken := "net." + "Dial("
	files := goSourceFiles(t)
	total := 0
	where := make([]string, 0, 2)
	for path, body := range files {
		if !isProductionSource(path) {
			continue
		}
		if count := strings.Count(body, dialToken); count > 0 {
			total += count
			where = append(where, path)
		}
	}
	if total != 1 || len(where) != 1 || filepath.ToSlash(where[0]) != "main.go" {
		t.Fatalf("net.Dial 应只有 main.go 连内核 UDS 一处，实际 %d 处：%v", total, where)
	}
}

// TestExternalCommandsOnlyForACMEClients 断言 exec.CommandContext 只出现在 ACME 调用
// （外部 certbot / acme.sh，ADR-0020）。出现别处意味着本仓开始调用外部工具改站点配置。
func TestExternalCommandsOnlyForACMEClients(t *testing.T) {
	execToken := "exec.Command" + "Context("
	files := goSourceFiles(t)
	for path, body := range files {
		if !isProductionSource(path) {
			continue
		}
		if !strings.Contains(body, execToken) {
			continue
		}
		want := "internal/certs/acme.go"
		if filepath.ToSlash(path) != want {
			t.Fatalf("%s 用了 %s，但外部命令只允许出现在 %s（ACME 客户端，ADR-0020）", path, execToken, want)
		}
	}
}

// TestBindingSuggestionPointsToSitePlugin 断言"绑定站点"的推荐载荷指向 site 插件，
// 且本仓从不执行它——只作为返回值交给前端 / 用户（被否决的直调路径见 CHANGELOG）。
func TestBindingSuggestionPointsToSitePlugin(t *testing.T) {
	files := goSourceFiles(t)
	found := 0
	for path, body := range files {
		if !isProductionSource(path) || !strings.Contains(body, "site.bindSSL") {
			continue
		}
		found++
	}
	if found == 0 {
		t.Fatal("没有找到 site.bindSSL 推荐载荷：绑定站点必须给出站点侧动作（归属登记 + 建议载荷）")
	}
	// 推荐载荷只允许出现在业务层（生成建议/hint），不允许出现在协议分发层被"顺手执行"。
	// binding/https_status/acme_issue 都是业务层：前两者构造 site_bind 载荷，
	// acme_issue 只是在成功提示里指向站点页的绑定方法。
	suggestionOnlyFiles := map[string]struct{}{
		"internal/certs/binding.go":      {},
		"internal/certs/https_status.go": {},
		"internal/certs/acme_issue.go":   {},
		"internal/certs/https_state.go":  {},
	}
	for path := range files {
		if !isProductionSource(path) {
			continue
		}
		if _, ok := suggestionOnlyFiles[filepath.ToSlash(path)]; ok {
			continue
		}
		body := files[path]
		if strings.Contains(body, "site.bindSSL") {
			t.Fatalf("%s 引用了 site.bindSSL：站点侧动作只能作为建议载荷生成，不得在别处执行", path)
		}
	}
}
