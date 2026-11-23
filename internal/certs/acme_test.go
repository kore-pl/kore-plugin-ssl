package certs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCertbotScript 是一个最小的 certbot 替身：--version 打印版本，其余调用按
// --config-dir/-d 参数把预生成证书写到 certbot 的标准位置，并记录 argv 供断言。
const fakeCertbotScript = `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "certbot 9.9.9-test"
  exit 0
fi
if [ -n "$FAKE_ARGS_LOG" ]; then
  printf '%s\n' "$*" > "$FAKE_ARGS_LOG"
fi
config=""; domain=""; prev=""
for a in "$@"; do
  if [ "$prev" = "--config-dir" ]; then config="$a"; fi
  if [ "$prev" = "-d" ]; then domain="$a"; fi
  prev="$a"
done
if [ -z "$config" ] || [ -z "$domain" ]; then
  echo "missing --config-dir or -d" 1>&2
  exit 2
fi
mkdir -p "$config/live/$domain"
cp "$FAKE_CERT" "$config/live/$domain/fullchain.pem"
cp "$FAKE_KEY" "$config/live/$domain/privkey.pem"
echo "Successfully received certificate for $domain"
`

// fakeAcmeShScript 是 acme.sh 替身：版本输出为两行，验证解析取 vX.Y.Z。
const fakeAcmeShScript = `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "https://github.com/acmesh-official/acme.sh"
  echo "v3.0.7"
  exit 0
fi
echo "unexpected invocation" 1>&2
exit 3
`

// writeExecutable 写一个 0755 的脚本并返回路径。
func writeExecutable(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("写测试脚本 %s 失败: %v", name, err)
	}
	return path
}

// acmeServiceWithTool 返回注入了指定工具路径的服务（时钟固定）。
func acmeServiceWithTool(t *testing.T, toolPath string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	return NewService(Options{
		Dir:       dir,
		Now:       func() time.Time { return fixedNow },
		ACMETools: map[string]string{"certbot": toolPath},
	}), dir
}

// TestACMEStatusDetectsCertbot 本机存在 certbot 时如实返回可用与版本。
func TestACMEStatusDetectsCertbot(t *testing.T) {
	tool := writeExecutable(t, t.TempDir(), "certbot", fakeCertbotScript)
	svc, _ := acmeServiceWithTool(t, tool)
	status, perr := svc.ACMEStatus()
	if perr != nil {
		t.Fatalf("ssl.acme.status 失败: %v", perr)
	}
	if !status.Available || status.Tool != acmeToolCertbot || status.Version != "9.9.9-test" {
		t.Fatalf("探测结果不符：%+v", status)
	}
}

// TestACMEStatusDetectsAcmeSh certbot 缺失时回落到 acme.sh，并解析 vX.Y.Z。
func TestACMEStatusDetectsAcmeSh(t *testing.T) {
	acmeSh := writeExecutable(t, t.TempDir(), "acme.sh", fakeAcmeShScript)
	svc := NewService(Options{Dir: t.TempDir(), ACMETools: map[string]string{"acme.sh": acmeSh}})
	status, perr := svc.ACMEStatus()
	if perr != nil {
		t.Fatalf("ssl.acme.status 失败: %v", perr)
	}
	if !status.Available || status.Tool != acmeToolACMESh || status.Version != "3.0.7" {
		t.Fatalf("探测结果不符：%+v", status)
	}
}

// TestACMEStatusUnavailable 没装客户端时返回 available=false，且不报错。
func TestACMEStatusUnavailable(t *testing.T) {
	svc := NewService(Options{
		Dir:       t.TempDir(),
		ACMETools: map[string]string{"certbot": filepath.Join(t.TempDir(), "missing-certbot")},
	})
	status, perr := svc.ACMEStatus()
	if perr != nil {
		t.Fatalf("缺工具不应报错: %v", perr)
	}
	if status.Available || status.Tool != "" || status.Version != "" {
		t.Fatalf("缺工具应 available=false 且 tool/version 为空：%+v", status)
	}
}

// TestACMEStatusBrokenBinary 二进制存在但 --version 跑不通时不误报可用。
func TestACMEStatusBrokenBinary(t *testing.T) {
	broken := writeExecutable(t, t.TempDir(), "certbot", "#!/bin/sh\nexit 7\n")
	svc, _ := acmeServiceWithTool(t, broken)
	status, perr := svc.ACMEStatus()
	if perr != nil {
		t.Fatalf("探测失败不应报错: %v", perr)
	}
	if status.Available {
		t.Fatalf("--version 失败的二进制不能算可用：%+v", status)
	}
}

// TestACMEIssueRequiresConfirm 未显式确认时拒绝联网签发，且不落任何文件。
func TestACMEIssueRequiresConfirm(t *testing.T) {
	argsLog := filepath.Join(t.TempDir(), "args.log")
	t.Setenv("FAKE_ARGS_LOG", argsLog)
	tool := writeExecutable(t, t.TempDir(), "certbot", fakeCertbotScript)
	svc, dir := acmeServiceWithTool(t, tool)
	_, perr := svc.ACMEIssue(ACMEIssueRequest{Domain: "acme.example.com", Email: "ops@example.com"})
	if perr == nil || perr.Code != codeInvalid {
		t.Fatalf("confirm=false 应 E_INVALID，实际 %+v", perr)
	}
	if !strings.Contains(perr.Message, "confirm") || perr.Hint == "" {
		t.Fatalf("必须说明要 confirm=true 并给 hint：%+v", perr)
	}
	if _, err := os.Stat(argsLog); !os.IsNotExist(err) {
		t.Fatal("未确认时不得调用外部客户端")
	}
	assertNoCertFilesIn(t, dir)
}

// TestACMEIssueUnavailable 无客户端时 E_UNSUPPORTED + hint。
func TestACMEIssueUnavailable(t *testing.T) {
	svc := NewService(Options{
		Dir:       t.TempDir(),
		ACMETools: map[string]string{"certbot": filepath.Join(t.TempDir(), "missing")},
	})
	_, perr := svc.ACMEIssue(ACMEIssueRequest{Domain: "acme.example.com", Email: "ops@example.com", Confirm: true})
	if perr == nil || perr.Code != codeUnsupported {
		t.Fatalf("无客户端应 E_UNSUPPORTED，实际 %+v", perr)
	}
	if !strings.Contains(perr.Message, "certbot") || perr.Hint == "" {
		t.Fatalf("message 应点明缺失的客户端并给 hint：%+v", perr)
	}
}

// TestACMEIssueImportsAndMarks 端到端：调外部工具 → 导入管理目录 → 写 .acme 标记 → 续期拒绝重签。
func TestACMEIssueImportsAndMarks(t *testing.T) {
	work := t.TempDir()
	certPEM, keyPEM := makeTestPair(t, testPairOptions{domain: "acme.example.com"})
	certPath := writeTestFile(t, work, "fixture.crt", certPEM)
	keyPath := writeTestFile(t, work, "fixture.key", keyPEM)
	argsLog := filepath.Join(work, "args.log")
	t.Setenv("FAKE_CERT", certPath)
	t.Setenv("FAKE_KEY", keyPath)
	t.Setenv("FAKE_ARGS_LOG", argsLog)
	tool := writeExecutable(t, work, "certbot", fakeCertbotScript)
	svc, dir := acmeServiceWithTool(t, tool)

	result, perr := svc.ACMEIssue(ACMEIssueRequest{
		Domain: "acme.example.com", Email: "ops@example.com", Confirm: true,
	})
	if perr != nil {
		t.Fatalf("签发失败: %v", perr)
	}
	if !result.Issued || !result.Imported || result.Tool != acmeToolCertbot {
		t.Fatalf("签发结果不符：%+v", result)
	}
	if !filepath.IsAbs(result.CertPath) || result.Fingerprint == "" || result.DaysLeft <= 0 {
		t.Fatalf("证书元数据缺失：%+v", result)
	}
	if _, err := os.Stat(result.CertPath); err != nil {
		t.Fatalf("证书未落盘: %v", err)
	}
	// 私钥只给路径，值绝不回显。
	if _, err := os.Stat(result.KeyPath); err != nil {
		t.Fatalf("私钥路径不存在: %v", err)
	}
	if strings.Contains(result.OutputTail, "BEGIN PRIVATE KEY") {
		t.Fatal("输出里不得出现私钥内容")
	}
	marker := filepath.Join(dir, "acme.example.com"+acmeMarkerSuffix)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf(".acme 标记未写入: %v", err)
	}
	args := readTestFile(t, argsLog)
	for _, want := range []string{"certonly", "--standalone", "-d acme.example.com", "--email ops@example.com", "--config-dir"} {
		if !strings.Contains(args, want) {
			t.Fatalf("调用参数缺少 %q：%s", want, args)
		}
	}
	// 导入后 source 必须是 acme，续期必须拒绝重签（不得当成自签证书覆盖）。
	listed, perr := svc.List()
	if perr != nil {
		t.Fatalf("list 失败: %v", perr)
	}
	if len(listed.Certs) != 1 || listed.Certs[0].Source != "acme" {
		t.Fatalf("导入后来源应为 acme：%+v", listed.Certs)
	}
	if _, perr := svc.Renew(RenewRequest{Domain: "acme.example.com"}); perr == nil || perr.Code != codeUnsupported {
		t.Fatalf("ACME 证书续期应 E_UNSUPPORTED，实际 %+v", perr)
	}
}

// TestACMEIssueToolFailure 外部工具失败时 E_UPSTREAM，并把输出尾部放进 hint。
func TestACMEIssueToolFailure(t *testing.T) {
	tool := writeExecutable(t, t.TempDir(), "certbot",
		"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'certbot 9.9.9-test'; exit 0; fi\necho 'error: port 80 is already in use' 1>&2\nexit 1\n")
	svc, dir := acmeServiceWithTool(t, tool)
	_, perr := svc.ACMEIssue(ACMEIssueRequest{Domain: "acme.example.com", Email: "ops@example.com", Confirm: true})
	if perr == nil || perr.Code != codeUpstream {
		t.Fatalf("工具失败应 E_UPSTREAM，实际 %+v", perr)
	}
	if !strings.Contains(perr.Hint, "port 80") {
		t.Fatalf("hint 应包含工具输出尾部：%q", perr.Hint)
	}
	assertNoCertFilesIn(t, dir)
}

// TestACMEIssueInvalidEmail 邮箱必填且形状合法。
func TestACMEIssueInvalidEmail(t *testing.T) {
	tool := writeExecutable(t, t.TempDir(), "certbot", fakeCertbotScript)
	svc, _ := acmeServiceWithTool(t, tool)
	for _, email := range []string{"", "not-an-email", "a@b"} {
		if _, perr := svc.ACMEIssue(ACMEIssueRequest{Domain: "acme.example.com", Email: email, Confirm: true}); perr == nil || perr.Code != codeInvalid {
			t.Fatalf("email=%q 应 E_INVALID，实际 %+v", email, perr)
		}
	}
}

// TestParseToolVersion 覆盖 certbot / acme.sh / 兜底三种版本形态。
func TestParseToolVersion(t *testing.T) {
	cases := []struct{ output, want string }{
		{"certbot 2.6.0", "2.6.0"},
		{"certbot v1.21.0 (snap)", "1.21.0"},
		{"https://github.com/acmesh-official/acme.sh\nv3.0.7\n", "3.0.7"},
		{"weird-tool 1.0\n", "weird-tool 1.0"},
	}
	for _, tc := range cases {
		if got := parseToolVersion(tc.output); got != tc.want {
			t.Fatalf("parseToolVersion(%q)=%q，期望 %q", tc.output, got, tc.want)
		}
	}
}

// TestACMEArgsShapes 固定各客户端的调用形态（standalone + 工作目录隔离）。
func TestACMEArgsShapes(t *testing.T) {
	req := ACMEIssueRequest{Domain: "acme.example.com", Email: "ops@example.com"}
	certbotArgs := strings.Join(acmeArgs(acmeToolCertbot, "/tmp/work", req), " ")
	for _, want := range []string{"certonly", "--standalone", "--non-interactive", "--agree-tos",
		"--email ops@example.com", "-d acme.example.com", "--config-dir /tmp/work/config",
		"--work-dir /tmp/work/work", "--logs-dir /tmp/work/logs"} {
		if !strings.Contains(certbotArgs, want) {
			t.Fatalf("certbot 参数缺 %q：%s", want, certbotArgs)
		}
	}
	acmeShArgs := strings.Join(acmeArgs(acmeToolACMESh, "/tmp/work", req), " ")
	for _, want := range []string{"--issue", "-d acme.example.com", "--standalone",
		"--accountemail ops@example.com", "--home /tmp/work"} {
		if !strings.Contains(acmeShArgs, want) {
			t.Fatalf("acme.sh 参数缺 %q：%s", want, acmeShArgs)
		}
	}
}

// assertNoCertFilesIn 断言目录里没有证书/私钥落盘（失败路径不留半成品）。
func assertNoCertFilesIn(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, acmeMarkerSuffix) {
			t.Fatalf("失败路径不应写入文件，发现 %s", name)
		}
	}
}
