package certs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ACME 支持是"探测 + 显式调用外部客户端"的骨架，不含内置 ACME 协议实现：
//
//   - 插件不联网、不内置 ACME 客户端（G-10 无联网 / G-17 依赖白名单）；
//   - 只在用户显式 confirm=true 时调用本机已安装的 certbot / acme.sh；
//   - 私钥内容绝不进返回值，只给路径与证书元数据；
//   - 未安装客户端时如实返回 E_UNSUPPORTED + hint，不假装成功。
const (
	// acmeToolCertbot / acmeToolACMESh 是支持的外部客户端标识。
	acmeToolCertbot = "certbot"
	acmeToolACMESh  = "acme.sh"
	// acmeStatusTimeout 是版本探测预算；acmeIssueTimeout 是签发预算（联网 + 校验可能较慢）。
	acmeStatusTimeout = 5 * time.Second
	acmeIssueTimeout  = 300 * time.Second
	// acmeOutputTailMax 是返回给调用方的工具输出尾部上限（字符），避免把整段日志塞进响应。
	acmeOutputTailMax = 1200
	// acmeDirName 是外部客户端工作目录（账号、证书、日志都落在这里，0700）。
	acmeDirName = "acme"
)

// certbotFixedPaths / acmeShFixedPaths 是 PATH 之外还要试的常见安装位置
// （snap 安装的 certbot 不一定在服务的 PATH 里；acme.sh 默认装在用户家目录）。
var (
	certbotFixedPaths = []string{"/usr/bin/certbot", "/usr/local/bin/certbot", "/snap/bin/certbot"}
	acmeShFixedPaths  = []string{"/usr/local/bin/acme.sh", "/usr/bin/acme.sh", "/root/.acme.sh/acme.sh"}
	// acmeEmailRE 是邮箱的宽松校验：只要求有本地部分、@、域名部分，避免因严格正则误拒合法地址。
	acmeEmailRE = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	// certbotVersionRE / acmeShVersionRE 从 --version 输出里提取版本号。
	certbotVersionRE = regexp.MustCompile(`(?i)certbot\s+([0-9][0-9A-Za-z.\-]*)`)
	acmeShVersionRE  = regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+`)
)

// ACMEStatus 是 ssl.acme.status 的结果：本机是否有可用的 ACME 客户端。
// 三字段恒返回（不可用时 available=false、tool/version 为空），缺工具不是错误。
type ACMEStatus struct {
	Available bool   `json:"available"`
	Tool      string `json:"tool"`
	Version   string `json:"version"`
}

// ACMEIssueRequest 是 ssl.acme.issue 的入参。
// Confirm 必须是 true——ACME 会联网向公共 CA 申请证书，G-10 要求由用户显式触发。
type ACMEIssueRequest struct {
	Domain  string `json:"domain"`
	Email   string `json:"email"`
	Confirm bool   `json:"confirm"`
}

// ACMEIssueResult 是签发结果：只含路径与证书元数据，绝不含私钥内容。
type ACMEIssueResult struct {
	Issued      bool   `json:"issued"`
	Imported    bool   `json:"imported"`
	Tool        string `json:"tool"`
	Domain      string `json:"domain"`
	CertPath    string `json:"cert_path"`
	KeyPath     string `json:"key_path"`
	NotAfter    string `json:"not_after,omitempty"`
	DaysLeft    int    `json:"days_left,omitempty"`
	Fingerprint string `json:"fingerprint_sha256,omitempty"`
	OutputTail  string `json:"output_tail,omitempty"`
}

// acmeToolInfo 是本机探测到的可用客户端。
type acmeToolInfo struct {
	name    string
	path    string
	version string
}

// ACMEStatus 探测本机 certbot / acme.sh：先 certbot 后 acme.sh，找到即可用即返回。
// 探测只跑 `<tool> --version`，不联网、不改任何文件。
func (s *Service) ACMEStatus() (*ACMEStatus, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	tool, ok := s.detectACMETool()
	if !ok {
		return &ACMEStatus{Available: false}, nil
	}
	return &ACMEStatus{Available: true, Tool: tool.name, Version: tool.version}, nil
}

// ACMEIssue 调用本机 ACME 客户端申请证书，并把签出的证书导入插件证书目录。
//
// 前置条件按顺序校验：显式确认 → 域名/邮箱合法 → 客户端可用。
// 任何一步不满足都返回结构化错误（E_INVALID / E_UNSUPPORTED），不落任何文件。
func (s *Service) ACMEIssue(req ACMEIssueRequest) (*ACMEIssueResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	if perr := validateDomain(req.Domain); perr != nil {
		return nil, perr
	}
	if perr := validateACMEEmail(req.Email); perr != nil {
		return nil, perr
	}
	if !req.Confirm {
		return nil, newCertHintError(codeInvalid,
			"ACME 签发会联网向公共 CA 申请证书，必须显式确认：params.confirm=true",
			"确认域名解析与 80 端口可达后再调用；不确认时可用 ssl.selfsign / ssl.import")
	}
	tool, ok := s.detectACMETool()
	if !ok {
		return nil, newCertHintError(codeUnsupported,
			"本机未找到可用的 ACME 客户端（certbot / acme.sh）",
			"安装 certbot 或 acme.sh 后重试；无联网环境请继续用 ssl.selfsign / ssl.import")
	}
	workDir := filepath.Join(s.store.dir, acmeDirName, tool.name)
	if err := ensurePrivateDir(workDir); err != nil {
		return nil, internalErr("准备 ACME 工作目录失败: " + err.Error())
	}
	output, runErr := s.runACMETool(tool, workDir, req)
	tail := tailString(output, acmeOutputTailMax)
	if runErr != nil {
		return nil, newCertHintError(codeUpstream,
			fmt.Sprintf("%s 执行失败：%v", tool.name, runErr),
			tail)
	}
	certPEM, keyPEM, certPath, keyPath, pickErr := pickIssuedPEM(tool, workDir, req.Domain)
	if pickErr != nil {
		return nil, newCertHintError(codeUpstream,
			fmt.Sprintf("%s 报告成功，但未在预期路径找到证书：%v", tool.name, pickErr),
			tail)
	}
	info, cerr := s.Import(ImportRequest{Domain: req.Domain, CertPEM: string(certPEM), KeyPEM: string(keyPEM)})
	if cerr != nil {
		return nil, newCertHintError(cerr.Code, "ACME 证书导入失败："+cerr.Message,
			"证书已签出但未纳入管理："+certPath+" / "+keyPath)
	}
	markerErr := s.store.writeACMEMarker(info.File, tool.name, nowOr(s.now))
	if markerErr != nil {
		// 标记写不进去等于"续期时会把它当自签重签"，必须如实报错而不是留个半状态。
		return nil, internalErr("写入 ACME 归属标记失败（证书已导入，但续期归属不可信）: " + markerErr.Error())
	}
	managedKeyPath := filepath.Join(s.store.dir, trimCertSuffix(info.File)+keySuffix)
	return &ACMEIssueResult{
		Issued: true, Imported: true, Tool: tool.name, Domain: req.Domain,
		CertPath: s.store.certAbsPath(info.File), KeyPath: managedKeyPath,
		NotAfter: info.NotAfter, DaysLeft: info.DaysLeft, Fingerprint: info.FingerprintSHA256,
		OutputTail: tail,
	}, nil
}

// validateACMEEmail 校验邮箱：ACME 注册账号必须给一个可用的联系邮箱。
func validateACMEEmail(email string) *CertError {
	value := strings.TrimSpace(email)
	if value == "" {
		return invalidParam("缺少必填字段 email（ACME 账号联系邮箱）")
	}
	if len(value) > 254 || !acmeEmailRE.MatchString(value) {
		return invalidParam("email 非法：" + value)
	}
	return nil
}

// detectACMETool 探测可用客户端：certbot 优先（续期生态更成熟），其次 acme.sh。
// 二进制存在但 --version 跑不通（损坏/权限/动态库缺失）时继续试下一个，不误报可用。
// acmeTools 非 nil 时只探测显式给出的工具路径（测试用），不做 PATH 搜索。
func (s *Service) detectACMETool() (acmeToolInfo, bool) {
	candidates := []struct {
		name  string
		fixed []string
	}{
		{acmeToolCertbot, certbotFixedPaths},
		{acmeToolACMESh, acmeShFixedPaths},
	}
	for _, candidate := range candidates {
		path := s.resolveToolPath(candidate.name, candidate.fixed)
		if path == "" {
			continue
		}
		version, err := toolVersion(path)
		if err != nil {
			continue
		}
		return acmeToolInfo{name: candidate.name, path: path, version: version}, true
	}
	return acmeToolInfo{}, false
}

// resolveToolPath 依次在 PATH、固定安装位置与用户家目录（acme.sh）里找可执行文件。
// acmeTools 非 nil 时只认显式配置的路径（测试注入），保证探测结果可确定复现。
func (s *Service) resolveToolPath(name string, fixed []string) string {
	if s.acmeTools != nil {
		return firstExecutable([]string{s.acmeTools[name]})
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	paths := append([]string(nil), fixed...)
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".acme.sh", "acme.sh"))
	}
	return firstExecutable(paths)
}

// firstExecutable 返回列表里第一个存在且带可执行位的文件路径；没有则返回空串。
func firstExecutable(paths []string) string {
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return path
	}
	return ""
}

// toolVersion 跑 `<tool> --version` 并提取版本号；输出合并 stdout+stderr。
// 请求级超时用 context.WithTimeout，defer cancel 保证不泄漏（G-19）。
func toolVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), acmeStatusTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return "", err
	}
	return parseToolVersion(string(output)), nil
}

// parseToolVersion 从版本输出里取版本号：certbot 取 "certbot X" 的 X；
// acme.sh 取 vX.Y.Z；统一去掉前导 v，保持纯数字形态。
// 都匹配不上时取最后一行非空文本（保留原始形态，不硬造格式）。
func parseToolVersion(output string) string {
	if match := certbotVersionRE.FindStringSubmatch(output); match != nil {
		return strings.TrimPrefix(match[1], "v")
	}
	if match := acmeShVersionRE.FindString(output); match != "" {
		return strings.TrimPrefix(match, "v")
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}

// runACMETool 组装并执行外部客户端命令；返回合并输出与执行错误。
func (s *Service) runACMETool(tool acmeToolInfo, workDir string, req ACMEIssueRequest) (string, error) {
	args := acmeArgs(tool.name, workDir, req)
	ctx, cancel := context.WithTimeout(context.Background(), acmeIssueTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, tool.path, args...).CombinedOutput()
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return string(output), fmt.Errorf("超时（%s 内未完成）", acmeIssueTimeout)
	}
	return string(output), err
}

// acmeArgs 按客户端拼参数：都用 standalone（自管 80 端口），把状态与日志限制在 workDir 内，
// 不写 /etc/letsencrypt 或家目录，避免污染系统目录。
func acmeArgs(tool, workDir string, req ACMEIssueRequest) []string {
	if tool == acmeToolCertbot {
		return []string{
			"certonly", "--standalone", "--non-interactive", "--agree-tos",
			"--email", req.Email, "-d", req.Domain,
			"--config-dir", filepath.Join(workDir, "config"),
			"--work-dir", filepath.Join(workDir, "work"),
			"--logs-dir", filepath.Join(workDir, "logs"),
		}
	}
	return []string{
		"--issue", "-d", req.Domain, "--standalone",
		"--accountemail", req.Email, "--home", workDir,
	}
}

// pickIssuedPEM 在各客户端的标准输出位置读取证书与私钥（只读文件，不打印内容）。
func pickIssuedPEM(tool acmeToolInfo, workDir, domain string) (certPEM, keyPEM []byte, certPath, keyPath string, err error) {
	candidates := issuedPathCandidates(tool.name, workDir, domain)
	for _, candidate := range candidates {
		certData, certErr := os.ReadFile(candidate.cert)
		if certErr != nil {
			continue
		}
		keyData, keyErr := os.ReadFile(candidate.key)
		if keyErr != nil {
			continue
		}
		return certData, keyData, candidate.cert, candidate.key, nil
	}
	return nil, nil, "", "", fmt.Errorf("已检查 %d 个候选路径（如 %s）", len(candidates), candidates[0].cert)
}

// issuedPaths 是一组"证书 + 私钥"候选路径。
type issuedPaths struct{ cert, key string }

// issuedPathCandidates 列出客户端可能落盘的证书/私钥路径。
// certbot 用 live/<domain>/；acme.sh 的 ecc / rsa 两个目录都要看。
func issuedPathCandidates(tool, workDir, domain string) []issuedPaths {
	if tool == acmeToolCertbot {
		live := filepath.Join(workDir, "config", "live", domain)
		return []issuedPaths{
			{cert: filepath.Join(live, "fullchain.pem"), key: filepath.Join(live, "privkey.pem")},
			{cert: filepath.Join(live, "cert.pem"), key: filepath.Join(live, "privkey.pem")},
		}
	}
	return []issuedPaths{
		{cert: filepath.Join(workDir, domain+"_ecc", "fullchain.cer"), key: filepath.Join(workDir, domain+"_ecc", domain+".key")},
		{cert: filepath.Join(workDir, domain, "fullchain.cer"), key: filepath.Join(workDir, domain, domain+".key")},
	}
}

// tailString 取输出尾部（按字符数），用于把工具报错回传给前端而不塞整段日志。
func tailString(output string, max int) string {
	trimmed := strings.TrimSpace(output)
	if len(trimmed) <= max {
		return trimmed
	}
	return "…" + trimmed[len(trimmed)-max:]
}

// ensurePrivateDir 创建 0700 目录（ACME 工作目录里有账号密钥，不能给组/其他用户读）。
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	return os.Chmod(dir, dirMode)
}

// writeACMEMarker 写 <base>.acme 归属标记：让 ssl.renew 把这张证书认成 ACME 托管，
// 不会当成自签证书重签。标记内容只有客户端名与时间，不含任何密钥材料。
func (s *certStore) writeACMEMarker(certFileName, tool string, now time.Time) error {
	base := trimCertSuffix(certFileName)
	marker := filepath.Join(s.dir, base+acmeMarkerSuffix)
	content := fmt.Sprintf("tool=%s\nissued_at=%s\n", tool, now.UTC().Format(time.RFC3339))
	if err := atomicWriteFile(marker, []byte(content), certFileMode); err != nil {
		return err
	}
	return nil
}
