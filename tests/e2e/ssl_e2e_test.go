//go:build linux && (amd64 || arm64 || riscv64 || loong64)

package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// certInfo 是方法返回的证书视图（只含公钥信息）。
type certInfo struct {
	Domain            string   `json:"domain"`
	Domains           []string `json:"domains"`
	File              string   `json:"file"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	DaysLeft          int      `json:"days_left"`
	Issuer            string   `json:"issuer"`
	KeyType           string   `json:"key_type"`
	KeyBits           int      `json:"key_bits"`
	ChainLength       int      `json:"chain_length"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	SelfSigned        bool     `json:"self_signed"`
	Source            string   `json:"source"`
	Expired           bool     `json:"expired"`
	ExpiringSoon      bool     `json:"expiring_soon"`
	Error             string   `json:"error,omitempty"`
}

// listResult 是 ssl.list 的结果。
type listResult struct {
	Certs []certInfo `json:"certs"`
	Count int        `json:"count"`
}

// renewResult 是 ssl.renew 的结果。
type renewResult struct {
	certInfo
	Renewed bool `json:"renewed"`
}

// verifyResult 是 ssl.verify 的结果。
type verifyResult struct {
	Reachable   bool   `json:"reachable"`
	Host        string `json:"host"`
	Address     string `json:"address"`
	Matched     bool   `json:"matched"`
	DaysLeft    int    `json:"days_left"`
	Issuer      string `json:"issuer"`
	SelfSigned  bool   `json:"self_signed"`
	ChainLength int    `json:"chain_length"`
	Error       string `json:"error,omitempty"`
}

// TestSSLPluginE2E 用真实插件二进制 + UDS 跑完整证书管理闭环。
func TestSSLPluginE2E(t *testing.T) {
	workspace := t.TempDir()
	binary := buildPlugin(t)
	certDir := filepath.Join(workspace, "certs")
	socket := filepath.Join(workspace, "ssl.sock")

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("监听 UDS 失败: %v", err)
	}
	defer func() { _ = listener.Close() }()
	_ = listener.(*net.UnixListener).SetDeadline(time.Now().Add(120 * time.Second))

	process, stderr := startPlugin(t, binary, socket, certDir)
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("接受插件连接失败: %v (stderr=%s)", err, stderr.String())
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
	handshake(t, conn)

	// --- 1. selfsign：真签发自签证书（额外覆盖 127.0.0.1，供回环探测）---
	selfSignRaw := mustCall(t, conn, "e2e-selfsign", "ssl.selfsign", map[string]any{
		"domain": "test.kore.local", "extra_sans": []string{"127.0.0.1"},
	})
	var created certInfo
	if err := json.Unmarshal([]byte(selfSignRaw), &created); err != nil {
		t.Fatalf("解析 selfsign 结果失败: %v (%s)", err, selfSignRaw)
	}
	if created.Domain != "test.kore.local" || created.DaysLeft != 365 || !created.SelfSigned || created.Source != "self-signed" {
		t.Fatalf("selfsign 结果不符: %s", selfSignRaw)
	}
	if created.KeyType != "rsa" || created.KeyBits != 2048 || created.ChainLength != 1 || created.Expired || created.ExpiringSoon {
		t.Fatalf("selfsign 公钥/链/有效期标记不符: %s", selfSignRaw)
	}
	if len(created.Domains) != 2 || !contains(created.Domains, "test.kore.local") || !contains(created.Domains, "127.0.0.1") {
		t.Fatalf("selfsign domains 不符: %v", created.Domains)
	}
	certFile := filepath.Join(certDir, "test.kore.local.crt")
	keyFile := filepath.Join(certDir, "test.kore.local.key")
	if mode := modeOf(t, certFile); mode != 0o644 {
		t.Fatalf("证书权限=%#o，期望 0644", mode)
	}
	if mode := modeOf(t, keyFile); mode != 0o600 {
		t.Fatalf("私钥权限=%#o，期望 0600", mode)
	}
	if mode := modeOf(t, certDir); mode != 0o700 {
		t.Fatalf("证书目录权限=%#o，期望 0700", mode)
	}
	t.Logf("E2E_SELFSIGN %s", selfSignRaw)

	// --- 2. list：真实扫描目录并解析证书 ---
	listRaw := mustCall(t, conn, "e2e-list", "ssl.list", map[string]any{})
	var listed listResult
	if err := json.Unmarshal([]byte(listRaw), &listed); err != nil {
		t.Fatalf("解析 list 失败: %v (%s)", err, listRaw)
	}
	if listed.Count != 1 {
		t.Fatalf("list.count=%d，期望 1: %s", listed.Count, listRaw)
	}
	entry := listed.Certs[0]
	if entry.Domain != "test.kore.local" || entry.DaysLeft != 365 || entry.File != "test.kore.local.crt" {
		t.Fatalf("list 条目不符: %s", listRaw)
	}
	if entry.FingerprintSHA256 != created.FingerprintSHA256 || entry.NotAfter == "" || entry.Issuer == "" {
		t.Fatalf("list 与 selfsign 口径不一致: %s vs %s", listRaw, selfSignRaw)
	}
	t.Logf("E2E_LIST %s", listRaw)

	// --- 3. 起真实 TLS 服务，用 curl -k 验证证书可用 ---
	address := startTLSServer(t, certFile, keyFile)
	code := curlTLS(t, "https://"+address+"/")
	if code != "200" {
		t.Fatalf("curl 访问自签 HTTPS 服务失败: status=%q", code)
	}
	t.Logf("E2E_CURL url=https://%s/ status=%s", address, code)

	// --- 4. verify：真实 TLS 握手探测，matched 必须是名称校验结果 ---
	verifyRaw := mustCall(t, conn, "e2e-verify", "ssl.verify", map[string]any{"domain": address})
	var verified verifyResult
	if err := json.Unmarshal([]byte(verifyRaw), &verified); err != nil {
		t.Fatalf("解析 verify 失败: %v (%s)", err, verifyRaw)
	}
	if !verified.Reachable || !verified.Matched || verified.Error != "" {
		t.Fatalf("verify 结果不符: %s", verifyRaw)
	}
	if verified.Host != "127.0.0.1" || verified.Address != address || verified.DaysLeft != 365 || !verified.SelfSigned {
		t.Fatalf("verify 元数据不符: %s", verifyRaw)
	}
	t.Logf("E2E_VERIFY %s", verifyRaw)

	// --- 5. import：证书与私钥不匹配必须 E_INVALID ---
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("读取证书失败: %v", err)
	}
	mismatchResp := request(t, conn, "e2e-import-mismatch", "ssl.import", map[string]any{
		"domain": "test.kore.local", "cert_pem": string(certPEM), "key_pem": keyPEMWithoutCert(t),
	})
	if mismatchResp.Error == nil || mismatchResp.Error.Code != "E_INVALID" || !strings.Contains(mismatchResp.Error.Message, "不匹配") {
		t.Fatalf("不匹配私钥应 E_INVALID，得到 %+v result=%s", mismatchResp.Error, mismatchResp.Result)
	}
	t.Logf("E2E_IMPORT_MISMATCH code=%s message=%s", mismatchResp.Error.Code, mismatchResp.Error.Message)

	// --- 6. import：合法证书 + 私钥成功落盘 ---
	importCert, importKey := makePair(t, "import.kore.local", "")
	importRaw := mustCall(t, conn, "e2e-import", "ssl.import", map[string]any{
		"domain": "import.kore.local", "cert_pem": importCert, "key_pem": importKey,
	})
	var imported certInfo
	if err := json.Unmarshal([]byte(importRaw), &imported); err != nil {
		t.Fatalf("解析 import 失败: %v (%s)", err, importRaw)
	}
	if imported.Domain != "import.kore.local" || imported.File != "import.kore.local.crt" || imported.ChainLength != 1 {
		t.Fatalf("import 结果不符: %s", importRaw)
	}
	if mode := modeOf(t, filepath.Join(certDir, "import.kore.local.key")); mode != 0o600 {
		t.Fatalf("导入私钥权限=%#o，期望 0600", mode)
	}
	t.Logf("E2E_IMPORT %s", importRaw)

	// --- 7. renew：自签证书重新签发成功 ---
	renewRaw := mustCall(t, conn, "e2e-renew", "ssl.renew", map[string]any{"domain": "test.kore.local", "days": 30})
	var renewed renewResult
	if err := json.Unmarshal([]byte(renewRaw), &renewed); err != nil {
		t.Fatalf("解析 renew 失败: %v (%s)", err, renewRaw)
	}
	if !renewed.Renewed || !renewed.SelfSigned || renewed.DaysLeft != 30 {
		t.Fatalf("自签续期结果不符: %s", renewRaw)
	}
	if renewed.FingerprintSHA256 == created.FingerprintSHA256 {
		t.Fatalf("续期后指纹应变化: %s", renewRaw)
	}
	if mode := modeOf(t, keyFile); mode != 0o600 {
		t.Fatalf("续期后私钥权限=%#o，期望 0600", mode)
	}
	if !contains(renewed.Domains, "127.0.0.1") {
		t.Fatalf("续期应保留附加 SAN 127.0.0.1: %v", renewed.Domains)
	}
	t.Logf("E2E_RENEW_SELFSIGNED %s", renewRaw)

	// 续期后同一 TLS 服务仍可用新证书完成匹配探测（服务端已换成新文件内容）。
	renewedServer := startTLSServer(t, certFile, keyFile)
	reVerified := mustCall(t, conn, "e2e-verify-renewed", "ssl.verify", map[string]any{"domain": renewedServer})
	var renewedVerify verifyResult
	if err := json.Unmarshal([]byte(reVerified), &renewedVerify); err != nil {
		t.Fatalf("解析续期后 verify 失败: %v", err)
	}
	if !renewedVerify.Reachable || !renewedVerify.Matched || renewedVerify.DaysLeft != 30 {
		t.Fatalf("续期后证书探测不符: %s", reVerified)
	}
	t.Logf("E2E_VERIFY_RENEWED %s", reVerified)

	// --- 8. renew：ACME 证书如实返回 E_UNSUPPORTED，且不改文件 ---
	acmeCert, acmeKey := makePair(t, "acme.kore.local", "Let's Encrypt R3")
	mustCall(t, conn, "e2e-import-acme", "ssl.import", map[string]any{
		"domain": "acme.kore.local", "cert_pem": acmeCert, "key_pem": acmeKey,
	})
	acmeBefore, err := os.ReadFile(filepath.Join(certDir, "acme.kore.local.crt"))
	if err != nil {
		t.Fatalf("读取 ACME 证书失败: %v", err)
	}
	acmeResp := request(t, conn, "e2e-renew-acme", "ssl.renew", map[string]any{"domain": "acme.kore.local"})
	if acmeResp.Error == nil || acmeResp.Error.Code != "E_UNSUPPORTED" {
		t.Fatalf("ACME 续期应 E_UNSUPPORTED，得到 %+v", acmeResp.Error)
	}
	if !strings.Contains(acmeResp.Error.Message, "ACME 客户端") || !strings.Contains(acmeResp.Error.Message, "v1.1") {
		t.Fatalf("ACME 续期说明不完整: %q", acmeResp.Error.Message)
	}
	acmeAfter, err := os.ReadFile(filepath.Join(certDir, "acme.kore.local.crt"))
	if err != nil || string(acmeBefore) != string(acmeAfter) {
		t.Fatal("ACME 续期失败不应改动原证书")
	}
	t.Logf("E2E_RENEW_ACME code=%s message=%s", acmeResp.Error.Code, acmeResp.Error.Message)

	// --- 9. renew：企业 CA 证书同样如实拒绝 ---
	corpCert, corpKey := makePair(t, "corp.kore.local", "Internal CA")
	mustCall(t, conn, "e2e-import-corp", "ssl.import", map[string]any{
		"domain": "corp.kore.local", "cert_pem": corpCert, "key_pem": corpKey,
	})
	corpResp := request(t, conn, "e2e-renew-corp", "ssl.renew", map[string]any{"domain": "corp.kore.local"})
	if corpResp.Error == nil || corpResp.Error.Code != "E_UNSUPPORTED" || !strings.Contains(corpResp.Error.Message, "不是自签") {
		t.Fatalf("企业 CA 证书续期应 E_UNSUPPORTED/不是自签，得到 %+v", corpResp.Error)
	}
	t.Logf("E2E_RENEW_NONSELF code=%s message=%s", corpResp.Error.Code, corpResp.Error.Message)

	// --- 10. 最终 list：4 张证书（自签续期后仍只有 1 份）---
	finalRaw := mustCall(t, conn, "e2e-list-final", "ssl.list", map[string]any{})
	var final listResult
	if err := json.Unmarshal([]byte(finalRaw), &final); err != nil {
		t.Fatalf("解析最终 list 失败: %v", err)
	}
	if final.Count != 4 {
		t.Fatalf("最终 list.count=%d，期望 4: %s", final.Count, finalRaw)
	}
	t.Logf("E2E_LIST_FINAL %s", finalRaw)

	// --- 11. shutdown：优雅退出，退出码 0 ---
	shutdownResp := request(t, conn, "e2e-shutdown", "kore.shutdown", map[string]any{})
	if shutdownResp.Error != nil {
		t.Fatalf("shutdown 失败: %+v", shutdownResp.Error)
	}
	waitExit(t, process)
	if strings.Contains(stderr.String(), "PRIVATE KEY") {
		t.Fatalf("插件 stderr 泄漏私钥: %s", stderr.String())
	}
	t.Logf("E2E_SHUTDOWN exit=0 stderr=%q", strings.TrimSpace(stderr.String()))
}

// startTLSServer 用落盘证书起真实 HTTPS 服务，返回监听地址。
func startTLSServer(t *testing.T, certFile, keyFile string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("加载证书对失败: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 TLS 端口失败: %v", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("kore-ssl-e2e-ok"))
	})}
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// curlTLS 用 curl -k 访问自签 HTTPS 服务并返回状态码；curl 不可用时回退 Go 客户端。
func curlTLS(t *testing.T, url string) string {
	t.Helper()
	path, err := exec.LookPath("curl")
	if err != nil {
		t.Logf("本机无 curl，回退 Go HTTP 客户端")
		return goTLSGet(t, url)
	}
	out, runErr := exec.Command(path, "-k", "-sS", "--max-time", "5", "-o", os.DevNull, "-w", "%{http_code}", url).CombinedOutput()
	if runErr != nil {
		t.Fatalf("curl 失败: %v output=%s", runErr, out)
	}
	return strings.TrimSpace(string(out))
}

// goTLSGet 是 curl 缺失时的回退：跳过证书校验的 HTTPS GET。
func goTLSGet(t *testing.T, url string) string {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   5 * time.Second,
	}
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("HTTPS GET 失败: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return fmt.Sprintf("%d", response.StatusCode)
}

// contains 判断字符串切片是否包含目标值。
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
