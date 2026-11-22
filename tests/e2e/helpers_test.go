//go:build linux && (amd64 || arm64 || riscv64 || loong64)

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// buildPlugin 构建真实插件二进制到临时目录。
func buildPlugin(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "ssl-plugin")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("构建插件失败: %v\n%s", err, out)
	}
	return binary
}

// startPlugin 以协议环境变量启动插件进程；stderr 收集起来便于失败时定位。
func startPlugin(t *testing.T, binary, socket, certDir string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	stderr := &bytes.Buffer{}
	process := exec.Command(binary)
	process.Env = append(os.Environ(),
		"KORE_PLUGIN_SOCK="+socket,
		"KORE_PLUGIN_ID=ssl",
		"KORE_PLUGIN_TOKEN=e2e-token",
		"KORE_SSL_CERT_DIR="+certDir,
	)
	process.Stdout = io.Discard
	process.Stderr = stderr
	if err := process.Start(); err != nil {
		t.Fatalf("启动插件失败: %v", err)
	}
	t.Cleanup(func() {
		if process.ProcessState == nil {
			_ = process.Process.Kill()
			_, _ = process.Process.Wait()
		}
	})
	return process, stderr
}

// handshake 读 kore.hello 并回 ok 响应。
func handshake(t *testing.T, conn net.Conn) {
	t.Helper()
	request := readRequest(t, conn)
	if request.Method != "kore.hello" {
		t.Fatalf("首帧应为 kore.hello，实际 %s", request.Method)
	}
	response := &pluginapi.Response{
		Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID,
		Result: json.RawMessage(`{"ok":true,"protocol":"kore.plugin.v1"}`),
	}
	if err := pluginapi.WriteJSON(conn, response); err != nil {
		t.Fatalf("回写 hello 失败: %v", err)
	}
}

// request 发送一次方法调用并读回响应。
func request(t *testing.T, conn net.Conn, id, method string, params any) *pluginapi.Response {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("序列化 %s 参数失败: %v", method, err)
	}
	req := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: id, ReqID: "r-" + id, Method: method, Params: raw,
	}
	if err := pluginapi.WriteJSON(conn, req); err != nil {
		t.Fatalf("发送 %s 失败: %v", method, err)
	}
	return readResponse(t, conn)
}

// mustCall 要求调用成功并返回 result 原文。
func mustCall(t *testing.T, conn net.Conn, id, method string, params any) string {
	t.Helper()
	response := request(t, conn, id, method, params)
	if response.Error != nil {
		t.Fatalf("%s 失败: %s/%s", method, response.Error.Code, response.Error.Message)
	}
	return string(response.Result)
}

// readRequest 读下一帧并断言是 request。
func readRequest(t *testing.T, conn net.Conn) *pluginapi.Request {
	t.Helper()
	env, err := pluginapi.DecodeFrame(readPayload(t, conn))
	if err != nil {
		t.Fatalf("解码请求失败: %v", err)
	}
	request, ok := env.(*pluginapi.Request)
	if !ok {
		t.Fatalf("期望 request，实际 %T", env)
	}
	return request
}

// readResponse 读下一帧并断言是 response。
func readResponse(t *testing.T, conn net.Conn) *pluginapi.Response {
	t.Helper()
	env, err := pluginapi.DecodeFrame(readPayload(t, conn))
	if err != nil {
		t.Fatalf("解码响应失败: %v", err)
	}
	response, ok := env.(*pluginapi.Response)
	if !ok {
		t.Fatalf("期望 response，实际 %T", env)
	}
	return response
}

// readPayload 读一整帧。
func readPayload(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	return payload
}

// waitExit 等待插件进程退出并断言退出码 0。
func waitExit(t *testing.T, process *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("插件退出异常: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("插件未在 10s 内退出")
	}
}

// makePair 在测试进程内生成一张证书与私钥；issuerCN 非空时只改 issuer 名，
// 用于构造"非自签"证书以验证续期拒绝分支（不冒充真实 CA）。
func makePair(t *testing.T, domain, issuerCN string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(20261122),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	parent := template
	if issuerCN != "" {
		parent = &x509.Certificate{Subject: pkix.Name{CommonName: issuerCN}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("编码测试私钥失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// keyPEMWithoutCert 返回一个与目标证书不匹配的私钥 PEM。
func keyPEMWithoutCert(t *testing.T) string {
	t.Helper()
	_, keyPEM := makePair(t, "unrelated.kore.local", "")
	return keyPEM
}

// modeOf 返回文件权限位。
func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s 失败: %v", path, err)
	}
	return info.Mode().Perm()
}
