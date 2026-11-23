package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// testConfig 构造握手与会话循环共用的一致配置（不依赖环境变量）。
func testConfig() config {
	return config{
		id: "ssl", version: "0.5.0", requiresKore: ">=0.1.0 <0.2.0",
		capabilities: []string{"system:admin"}, startedAt: time.Now(),
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestService(t *testing.T) *certs.Service {
	t.Helper()
	return certs.NewService(certs.Options{Dir: t.TempDir()})
}

func readFrame(t *testing.T, conn net.Conn) interface{} {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		t.Fatalf("解码帧失败: %v", err)
	}
	return env
}

func readRequest(t *testing.T, conn net.Conn) *pluginapi.Request {
	t.Helper()
	env := readFrame(t, conn)
	request, ok := env.(*pluginapi.Request)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 request", env)
	}
	return request
}

func readResponse(t *testing.T, conn net.Conn) *pluginapi.Response {
	t.Helper()
	env := readFrame(t, conn)
	response, ok := env.(*pluginapi.Response)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 response", env)
	}
	return response
}

func writeResponse(t *testing.T, conn net.Conn, id, reqID string, result json.RawMessage) {
	t.Helper()
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: id, ReqID: reqID, Result: result}
	if err := pluginapi.WriteJSON(conn, response); err != nil {
		t.Fatalf("写响应失败: %v", err)
	}
}

// TestHandshake 校验 hello 首帧字段与三步握手。
func TestHandshake(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := make(chan error, 1)
	go func() { done <- handshake(pluginConn, testConfig()); _ = pluginConn.Close() }()

	request := readRequest(t, kernelConn)
	if request.Method != helloMethod {
		t.Fatalf("首帧方法=%q，期望 %q", request.Method, helloMethod)
	}
	var params helloParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		t.Fatalf("解析 hello 参数失败: %v", err)
	}
	if params.PluginID != "ssl" || params.ID != "ssl" {
		t.Fatalf("plugin_id/id=%q/%q，期望都是 ssl", params.PluginID, params.ID)
	}
	if params.Protocol != pluginapi.Protocol || params.Version != testConfig().version {
		t.Fatalf("protocol/version=%q/%q 不符合 §5", params.Protocol, params.Version)
	}
	if params.PID != os.Getpid() {
		t.Fatalf("pid=%d，期望 %d", params.PID, os.Getpid())
	}
	result, err := json.Marshal(helloResult{OK: true, Protocol: pluginapi.Protocol})
	if err != nil {
		t.Fatalf("序列化握手响应失败: %v", err)
	}
	writeResponse(t, kernelConn, request.ID, request.ReqID, result)
	if err := <-done; err != nil {
		t.Fatalf("握手返回错误: %v", err)
	}
}

// TestDispatchMethods 校验真实方法在协议层的成功/失败分支。
func TestDispatchMethods(t *testing.T) {
	svc := newTestService(t)
	cfg := testConfig()
	cases := []struct {
		name   string
		method string
		params json.RawMessage
		wantOK bool
	}{
		{"ping", "kore.ping", nil, true},
		{"list-empty", "ssl.list", nil, true},
		{"selfsign", "ssl.selfsign", json.RawMessage(`{"domain":"example.com","days":30}`), true},
		{"list-after-selfsign", "ssl.list", nil, true},
		{"renew-selfsigned", "ssl.renew", json.RawMessage(`{"domain":"example.com"}`), true},
		{"verify-unreachable", "ssl.verify", json.RawMessage(`{"domain":"127.0.0.1:1"}`), true},
		{"expiring-all", "ssl.expiring", nil, true},
		{"expiring-window", "ssl.expiring", json.RawMessage(`{"days":7}`), true},
		{"expiring-bad-window", "ssl.expiring", json.RawMessage(`{"days":0.5}`), false},
		{"renew-set", "ssl.renew.set", json.RawMessage(`{"name":"example.com"}`), true},
		{"renew-set-unknown", "ssl.renew.set", json.RawMessage(`{"name":"absent.kore.local"}`), false},
		{"renew-due-window", "ssl.renew", json.RawMessage(`{"domain":"example.com","days_before":1}`), true},
		{"bind-set", "ssl.bind.set", json.RawMessage(`{"cert":"example.com","site":"www.example.com"}`), true},
		{"bind-list", "ssl.bind.list", nil, true},
		{"bind-set-unknown-cert", "ssl.bind.set", json.RawMessage(`{"cert":"absent.kore.local","site":"www.kore.local"}`), false},
		{"bind-remove", "ssl.bind.remove", json.RawMessage(`{"cert":"example.com"}`), true},
		{"bind-remove-missing", "ssl.bind.remove", json.RawMessage(`{"cert":"example.com"}`), false},
		{"https-status-unreachable", "ssl.https.status", json.RawMessage(`{"domain":"127.0.0.1","http_port":1,"https_port":1}`), true},
		{"https-status-bad-port", "ssl.https.status", json.RawMessage(`{"domain":"example.com","http_port":70000}`), false},
		{"acme-status", "ssl.acme.status", nil, true},
		{"acme-issue-needs-confirm", "ssl.acme.issue", json.RawMessage(`{"domain":"example.com","email":"ops@example.com"}`), false},
		{"issue-unsupported", "ssl.issue", json.RawMessage(`{"domain":"example.com"}`), false},
		{"selfsign-bad-domain", "ssl.selfsign", json.RawMessage(`{"domain":"BAD"}`), false},
		{"import-missing-key", "ssl.import", json.RawMessage(`{"domain":"example.com","cert_pem":"x"}`), false},
		{"verify-bad-target", "ssl.verify", json.RawMessage(`{"domain":"https://example.com"}`), false},
		{"unknown-method", "ssl.nope", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pluginapi.Request{Type: pluginapi.TypeRequest, ID: "id", ReqID: "r", Method: tc.method, Params: tc.params}
			resp, shutdown := dispatch(req, cfg, svc, testLogger())
			if shutdown {
				t.Fatalf("%s 不应触发 shutdown", tc.method)
			}
			if tc.wantOK && resp.Error != nil {
				t.Fatalf("%s 期望成功，得到错误 %v", tc.method, resp.Error)
			}
			if !tc.wantOK && resp.Error == nil {
				t.Fatalf("%s 期望错误，得到成功", tc.method)
			}
			if tc.wantOK && len(resp.Result) == 0 {
				t.Fatalf("%s 成功但没有结果", tc.method)
			}
			if !tc.wantOK && resp.Result != nil {
				t.Fatalf("%s 出错时不应带结果", tc.method)
			}
		})
	}
}

// TestDispatchRenewACMEUnsupported 校验 ACME 证书续期返回 E_UNSUPPORTED 而不是假成功。
func TestDispatchRenewACMEUnsupported(t *testing.T) {
	svc := newTestService(t)
	acme := testACMEIssuedPair(t)
	if _, perr := svc.Import(certs.ImportRequest{
		Domain: "acme.example.com", CertPEM: acme.certPEM, KeyPEM: acme.keyPEM,
	}); perr != nil {
		t.Fatalf("导入 ACME 证书失败: %v", perr)
	}
	req := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id", ReqID: "r", Method: "ssl.renew",
		Params: json.RawMessage(`{"domain":"acme.example.com"}`),
	}
	resp, _ := dispatch(req, testConfig(), svc, testLogger())
	if resp.Error == nil || resp.Error.Code != pluginapi.E_UNSUPPORTED {
		t.Fatalf("ACME 续期应 E_UNSUPPORTED，得到 %+v", resp.Error)
	}
}

// TestDispatchShutdown 校验 kore.shutdown 返回 shutdown 信号。
func TestDispatchShutdown(t *testing.T) {
	req := &pluginapi.Request{Type: pluginapi.TypeRequest, ID: "id", ReqID: "r", Method: "kore.shutdown"}
	_, shutdown := dispatch(req, testConfig(), newTestService(t), testLogger())
	if !shutdown {
		t.Fatal("kore.shutdown 应返回 shutdown=true")
	}
}

// testPair 是测试用的证书 + 私钥 PEM 组合。
type testPair struct {
	certPEM string
	keyPEM  string
}

// testACMEIssuedPair 造一张 issuer 为 Let's Encrypt R3 的证书（自签结构、非自签 issuer），
// 用于验证 renew 的 ACME 识别分支：真实 ACME 证书不可能由本地签出，这里只验证归属判定。
func testACMEIssuedPair(t *testing.T) testPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: "acme.example.com"},
		DNSNames:              []string{"acme.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	parent := &x509.Certificate{Subject: pkix.Name{CommonName: "Let's Encrypt R3"}}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成 ACME 风格测试证书失败: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("编码测试私钥失败: %v", err)
	}
	return testPair{
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}
}
