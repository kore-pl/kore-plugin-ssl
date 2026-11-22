package main

import (
	"encoding/json"
	"io"
	"log/slog"
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
		id: "ssl", version: "0.1.0", requiresKore: ">=0.1.0 <0.2.0",
		capabilities: []string{"system:admin"}, startedAt: time.Now(),
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
	if params.Protocol != pluginapi.Protocol || params.Version != "0.1.0" {
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

// TestDispatchMethods 校验三个 ssl 方法与 ping/shutdown 的结构化结果。
func TestDispatchMethods(t *testing.T) {
	svc := certs.NewService(nil)
	cfg := testConfig()
	cases := []struct {
		method string
		params json.RawMessage
		wantOK bool
	}{
		{"kore.ping", nil, true},
		{"ssl.list", nil, true},
		{"ssl.issue", json.RawMessage(`{"domain":"example.com"}`), true},
		{"ssl.renew", json.RawMessage(`{"domain":"example.com"}`), true},
		{"ssl.issue", json.RawMessage(`{"domain":"BAD"}`), false},
		{"ssl.nope", nil, false},
	}
	for _, tc := range cases {
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
	}
}

// TestDispatchShutdown 校验 kore.shutdown 返回 shutdown 信号。
func TestDispatchShutdown(t *testing.T) {
	req := &pluginapi.Request{Type: pluginapi.TypeRequest, ID: "id", ReqID: "r", Method: "kore.shutdown"}
	_, shutdown := dispatch(req, testConfig(), certs.NewService(nil), testLogger())
	if !shutdown {
		t.Fatal("kore.shutdown 应返回 shutdown=true")
	}
}
