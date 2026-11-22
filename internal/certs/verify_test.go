package certs

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestVerifySelfSignedLoopback 对真实 TLS 自签服务做握手探测：字段齐全且 matched=true。
func TestVerifySelfSignedLoopback(t *testing.T) {
	svc, dir := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "127.0.0.1"}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	address := serveTestTLS(t, readTestFile(t, dir+"/127.0.0.1.crt"), readTestFile(t, dir+"/127.0.0.1.key"))

	result, perr := svc.Verify(VerifyRequest{Domain: address})
	if perr != nil {
		t.Fatalf("探测失败: %v", perr)
	}
	if !result.Reachable || !result.Matched || result.Error != "" {
		t.Fatalf("探测结果不符: %+v", result)
	}
	if result.Host != "127.0.0.1" || result.Address != address {
		t.Fatalf("host/address 不符: %+v", result)
	}
	if result.DaysLeft != 365 || !result.SelfSigned || result.ChainLength != 1 {
		t.Fatalf("有效期/自签/链长不符: %+v", result)
	}
	if result.Issuer == "" || result.NotAfter == "" || len(result.FingerprintSHA256) != 64 {
		t.Fatalf("元数据缺失: %+v", result)
	}
}

// TestVerifyNameMismatch 校验 matched 是真实名称校验结果：证书不覆盖目标时 reachable 但 matched=false。
func TestVerifyNameMismatch(t *testing.T) {
	svc, dir := testService(t)
	// 证书签给 127.0.0.2，服务却监听在 127.0.0.1：握手能通，名称不匹配。
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "127.0.0.2"}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	address := serveTestTLS(t, readTestFile(t, dir+"/127.0.0.2.crt"), readTestFile(t, dir+"/127.0.0.2.key"))

	result, perr := svc.Verify(VerifyRequest{Domain: address})
	if perr != nil {
		t.Fatalf("探测不应报协议错误: %v", perr)
	}
	if !result.Reachable {
		t.Fatalf("握手应成功: %+v", result)
	}
	if result.Matched {
		t.Fatalf("名称不匹配时 matched 不应为 true: %+v", result)
	}
	if result.Error == "" || !strings.Contains(result.Error, "valid for 127.0.0.2") {
		t.Fatalf("应带名称不匹配说明，得到 %q", result.Error)
	}
}

// TestVerifyUnreachable 校验连接失败返回 reachable=false + error，而不是协议错误。
func TestVerifyUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close() // 释放端口，后续连接会被拒绝

	svc, _ := testService(t)
	start := time.Now()
	result, perr := svc.Verify(VerifyRequest{Domain: address})
	if perr != nil {
		t.Fatalf("连接失败不应是协议错误: %v", perr)
	}
	if result.Reachable || result.Matched || result.Error == "" {
		t.Fatalf("不可达结果不符: %+v", result)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("拒绝连接应快速返回，耗时 %s", elapsed)
	}
}

// TestVerifyExpiredCert 校验过期证书仍能探测到元数据并如实标记负剩余天数。
func TestVerifyExpiredCert(t *testing.T) {
	svc, dir := testService(t)
	now := time.Now()
	certPEM, keyPEM := makeTestPair(t, testPairOptions{
		domain: "127.0.0.1", ipAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		notBefore: now.Add(-100 * 24 * time.Hour), notAfter: now.Add(-24 * time.Hour),
	})
	writeTestFile(t, dir, "expired.crt", certPEM)
	writeTestFile(t, dir, "expired.key", keyPEM)
	address := serveTestTLS(t, certPEM, keyPEM)

	result, perr := svc.Verify(VerifyRequest{Domain: address})
	if perr != nil || !result.Reachable {
		t.Fatalf("过期证书也应可探测: result=%+v err=%v", result, perr)
	}
	if result.DaysLeft >= 0 || result.DaysLeft != -1 {
		t.Fatalf("过期证书 days_left=%d，期望 -1", result.DaysLeft)
	}
	if !result.Matched {
		t.Fatalf("名称匹配应仍为 true: %+v", result)
	}
}

// TestVerifyInvalidTargets 覆盖探测目标的格式/白名单校验。
func TestVerifyInvalidTargets(t *testing.T) {
	svc, _ := testService(t)
	cases := []struct {
		name   string
		target string
	}{
		{"empty", ""},
		{"url", "https://example.com"},
		{"path", "example.com/../x"},
		{"bad-port", "example.com:0"},
		{"non-numeric-port", "example.com:https"},
		{"single-label", "localhost"},
		{"uppercase", "EXAMPLE.com"},
		{"space", "example com:443"},
		{"empty-host", ":443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, perr := svc.Verify(VerifyRequest{Domain: tc.target}); perr == nil {
				t.Fatalf("%q 应被拒绝", tc.target)
			}
		})
	}
}

// TestParseVerifyTarget 校验目标解析：默认端口、显式端口与裸 IPv6。
func TestParseVerifyTarget(t *testing.T) {
	cases := []struct {
		raw     string
		host    string
		address string
	}{
		{"example.com", "example.com", "example.com:443"},
		{"example.com:8443", "example.com", "example.com:8443"},
		{"127.0.0.1:9443", "127.0.0.1", "127.0.0.1:9443"},
		{"127.0.0.1", "127.0.0.1", "127.0.0.1:443"},
		{"::1", "::1", "[::1]:443"},
		{"[::1]:8443", "::1", "[::1]:8443"},
	}
	for _, tc := range cases {
		host, address, perr := parseVerifyTarget(tc.raw)
		if perr != nil {
			t.Fatalf("%q 解析失败: %v", tc.raw, perr)
		}
		if host != tc.host || address != tc.address {
			t.Fatalf("%q => host=%q address=%q，期望 %q/%q", tc.raw, host, address, tc.host, tc.address)
		}
	}
}
