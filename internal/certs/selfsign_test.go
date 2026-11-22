package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSelfSignRoundTrip 校验自签产物：字段、权限、磁盘回读的 x509 语义全部真实。
func TestSelfSignRoundTrip(t *testing.T) {
	svc, dir := testService(t)
	info, perr := svc.SelfSign(SelfSignRequest{Domain: "test.kore.local"})
	if perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	if info.Domain != "test.kore.local" || len(info.Domains) != 1 || info.Domains[0] != "test.kore.local" {
		t.Fatalf("域名/SAN 不符: %+v", info)
	}
	if !info.SelfSigned || info.Source != "self-signed" || info.IsCA {
		t.Fatalf("自签标记不符: self_signed=%v source=%q is_ca=%v", info.SelfSigned, info.Source, info.IsCA)
	}
	if info.DaysLeft != 365 || info.Expired || info.ExpiringSoon {
		t.Fatalf("有效期标记不符: days_left=%d expired=%v expiring_soon=%v", info.DaysLeft, info.Expired, info.ExpiringSoon)
	}
	if info.KeyType != "rsa" || info.KeyBits != 2048 {
		t.Fatalf("公钥信息不符: %s/%d", info.KeyType, info.KeyBits)
	}
	if info.ChainLength != 1 || len(info.FingerprintSHA256) != 64 {
		t.Fatalf("链长/指纹不符: chain=%d fp=%q", info.ChainLength, info.FingerprintSHA256)
	}
	if info.File != "test.kore.local.crt" || info.Serial == "" || info.Issuer == "" {
		t.Fatalf("文件/序列号/签发者不符: %+v", info)
	}

	// 权限硬约束：目录 0700、证书 0644、私钥 0600。
	if mode := fileMode(t, dir); mode != 0o700 {
		t.Fatalf("证书目录权限=%#o，期望 0700", mode)
	}
	certPath := dir + "/test.kore.local.crt"
	keyPath := dir + "/test.kore.local.key"
	if mode := fileMode(t, certPath); mode != 0o644 {
		t.Fatalf("证书权限=%#o，期望 0644", mode)
	}
	if mode := fileMode(t, keyPath); mode != 0o600 {
		t.Fatalf("私钥权限=%#o，期望 0600", mode)
	}

	// 磁盘内容必须能被 x509 真实解析，且与返回字段一致。
	block, _ := pem.Decode([]byte(readTestFile(t, certPath)))
	if block == nil {
		t.Fatal("证书文件不是 PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509 解析磁盘证书失败: %v", err)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "test.kore.local" {
		t.Fatalf("磁盘证书 DNSNames=%v", parsed.DNSNames)
	}
	if parsed.IsCA {
		t.Fatal("自签叶子证书不应是 CA")
	}
	if span := parsed.NotAfter.Sub(parsed.NotBefore); span < 364*24*time.Hour || span > 366*24*time.Hour {
		t.Fatalf("有效期跨度=%s，期望约 365 天", span)
	}
	if parsed.Subject.CommonName != "test.kore.local" {
		t.Fatalf("CN=%q", parsed.Subject.CommonName)
	}
}

// TestSelfSignTLSHandshake 用自签产物起真实 TLS 服务：tls.Dial 成功且能拿到证书，
// 再用 https 客户端确认应用层可用。
func TestSelfSignTLSHandshake(t *testing.T) {
	svc, dir := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "test.kore.local"}); perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	address := serveTestTLS(t, readTestFile(t, dir+"/test.kore.local.crt"), readTestFile(t, dir+"/test.kore.local.key"))

	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS 握手失败: %v", err)
	}
	defer func() { _ = conn.Close() }()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("握手成功但对端未提供证书")
	}
	if got := state.PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != "test.kore.local" {
		t.Fatalf("对端证书 DNSNames=%v", got)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   5 * time.Second,
	}
	response, err := client.Get("https://" + address + "/")
	if err != nil {
		t.Fatalf("HTTPS 请求失败: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS 状态码=%d", response.StatusCode)
	}
}

// TestSelfSignECDSA 校验 ecdsa256 产物的公钥信息。
func TestSelfSignECDSA(t *testing.T) {
	svc, _ := testService(t)
	info, perr := svc.SelfSign(SelfSignRequest{Domain: "ecdsa.kore.local", KeyType: "ecdsa256", Days: 10})
	if perr != nil {
		t.Fatalf("ECDSA 自签失败: %v", perr)
	}
	if info.KeyType != "ecdsa" || info.KeyBits != 256 {
		t.Fatalf("公钥信息不符: %s/%d", info.KeyType, info.KeyBits)
	}
	if info.DaysLeft != 10 {
		t.Fatalf("days_left=%d，期望 10", info.DaysLeft)
	}
}

// TestSelfSignIPDomain 校验 IP 主体进入 IPAddresses（否则 TLS 客户端按 IP 校验会失败）。
func TestSelfSignIPDomain(t *testing.T) {
	svc, dir := testService(t)
	info, perr := svc.SelfSign(SelfSignRequest{Domain: "127.0.0.1"})
	if perr != nil {
		t.Fatalf("IP 自签失败: %v", perr)
	}
	if len(info.Domains) != 1 || info.Domains[0] != "127.0.0.1" {
		t.Fatalf("IP SAN 不符: %v", info.Domains)
	}
	block, _ := pem.Decode([]byte(readTestFile(t, dir+"/127.0.0.1.crt")))
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析 IP 证书失败: %v", err)
	}
	if len(parsed.DNSNames) != 0 || len(parsed.IPAddresses) != 1 || parsed.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("IP 证书 SAN 不符: dns=%v ip=%v", parsed.DNSNames, parsed.IPAddresses)
	}
}

// TestSelfSignExtraSANs 校验附加 SAN 同时进入 DNSNames 与 IPAddresses。
func TestSelfSignExtraSANs(t *testing.T) {
	svc, dir := testService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{
		Domain: "test.kore.local", ExtraSANs: []string{"127.0.0.1", "alt.kore.local"},
	}); perr != nil {
		t.Fatalf("带附加 SAN 自签失败: %v", perr)
	}
	block, _ := pem.Decode([]byte(readTestFile(t, dir+"/test.kore.local.crt")))
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !containsString(parsed.DNSNames, "test.kore.local") || !containsString(parsed.DNSNames, "alt.kore.local") {
		t.Fatalf("DNSNames=%v", parsed.DNSNames)
	}
	if len(parsed.IPAddresses) != 1 || parsed.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("IPAddresses=%v", parsed.IPAddresses)
	}
	if err := parsed.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("证书应匹配 127.0.0.1: %v", err)
	}
}

// TestSelfSignInvalidParams 覆盖参数校验的拒绝分支。
func TestSelfSignInvalidParams(t *testing.T) {
	svc, dir := testService(t)
	cases := []struct {
		name string
		req  SelfSignRequest
		want string
	}{
		{"bad-domain", SelfSignRequest{Domain: "BAD"}, "domain"},
		{"one-label", SelfSignRequest{Domain: "localhost"}, "domain"},
		{"bad-days", SelfSignRequest{Domain: "a.kore.local", Days: -1}, "days"},
		{"too-many-days", SelfSignRequest{Domain: "a.kore.local", Days: 99999}, "days"},
		{"bad-key-type", SelfSignRequest{Domain: "a.kore.local", KeyType: "rsa1024"}, "key_type"},
		{"bad-extra-san", SelfSignRequest{Domain: "a.kore.local", ExtraSANs: []string{"*.kore.local"}}, "extra_sans"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, perr := svc.SelfSign(tc.req)
			if info != nil || perr == nil {
				t.Fatalf("期望参数错误，得到 info=%+v perr=%v", info, perr)
			}
			if !strings.Contains(perr.Message, tc.want) {
				t.Fatalf("错误信息 %q 未含 %q", perr.Message, tc.want)
			}
		})
	}
	if entries, err := readDirNames(dir); err != nil || len(entries) != 0 {
		t.Fatalf("参数错误不应落盘，目录=%v err=%v", entries, err)
	}
}

// TestSelfSignResultNeverContainsPrivateKey 红线：返回结构里绝不能出现私钥字节。
func TestSelfSignResultNeverContainsPrivateKey(t *testing.T) {
	svc, dir := testService(t)
	info, perr := svc.SelfSign(SelfSignRequest{Domain: "secret.kore.local"})
	if perr != nil {
		t.Fatalf("自签失败: %v", perr)
	}
	payload, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("序列化结果失败: %v", err)
	}
	keyPEM := readTestFile(t, dir+"/secret.kore.local.key")
	if strings.Contains(string(payload), "PRIVATE KEY") {
		t.Fatalf("返回结果含 PRIVATE KEY 标记: %s", payload)
	}
	// 去掉 PEM 头尾后比较正文，避免误伤字段名。
	body := strings.TrimSpace(strings.Split(strings.TrimSpace(keyPEM), "\n")[1])
	if body != "" && strings.Contains(string(payload), body) {
		t.Fatal("返回结果含私钥内容")
	}
}

// readDirNames 返回目录下的文件名列表。
func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}
