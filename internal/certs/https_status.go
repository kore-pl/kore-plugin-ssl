package certs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// 强制 HTTPS 的只读判定（0.4.0）。
//
// 边界（本仓**只判定、不改配置**）：
//   - 探测 443 是否真能 TLS 握手、80 是否把请求 3xx 跳到 https——这是"该站点是否
//     已启用 HTTPS / 强制跳转"的事实来源；
//   - 写站点配置、加 443 监听、生成 80→443 跳转的唯一归属方是 site 插件
//     （`site.bindSSL` 的 force_https 字段，默认 true）；本仓不写配置、不 reload，
//     只把"要开启跳转该调什么"作为建议载荷返回；
//   - 探测只在用户显式调用 ssl.https.status（或 ssl.bind.set 显式带 probe）时发生，
//     没有后台任务、没有隐式出站（G-10）。
const (
	// defaultHTTPPort / defaultHTTPSPort 是缺省探测端口。
	defaultHTTPPort  = 80
	defaultHTTPSPort = 443
	// httpsProbeTimeout 是单次探测（连接 + 握手 / 读响应头）的预算。
	httpsProbeTimeout = 3 * time.Second
	// httpProbeMaxHeaderBytes 是响应头读取上限，防对端灌爆内存。
	httpProbeMaxHeaderBytes = 16 << 10
	// httpProbeUserAgent 是本插件探测请求的 UA（可被服务端日志识别）。
	httpProbeUserAgent = "kore-ssl/https-status"
)

// 判定结论：只读事实，不是配置状态。
const (
	// VerdictForceHTTPS：443 可握手且 80 已 3xx 跳转到 https。
	VerdictForceHTTPS = "force-https"
	// VerdictHTTPSNoRedirect：443 可握手，但 80 没有跳到 https（未开启强制跳转）。
	VerdictHTTPSNoRedirect = "https-without-redirect"
	// VerdictHTTPSUnreachable：443 不可握手（证书未生效 / 端口未监听 / 网络不可达）。
	VerdictHTTPSUnreachable = "https-unreachable"
)

// HTTPSStatusRequest 是 ssl.https.status 的入参：host 或 IP，端口缺省 80 / 443。
// 端口可显式给出，只用于联调与测试（与"不让人填环境细节"一致：默认值即可用）。
type HTTPSStatusRequest struct {
	Domain    string
	HTTPPort  int
	HTTPSPort int
}

// HTTPSProbe 是 443 侧的探测结果。Reachable 只表示"能完成 TLS 握手"，
// Matched 才表示"对端证书覆盖探测主机"（信任链不在本插件判定范围）。
type HTTPSProbe struct {
	Address   string `json:"address"`
	Reachable bool   `json:"reachable"`
	Matched   bool   `json:"matched"`
	NotAfter  string `json:"not_after,omitempty"`
	DaysLeft  int    `json:"days_left"`
	Issuer    string `json:"issuer,omitempty"`
	Error     string `json:"error,omitempty"`
}

// HTTPProbe 是 80 侧的探测结果：不跟随跳转，只看第一跳的状态码与 Location。
type HTTPProbe struct {
	Address          string `json:"address"`
	Reachable        bool   `json:"reachable"`
	StatusCode       int    `json:"status_code"`
	Location         string `json:"location,omitempty"`
	RedirectsToHTTPS bool   `json:"redirects_to_https"`
	Error            string `json:"error,omitempty"`
}

// HTTPSStatusResult 是 ssl.https.status 的结果。
// ForceHTTPS 是本次判定的核心结论（443 可达 + 80 跳转 https），Verdict 给它一个稳定枚举。
type HTTPSStatusResult struct {
	Domain     string     `json:"domain"`
	HTTPS      HTTPSProbe `json:"https"`
	HTTP       HTTPProbe  `json:"http"`
	ForceHTTPS bool       `json:"force_https"`
	Verdict    string     `json:"verdict"`
	// Enforced 是本仓登记的**期望状态**（ssl.https.enforce）。
	Enforced bool `json:"enforced"`
	// Source 是强制 HTTPS 的来源：plugin（本仓登记）/ manual（未登记但实测在跳）/ none。
	Source string `json:"source"`
	// RedirectCode 是 80 侧第一跳状态码（0 表示不可达或非 3xx）。
	RedirectCode int        `json:"redirect_code"`
	SiteAction   SiteAction `json:"site_action"`
	Hint         string     `json:"hint"`
}

// HTTPSStatus 对目标做 80 / 443 的真实行为探测，返回只读判定。
//
// 失败语义与 ssl.verify 一致：连不上属于观测值（reachable=false + error），
// 不映射成协议错误；只有入参非法才返回 E_INVALID。
func (s *Service) HTTPSStatus(req HTTPSStatusRequest) (*HTTPSStatusResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	host, perr := normalizeProbeHost(req.Domain)
	if perr != nil {
		return nil, perr
	}
	httpPort, perr := normalizeProbePort(req.HTTPPort, defaultHTTPPort, "http_port")
	if perr != nil {
		return nil, perr
	}
	httpsPort, perr := normalizeProbePort(req.HTTPSPort, defaultHTTPSPort, "https_port")
	if perr != nil {
		return nil, perr
	}

	httpsProbe := s.probeHTTPS(host, httpsPort)
	httpProbe := s.probeHTTP(host, httpPort)
	forceHTTPS := httpsProbe.Reachable && httpProbe.RedirectsToHTTPS
	result := &HTTPSStatusResult{
		Domain:     host,
		HTTPS:      httpsProbe,
		HTTP:       httpProbe,
		ForceHTTPS: forceHTTPS,
		Verdict:    verdictFor(httpsProbe, httpProbe),
		SiteAction: SiteAction{
			Plugin: sitePluginID,
			Method: siteBindSSLMethod,
			Params: SiteActionParams{Domain: host, ForceHTTPS: boolPtr(true)},
			Note: "开启或关闭跳转归 site 插件：site.bindSSL 的 force_https（默认 true）" +
				"控制 80→443；本仓不改配置，只给载荷",
		},
	}
	enforced, registered := s.httpsEnforced(host)
	result.Enforced = registered && enforced
	switch {
	case result.Enforced:
		result.Source = "plugin"
	case httpProbe.RedirectsToHTTPS:
		result.Source = "manual"
	default:
		result.Source = "none"
	}
	result.RedirectCode = httpProbe.StatusCode
	result.Hint = hintForVerdict(result)
	return result, nil
}

// verdictFor 把两侧探测事实收敛为三值判定。
func verdictFor(httpsProbe HTTPSProbe, httpProbe HTTPProbe) string {
	switch {
	case !httpsProbe.Reachable:
		return VerdictHTTPSUnreachable
	case httpProbe.RedirectsToHTTPS:
		return VerdictForceHTTPS
	default:
		return VerdictHTTPSNoRedirect
	}
}

// hintForVerdict 给出"下一步怎么办"：每条都指向站点插件，本仓不落任何配置。
func hintForVerdict(result *HTTPSStatusResult) string {
	switch result.Verdict {
	case VerdictForceHTTPS:
		return "443 可握手、80 已跳转到 https，强制 HTTPS 已生效（配置由 site 插件持有，本仓只判定）"
	case VerdictHTTPSNoRedirect:
		return "443 可握手，但 80 没有跳到 https：到站点页用 site.bindSSL 重新绑定并保持 force_https=true 即可开启跳转；" +
			"若证书尚未绑定，先用 ssl.bind.list 取 cert_path / key_path"
	default:
		return "443 无法完成 TLS 握手：确认站点已用 site.bindSSL 绑定证书、服务已加载配置，再用 ssl.verify 单独排查 443"
	}
}

// normalizeProbeHost 校验证书探测主机：拒绝 URL / 端口混写，域名或 IP 字面量均可。
func normalizeProbeHost(raw string) (string, *CertError) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", invalidParam("缺少必填字段 domain")
	}
	if strings.Contains(host, "://") {
		return "", invalidParam("domain 只接受主机名或 IP，不接受 URL")
	}
	if err := validateVerifyHost(host); err != nil {
		return "", err
	}
	return host, nil
}

// normalizeProbePort 校验探测端口：0 取默认，其余 1..65535。
func normalizeProbePort(port, fallback int, field string) (int, *CertError) {
	if port == 0 {
		return fallback, nil
	}
	if port < 1 || port > 65535 {
		return 0, invalidParam(field + " 必须在 1..65535")
	}
	return port, nil
}

// probeHTTPS 连接 443 侧并取对端证书（InsecureSkipVerify：自签/过期也要能判定"能不能握手"）。
func (s *Service) probeHTTPS(host string, port int) HTTPSProbe {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	probe := HTTPSProbe{Address: address}
	leaf, _, err := s.probeTLS(address, httpsProbeTimeout)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	probe.Reachable = true
	probe.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	probe.DaysLeft = daysLeft(leaf.NotAfter, nowOr(s.now))
	probe.Issuer = nameOrDN(leaf.Issuer.CommonName, leaf.Issuer.String())
	probe.Matched = leaf.VerifyHostname(host) == nil
	return probe
}

// probeHTTP 连接 80 侧发一个最小 GET /，只读第一跳状态码与 Location（不跟随跳转）。
func (s *Service) probeHTTP(host string, port int) HTTPProbe {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	probe := HTTPProbe{Address: address}
	ctx, cancel := context.WithTimeout(context.Background(), httpsProbeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(httpsProbeTimeout))
	request := "GET / HTTP/1.1\r\nHost: " + host +
		"\r\nUser-Agent: " + httpProbeUserAgent + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		probe.Error = err.Error()
		return probe
	}
	reader := textproto.NewReader(bufio.NewReaderSize(io.LimitReader(conn, httpProbeMaxHeaderBytes), 4096))
	statusLine, err := reader.ReadLine()
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	code, err := parseStatusCode(statusLine)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	header, err := reader.ReadMIMEHeader()
	if err != nil && !isTruncatedHeader(err) {
		probe.Error = err.Error()
		return probe
	}
	probe.Reachable = true
	probe.StatusCode = code
	probe.Location = header.Get("Location")
	probe.RedirectsToHTTPS = isHTTPSRedirect(code, probe.Location)
	return probe
}

// parseStatusCode 从状态行（如 "HTTP/1.1 301 Moved Permanently"）取状态码。
func parseStatusCode(line string) (int, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || !strings.HasPrefix(strings.ToUpper(fields[0]), "HTTP/") {
		return 0, fmt.Errorf("响应不是 HTTP 状态行: %q", truncateForError(line))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil || code < 100 || code > 599 {
		return 0, fmt.Errorf("状态码非法: %q", truncateForError(fields[1]))
	}
	return code, nil
}

// isHTTPSRedirect 判定是否为指向 https 的 3xx（301/302/303/307/308）。
func isHTTPSRedirect(code int, location string) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(location)), "https://")
	default:
		return false
	}
}

// isTruncatedHeader 判断读取响应头时的错误是否只是"对端未给完整头"：
// 已经拿到状态行时，头缺失不影响"是否跳转"的判定，按观测值处理而不是整体失败。
func isTruncatedHeader(err error) bool {
	if err == nil {
		return false
	}
	return err == io.EOF || err == io.ErrUnexpectedEOF ||
		strings.Contains(err.Error(), "malformed MIME header")
}

// truncateForError 截断回显内容，避免把对端任意长度的内容塞进错误消息。
func truncateForError(raw string) string {
	const limit = 80
	if len(raw) <= limit {
		return raw
	}
	return raw[:limit] + "..."
}
