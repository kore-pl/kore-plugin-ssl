package certs

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// domainMaxLen 是 RFC 1035 域名长度上限。
const domainMaxLen = 253

// domainRE 严格约束域名：小写字母数字与连字符组成的标签，至少两个标签。
// 它同时拒绝路径分隔符与 ".."，杜绝任何形式的路径穿越（域名会拼进证书目录文件名）。
// 比 `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$` 更严：每个标签都不允许首尾连字符、连续点。
var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// daysMax 是自签有效期的上限（10 年），避免误传入造成不可控的长期证书。
const daysMax = 3650

// validateDomain 校验域名，拒绝空值、超长、大写与非法字符。
func validateDomain(domain string) *CertError {
	if domain == "" {
		return invalidParam("缺少必填字段 domain")
	}
	if len(domain) > domainMaxLen {
		return invalidParam("domain 超过 253 字符")
	}
	if domain != strings.ToLower(domain) {
		return invalidParam("domain 必须为小写")
	}
	if !domainRE.MatchString(domain) {
		return invalidParam("domain 非法：仅允许小写字母数字、连字符与点，且至少两个标签")
	}
	return nil
}

// validateDays 校验有效期天数：0 表示由调用方取默认值，其余必须在 1..3650。
func validateDays(days int) *CertError {
	if days == 0 {
		return nil
	}
	if days < 1 || days > daysMax {
		return invalidParam("days 必须在 1.." + strconv.Itoa(daysMax))
	}
	return nil
}

// validateKeyType 校验密钥类型；空串表示默认 rsa2048。
func validateKeyType(keyType string) *CertError {
	switch keyType {
	case "", "rsa2048", "ecdsa256":
		return nil
	default:
		return invalidParam("key_type 非法：仅支持 rsa2048 / ecdsa256")
	}
}

// normalizeExtraSAN 校验并归一化一个附加 SAN：IP 字面量或合法 DNS 名（小写）。
// 通配符不允许作为自签附加 SAN——自签只服务确定的名字，避免签出超范围证书。
func normalizeExtraSAN(raw string) (string, *CertError) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", invalidParam("extra_sans 不能包含空值")
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if value != strings.ToLower(value) {
		return "", invalidParam("extra_sans 必须为小写：" + value)
	}
	if !domainRE.MatchString(value) {
		return "", invalidParam("extra_sans 非法：" + value)
	}
	return value, nil
}

// parseVerifyTarget 解析 ssl.verify 的目标：host（默认 443）或 host:port。
// 只接受 DNS 名（走 domainRE 白名单）或 IP 字面量；拒绝 URL、路径与空端口。
func parseVerifyTarget(raw string) (host, address string, perr *CertError) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", "", invalidParam("缺少必填字段 domain")
	}
	if strings.Contains(target, "://") {
		return "", "", invalidParam("domain 只接受 host 或 host:port，不接受 URL")
	}
	host, port, err := splitTarget(target)
	if err != nil {
		return "", "", invalidParam(err.Error())
	}
	if err := validateVerifyHost(host); err != nil {
		return "", "", err
	}
	return host, net.JoinHostPort(host, port), nil
}

// splitTarget 拆出 host 与端口：支持 host、host:port、[v6]:port 与裸 IPv6。
// 端口缺省为 443；任何无法确定的形态都按非法目标拒绝。
func splitTarget(target string) (string, string, error) {
	const defaultPort = "443"
	if strings.HasPrefix(target, "[") {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return "", "", errTarget("IPv6 目标必须写成 [addr]:port")
		}
		if err := checkPort(port); err != nil {
			return "", "", err
		}
		return host, port, nil
	}
	switch strings.Count(target, ":") {
	case 0:
		return target, defaultPort, nil
	case 1:
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return "", "", errTarget("目标格式非法，应为 host 或 host:port")
		}
		if err := checkPort(port); err != nil {
			return "", "", err
		}
		return host, port, nil
	default:
		// 多冒号且未加方括号：只可能是裸 IPv6，不允许再带端口。
		if net.ParseIP(target) == nil {
			return "", "", errTarget("目标格式非法，IPv6 带端口请写成 [addr]:port")
		}
		return target, defaultPort, nil
	}
}

// errTarget 是目标格式错误的本地错误类型，避免在这里引入 fmt 依赖。
type errTarget string

func (e errTarget) Error() string { return string(e) }

// checkPort 校验端口为 1..65535 的十进制数字。
func checkPort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return errTarget("端口必须在 1..65535")
	}
	return nil
}

// validateVerifyHost 校验探测目标主机：IP 字面量直接放行，其余必须是合法小写域名。
func validateVerifyHost(host string) *CertError {
	if host == "" {
		return invalidParam("缺少探测主机")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	if host != strings.ToLower(host) {
		return invalidParam("domain 必须为小写")
	}
	if len(host) > domainMaxLen || !domainRE.MatchString(host) {
		return invalidParam("domain 非法：仅允许小写字母数字、连字符与点，且至少两个标签")
	}
	return nil
}
