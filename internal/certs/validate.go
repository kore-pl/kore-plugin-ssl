package certs

import (
	"regexp"
	"strings"
)

// domainMaxLen 是 RFC 1035 域名长度上限。
const domainMaxLen = 253

// domainRE 严格约束域名：小写字母数字与连字符组成的标签，至少两个标签。
// 与 site 同口径，同时拒绝路径分隔符与 ".."，杜绝任何形式的路径穿越。
var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

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

// validateEmail 校验选填邮箱：为空合法，否则必须含单个 @ 且两侧非空。
func validateEmail(email string) *CertError {
	if email == "" {
		return nil
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return invalidParam("email 非法：需要一个 @ 且两侧非空")
	}
	return nil
}
