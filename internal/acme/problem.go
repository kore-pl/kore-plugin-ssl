package acme

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Problem 是 RFC 8555 §6.7 的错误体（problem+json）。
type Problem struct {
	Type        string       `json:"type"`
	Detail      string       `json:"detail"`
	Status      int          `json:"status"`
	Instance    string       `json:"instance"`
	Identifier  *Identifier  `json:"identifier,omitempty"`
	Subproblems []Subproblem `json:"subproblems,omitempty"`
}

// Subproblem 是批量请求里单个标识符的错误。
type Subproblem struct {
	Type       string      `json:"type"`
	Detail     string      `json:"detail"`
	Identifier *Identifier `json:"identifier,omitempty"`
}

// Kind 是错误分类；certs 层据此映射成协议错误码（不把 ACME 的类型字符串漏给用户）。
type Kind string

const (
	// KindInvalid 是请求/参数/校验问题（含 EAB 配置错误、challenge 失败、finalize 被拒）。
	KindInvalid Kind = "invalid"
	// KindAuth 是账号相关错误（账号不存在、EAB 不被接受）。
	KindAuth Kind = "auth"
	// KindRateLimit 是 CA 限流（rateLimited）。
	KindRateLimit Kind = "rate-limit"
	// KindUpstream 是 CA 侧/网络问题（5xx、DNS、连接失败）。
	KindUpstream Kind = "upstream"
	// KindUnsupported 是本客户端未实现的 ACME 能力（如只支持 HTTP-01）。
	KindUnsupported Kind = "unsupported"
)

// Error 是内置 ACME 客户端的统一错误：Kind 给程序判断，Hint 给用户下一步。
type Error struct {
	Kind        Kind
	ProblemType string
	Detail      string
	Hint        string
	Subproblems []Subproblem
}

// Error 实现 error 接口；message 不含任何密钥材料。
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.ProblemType != "" {
		return fmt.Sprintf("acme %s (%s): %s", e.Kind, shortProblemType(e.ProblemType), e.Detail)
	}
	return fmt.Sprintf("acme %s: %s", e.Kind, e.Detail)
}

// acmeProblemPrefix 是 RFC 8555 错误类型的 URN 前缀。
const acmeProblemPrefix = "urn:ietf:params:acme:error:"

// shortProblemType 去掉 URN 前缀，只留可读的动作名（如 badNonce）。
func shortProblemType(raw string) string {
	return strings.TrimPrefix(raw, acmeProblemPrefix)
}

// parseProblem 解析错误响应体；非 JSON 时退化成"HTTP 状态码"的错误。
func parseProblem(body []byte, status int) Problem {
	var prob Problem
	if err := json.Unmarshal(body, &prob); err == nil && prob.Type != "" {
		if prob.Status == 0 {
			prob.Status = status
		}
		return prob
	}
	return Problem{Type: "", Detail: strings.TrimSpace(string(body)), Status: status}
}

// kindOf 把 ACME 错误类型映射为内部 Kind。
func kindOf(problemType string) Kind {
	switch shortProblemType(problemType) {
	case "rateLimited":
		return KindRateLimit
	case "accountDoesNotExist", "unauthorized", "externalAccountRequired":
		return KindAuth
	case "serverInternal", "connection", "dns":
		return KindUpstream
	case "":
		return KindUpstream
	default:
		return KindInvalid
	}
}

// hintForProblem 给出可操作提示；每条都要求用户能做点什么，而不是只说"失败了"。
func hintForProblem(prob Problem) string {
	switch shortProblemType(prob.Type) {
	case "rateLimited":
		return "该 CA 对同一域名/账号有签发频率限制：先用 letsencrypt-staging 跑通流程，或等 Retry-After 之后重试（staging 不占生产配额）"
	case "externalAccountRequired":
		return "该 CA 要求 EAB：在 CA 控制台创建 ACME 账号，把 eab_kid / eab_hmac_key 写进 ssl.acme.auto 后再签发（LiteSSL 强制要求）"
	case "badNonce":
		return "CA 的 nonce 已失效：客户端会自动换新 nonce 重试一次；仍失败说明与 CA 的时钟/网络不稳定，稍后重试"
	case "badCSR":
		return "CA 拒绝了 CSR：确认域名列表与订单一致、密钥算法受支持（本客户端用 ECDSA P-256 / RSA 2048）"
	case "orderNotReady":
		return "订单尚未就绪：通常是 challenge 还没完成；检查 webroot 是否可被 CA 通过 http://<域名>/.well-known/acme-challenge/ 访问"
	case "rejectedIdentifier":
		return "CA 拒绝为该标识符签发：域名需是公网可解析的真实域名，通配符需 DNS-01（本客户端未实现）"
	case "unauthorized":
		return "CA 判定账号/账号密钥无权重：删除 <cert dir>/acme/accounts 下的账号后重试，或确认 EAB kid 与 hmac key 属于同一 CA 账号"
	case "dns", "connection":
		return "CA 无法解析或连接域名：确认域名 A/AAAA 记录指向本机公网 IP、80 端口可达、防火墙放行"
	case "serverInternal":
		return "CA 侧内部错误：稍后重试；连续失败可在 ssl.acme.builtin.status 的 audit 里看最近一次原因"
	default:
		return "按 message 里的 CA 原文修正；ssl.acme.builtin.status 可查看最近一次尝试的审计记录"
	}
}

// newProblemError 把 Problem 转成带 Hint 的 Error。
func newProblemError(prob Problem) *Error {
	detail := strings.TrimSpace(prob.Detail)
	if detail == "" {
		detail = fmt.Sprintf("CA 返回 HTTP %d 且没有错误详情", prob.Status)
	}
	if len(prob.Subproblems) > 0 {
		parts := make([]string, 0, len(prob.Subproblems))
		for _, sub := range prob.Subproblems {
			target := ""
			if sub.Identifier != nil {
				target = sub.Identifier.Value + " "
			}
			parts = append(parts, target+strings.TrimSpace(sub.Detail))
		}
		detail += "（" + strings.Join(parts, "；") + "）"
	}
	return &Error{Kind: kindOf(prob.Type), ProblemType: prob.Type, Detail: detail, Hint: hintForProblem(prob), Subproblems: prob.Subproblems}
}

// errf 构造本地错误（不经 CA）。
func errf(kind Kind, hint, format string, args ...any) *Error {
	return &Error{Kind: kind, Detail: fmt.Sprintf(format, args...), Hint: hint}
}
