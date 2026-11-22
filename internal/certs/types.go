// Package certs 实现 ssl 插件的业务方法层：域名校验、证书清单与签发/续期编排。
//
// 与 site（M4-B）同口径：只做参数校验 + 结构化结果，不接真实 ACME 服务。
// 签发通道抽象为 Issuer 接口，默认 StubIssuer 不连接任何 CA、不捆绑证书工具二进制。
// 本包只依赖标准库与 pluginapi（错误码常量），可被 tests/fault 直接 import 做方法级断言。
package certs

import "github.com/pengtang1024/kore/pkg/pluginapi"

// FaultKind 是故障注入类型；值即故障标识，便于测试与日志直接比对。
type FaultKind string

const (
	FaultNone        FaultKind = ""
	FaultKill        FaultKind = "kill"
	FaultTimeout     FaultKind = "timeout"
	FaultDiskFull    FaultKind = "disk_full"
	FaultCgroupLimit FaultKind = "cgroup_limit"
)

// Fault 描述注入到 Issuer 的故障；Message 为人类可读说明，不含凭据。
type Fault struct {
	Kind    FaultKind
	Message string
}

// CertInfo 是单张证书的结构化视图；所有字段显式，不使用 map[string]any。
type CertInfo struct {
	Domain    string `json:"domain"`
	Serial    string `json:"serial"`
	Status    string `json:"status"` // issued | renewed
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Issuer    string `json:"issuer"`
	RenewDue  bool   `json:"renew_due"`
	Source    string `json:"source"` // "stub"：明确标注非真实 CA 签发
}

// CertError 是业务方法错误：Code 取自 pluginapi.E_*，Message 带上下文。
type CertError struct {
	Code    string
	Message string
}

// Error 实现 error 接口，返回 "code: message"。
func (e *CertError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Code + ": " + e.Message
}

// newCertError 构造带协议错误码的方法错误。
func newCertError(code, msg string) *CertError {
	return &CertError{Code: code, Message: msg}
}

// invalidParam / internalErr / upstreamErr 是三类常用错误构造器。
func invalidParam(msg string) *CertError {
	return newCertError(pluginapi.E_INVALID, msg)
}

func internalErr(msg string) *CertError {
	return newCertError(pluginapi.E_INTERNAL, msg)
}

func upstreamErr(msg string) *CertError {
	return newCertError(pluginapi.E_UPSTREAM, msg)
}
