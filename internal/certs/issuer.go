package certs

import (
	"context"
	"fmt"
	"time"
)

// Issuer 是 ACME 签发通道的抽象。当前仅 StubIssuer 实现——不连真实 CA，
// 真 CA 留后续；换真实实现只需替换注入的 Issuer，不动方法层与 fault 测试。
type Issuer interface {
	Issue(ctx context.Context, domain string) (*CertInfo, *CertError)
}

// StubIssuer 是不连接任何 CA 的桩实现，可注入故障以验证四类故障下的错误返回。
type StubIssuer struct {
	Fault Fault
}

// Issue 在注入故障时返回对应协议错误；否则返回结构化的桩证书记录。
func (s *StubIssuer) Issue(ctx context.Context, domain string) (*CertInfo, *CertError) {
	if err := ctx.Err(); err != nil {
		return nil, upstreamErr("ACME 请求上下文结束: " + err.Error())
	}
	switch s.Fault.Kind {
	case FaultKill:
		return nil, upstreamErr("进程被 kill: " + s.Fault.Message)
	case FaultTimeout:
		return nil, upstreamErr("ACME 签发超时: " + s.Fault.Message)
	case FaultDiskFull:
		return nil, internalErr("证书落盘失败(ENOSPC): " + s.Fault.Message)
	case FaultCgroupLimit:
		return nil, internalErr("cgroup 内存超限(OOM): " + s.Fault.Message)
	case FaultNone:
		now := time.Now()
		return &CertInfo{
			Domain: domain, Serial: "stub-" + domain, Status: "issued",
			NotBefore: now.UTC().Format(time.RFC3339),
			NotAfter:  now.Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
			Issuer:    "stub-acme", RenewDue: false, Source: "stub",
		}, nil
	default:
		return nil, internalErr(fmt.Sprintf("未知故障类型 %q", s.Fault.Kind))
	}
}
