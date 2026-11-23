// Package certs 实现 ssl 插件的真实证书管理业务层：扫描并解析证书目录、
// 导入证书与私钥（结构 / 匹配 / SAN 三重校验）、签发自签证书、判定续期通道，
// 以及对目标做真实 TLS 握手探测。
//
// 安全口径：
//   - 落盘只发生在固定证书目录（KORE_SSL_CERT_DIR，默认 /etc/kore/ssl），
//     不接受 RPC 入参里的任意路径；
//   - 私钥不进入任何返回结构、错误消息与日志（覆盖写入前只在内存做快照用于回滚）；
//     list 只解析证书公钥信息；
//   - 证书 0644、私钥 0600、目录 0700；写入一律临时文件 + fsync + rename。
//
// 依赖范围（G-17）：仅 Go 标准库 + pluginapi（错误码常量）。不引入第三方
// ACME 库；v1 不实现自动签发/续期，ssl.renew 对 ACME 证书如实返回 E_UNSUPPORTED。
package certs

import (
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 证书目录配置：固定目录语义，外部只能通过环境变量指定根目录，不能指定任意文件。
const (
	// DirEnv 是证书根目录的环境变量名。
	DirEnv = "KORE_SSL_CERT_DIR"
	// DefaultDir 是未配置时的默认证书目录。
	DefaultDir = "/etc/kore/ssl"
	// certSuffix 是证书文件后缀；selfsign/import 写这个后缀。
	certSuffix = ".crt"
	// pemSuffix 是外部导入证书可能使用的后缀，list 同样扫描。
	pemSuffix = ".pem"
	// keySuffix 是私钥后缀（0600），list 不扫描。
	keySuffix = ".key"
	// chainSuffix 是独立中间链文件后缀；它从属于同名前缀的叶子证书，不作为独立条目列出。
	chainSuffix = ".chain.pem"
	// acmeMarkerSuffix 是 ACME 托管标记文件后缀（v1.1 ACME 客户端写入的归属标记）。
	acmeMarkerSuffix = ".acme"
	// certFileMode / keyFileMode / dirMode 是落盘权限硬约束。
	certFileMode = 0o644
	keyFileMode  = 0o600
	dirMode      = 0o700
)

// CertInfo 是单张证书的结构化视图，只含公钥与元数据。
// 所有字段显式，不使用 map[string]any；字段为空时按 omitempty 省略，便于调用方区分。
type CertInfo struct {
	// Domain 是证书的主域名：首个 DNS SAN，其次首个 IP SAN，最后 CN。
	Domain string `json:"domain"`
	// Domains 是全部标识（SAN + CN），升序排列；含通配符时保留 *. 前缀。
	Domains []string `json:"domains"`
	// File 是证书目录内的文件名（不含绝对路径）。
	File string `json:"file,omitempty"`
	// NotBefore / NotAfter 是 UTC RFC3339 有效期。
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
	// DaysLeft 是剩余天数：向上取整（刚签发即 365），已过期时为负。
	DaysLeft int `json:"days_left"`
	// Issuer 是签发者 CommonName（为空时回退完整 DN），Subject 同理。
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
	Serial  string `json:"serial,omitempty"`
	IsCA    bool   `json:"is_ca"`
	// KeyType 是证书公钥算法：rsa / ecdsa / ed25519；KeyBits 是位数。
	KeyType string `json:"key_type,omitempty"`
	KeyBits int    `json:"key_bits,omitempty"`
	// ChainLength 是随叶子证书一起提供的证书数量（含叶子）；独立 chain 文件计入。
	ChainLength int `json:"chain_length"`
	// FingerprintSHA256 是 DER 的 SHA-256 小写十六进制。
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	// SelfSigned 表示 Issuer==Subject 且签名可由自身公钥验证。
	SelfSigned bool `json:"self_signed"`
	// Source 是来源判定：self-signed / acme / imported。
	Source string `json:"source,omitempty"`
	// Expired 为 now >= not_after；ExpiringSoon 为未过期且 days_left < 30。
	Expired      bool `json:"expired"`
	ExpiringSoon bool `json:"expiring_soon"`
	// Error 仅在单条扫描失败时出现，不影响其它条目。
	Error string `json:"error,omitempty"`
}

// ListResult 是 ssl.list 的结构化结果。
type ListResult struct {
	Certs []CertInfo `json:"certs"`
	Count int        `json:"count"`
}

// ImportRequest 是 ssl.import 的入参：证书与私钥必填，链选填。
type ImportRequest struct {
	Domain   string
	CertPEM  string
	KeyPEM   string
	ChainPEM string
}

// SelfSignRequest 是 ssl.selfsign 的入参。
// Days 为 0 时取 365；KeyType 为空时取 rsa2048；ExtraSANs 是可选附加标识
// （合法 DNS 名或 IP 字面量），用于内网/回环联调时让证书同时覆盖多个名字。
type SelfSignRequest struct {
	Domain    string
	Days      int
	KeyType   string
	ExtraSANs []string
}

// RenewRequest 是 ssl.renew 的入参；Days 为 0 时沿用原证书有效期跨度。
// DaysBefore > 0 时按"到期前多少天才续"判定，未到窗口返回 renewed=false + skipped=not_due
// （定时任务每天调用时必须靠它避免天天重签）。
type RenewRequest struct {
	Domain     string
	Days       int
	DaysBefore int
}

// RenewResult 是续期结果：证书信息 + 是否真的重新签发。
// BackupPath 是续期前旧证书备份目录（空表示本次未发生覆盖，未产生备份）。
type RenewResult struct {
	CertInfo
	Renewed    bool   `json:"renewed"`
	Skipped    string `json:"skipped,omitempty"`
	BackupPath string `json:"backup_path,omitempty"`
}

// VerifyRequest 是 ssl.verify 的入参：host 或 host:port。
type VerifyRequest struct {
	Domain string
}

// VerifyResult 是 ssl.verify 的结果。连接/握手失败时 Reachable=false 并带 Error，
// 不做成协议错误（探测失败是观测值，不是方法失败）。
type VerifyResult struct {
	Reachable         bool   `json:"reachable"`
	Host              string `json:"host"`
	Address           string `json:"address"`
	Matched           bool   `json:"matched"`
	NotBefore         string `json:"not_before,omitempty"`
	NotAfter          string `json:"not_after,omitempty"`
	DaysLeft          int    `json:"days_left"`
	Issuer            string `json:"issuer,omitempty"`
	Subject           string `json:"subject,omitempty"`
	Serial            string `json:"serial,omitempty"`
	SelfSigned        bool   `json:"self_signed"`
	ChainLength       int    `json:"chain_length"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	Error             string `json:"error,omitempty"`
}

// CertError 是业务方法错误：Code 取自 pluginapi.E_*，Message 带上下文且不含私钥。
// Hint 是可选的下一步提示，协议层会放进 detail.hint（内核转成 HTTP 错误体的 hint 字段）。
type CertError struct {
	Code    string
	Message string
	Hint    string
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

// newCertHintError 构造带可操作提示的方法错误（hint 走协议 detail，不塞进 message）。
func newCertHintError(code, msg, hint string) *CertError {
	return &CertError{Code: code, Message: msg, Hint: hint}
}

// FaultKind 是故障注入类型；值即故障标识，便于测试与日志直接比对。
type FaultKind string

const (
	FaultNone        FaultKind = ""
	FaultKill        FaultKind = "kill"
	FaultTimeout     FaultKind = "timeout"
	FaultDiskFull    FaultKind = "disk-full"
	FaultCgroupLimit FaultKind = "cgroup-limit"
)

// Fault 是故障注入模式，取环境变量 KORE_FAULT；空值表示不注入。
type Fault string

// ParseFault 把环境变量字符串收敛为受控 Fault 枚举；未知值不静默吞掉，
// 交由 faultError 返回 E_INVALID（不伪装成正常路径）。
func ParseFault(raw string) Fault { return Fault(raw) }

// faultError 在方法入口统一注入故障，四类分别映射协议错误码：
// 进程失联/超时 → E_UPSTREAM，磁盘满/cgroup OOM → E_INTERNAL。
func faultError(f Fault) *CertError {
	switch FaultKind(f) {
	case FaultNone:
		return nil
	case FaultKill:
		return newCertError(codeUpstream, "证书操作进程被 kill -9 终止，方法无响应")
	case FaultTimeout:
		return newCertError(codeUpstream, "证书操作超时（timeout），未在预算内完成")
	case FaultDiskFull:
		return newCertError(codeInternal, "磁盘满（ENOSPC），无法写入证书目录")
	case FaultCgroupLimit:
		return newCertError(codeInternal, "cgroup memory.max 超限，进程被 OOM killer 终止")
	default:
		return newCertError(codeInvalid, "未知故障注入模式："+string(f))
	}
}

// 协议错误码别名：集中在此处，避免业务文件散落字符串常量。
const (
	codeInvalid     = pluginapi.E_INVALID
	codeNotFound    = pluginapi.E_NOTFOUND
	codeConflict    = pluginapi.E_CONFLICT
	codeUpstream    = pluginapi.E_UPSTREAM
	codeInternal    = pluginapi.E_INTERNAL
	codeUnsupported = pluginapi.E_UNSUPPORTED
)

// invalidParam / internalErr / notFoundErr / unsupportedErr 是常用错误构造器。
func invalidParam(msg string) *CertError { return newCertError(codeInvalid, msg) }

func internalErr(msg string) *CertError { return newCertError(codeInternal, msg) }

func notFoundErr(msg string) *CertError { return newCertError(codeNotFound, msg) }

func unsupportedErr(msg string) *CertError { return newCertError(codeUnsupported, msg) }

// acmeRenewMessage 是 ACME 续期未实现的固定说明：不假装成功，明确版本计划。
const acmeRenewMessage = "ACME 续期需要 ACME 客户端，当前版本未实现，请在 v1.1 跟进"

// nowOr 返回注入时钟或当前时间，保证测试可确定性。
func nowOr(now func() time.Time) time.Time {
	if now != nil {
		return now()
	}
	return time.Now()
}
