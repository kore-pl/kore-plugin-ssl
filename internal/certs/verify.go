package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

// verifyTimeout 是 TLS 探测（TCP 连接 + 握手）的总预算。
const verifyTimeout = 10 * time.Second

// Verify 对目标做真实 TLS 握手探测：连接 host:port（缺省 443），取出对端证书
// 后返回有效期、剩余天数、签发者与域名匹配结果。
//
// 探测使用 InsecureSkipVerify：自签 / 过期证书也要能取到元数据再如实呈现；
// 因此 matched 只表示"证书名称覆盖探测主机"，不代表信任链通过。连接或握手
// 失败属于观测值，返回 reachable=false + error，不映射成协议错误。
func (s *Service) Verify(req VerifyRequest) (*VerifyResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	host, address, perr := parseVerifyTarget(req.Domain)
	if perr != nil {
		return nil, perr
	}
	now := nowOr(s.now)
	timeout := s.verifyTimeout
	if timeout <= 0 {
		timeout = verifyTimeout
	}
	result := &VerifyResult{Host: host, Address: address}
	leaf, chainLength, err := s.probeTLS(address, timeout)
	if err != nil {
		result.Reachable = false
		result.Error = err.Error()
		return result, nil
	}
	result.Reachable = true
	result.ChainLength = chainLength
	result.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	result.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	result.DaysLeft = daysLeft(leaf.NotAfter, now)
	result.Issuer = nameOrDN(leaf.Issuer.CommonName, leaf.Issuer.String())
	result.Subject = nameOrDN(leaf.Subject.CommonName, leaf.Subject.String())
	result.Serial = leaf.SerialNumber.Text(16)
	result.SelfSigned = isSelfSigned(leaf)
	result.FingerprintSHA256 = fingerprint(leaf)
	if err := leaf.VerifyHostname(host); err != nil {
		result.Matched = false
		result.Error = err.Error()
		return result, nil
	}
	result.Matched = true
	return result, nil
}

// probeTLS 建立 TLS 连接并取对端叶子证书；超时覆盖连接与握手全过程。
func (s *Service) probeTLS(address string, timeout time.Duration) (*x509.Certificate, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			// 只做探测，不做信任判定：自签/过期证书也要拿到元数据如实呈现。
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, 0, verifyError("连接未升级为 TLS")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, 0, errNoPeerCert
	}
	return state.PeerCertificates[0], len(state.PeerCertificates), nil
}

// errNoPeerCert 是握手成功但服务端未提供证书的错误。
var errNoPeerCert = verifyError("TLS 握手成功但对端未提供证书")

// verifyError 是探测阶段的本地错误类型。
type verifyError string

func (e verifyError) Error() string { return string(e) }
