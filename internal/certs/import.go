package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
)

// Import 校验并落盘一张已有证书：
//
//  1. cert_pem 必须是可被 x509.ParseCertificate 解析的 PEM 证书（允许 fullchain，
//     首块为叶子，其余计入 chain_length）；
//  2. 私钥必须是 PEM 且非加密（拒绝 PKCS#8 ENCRYPTED、带 Proc-Type/DEK-Info 的
//     传统加密块以及 OpenSSH 私钥）；
//  3. 证书 SAN 必须覆盖 domain（DNS 精确 / 通配符一级子域 / IP SAN）；
//  4. tls.X509KeyPair 校验证书与私钥匹配，不匹配一律 E_INVALID；
//  5. 原子写入：私钥 0600、证书 0644、目录 0700，失败整组回滚。
func (s *Service) Import(req ImportRequest) (*CertInfo, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	if perr := validateDomain(req.Domain); perr != nil {
		return nil, perr
	}
	if req.CertPEM == "" {
		return nil, invalidParam("缺少必填字段 cert_pem")
	}
	if req.KeyPEM == "" {
		return nil, invalidParam("缺少必填字段 key_pem")
	}
	certPEM := []byte(req.CertPEM)
	keyPEM := []byte(req.KeyPEM)
	bundle, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, invalidParam("cert_pem 不是合法证书: " + err.Error())
	}
	if !certCoversDomain(bundle.leaf, req.Domain) {
		return nil, invalidParam(fmt.Sprintf(
			"证书 SAN 不含 domain %q（证书标识: %s）", req.Domain, strings.Join(certDomains(bundle.leaf), ", ")))
	}
	if perr := validatePrivateKeyPEM(keyPEM); perr != nil {
		return nil, perr
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, invalidParam("证书与私钥不匹配或密钥格式非法: " + err.Error())
	}
	chainPEM, chainCount, perr := parseChainPEM(req.ChainPEM)
	if perr != nil {
		return nil, perr
	}
	// 覆盖已有证书时沿用其文件名（可能是 .pem），避免同域出现两份证书。
	certFileName := req.Domain + certSuffix
	now := nowOr(s.now)
	if existing, _, findErr := s.store.findCert(req.Domain, now); findErr == nil {
		certFileName = filepath.Base(existing)
	}
	if err := s.store.writePair(certFileName, certPEM, keyPEM, chainPEM); err != nil {
		return nil, internalErr("写入证书失败: " + err.Error())
	}
	info, err := s.inspectWritten(certFileName, now)
	if err != nil {
		return nil, internalErr(err.Error())
	}
	info.ChainLength = countPEMCerts(certPEM) + chainCount
	return &info, nil
}

// validatePrivateKeyPEM 检查私钥 PEM 的类型与加密状态，不读取、不回显密钥内容。
func validatePrivateKeyPEM(keyPEM []byte) *CertError {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return invalidParam("key_pem 不是 PEM 格式（未找到 PEM 块）")
	}
	if isEncryptedPEMBlock(block) {
		return invalidParam("私钥带 passphrase（加密 PEM），拒绝导入：请提供未加密私钥")
	}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return nil
	case "ENCRYPTED PRIVATE KEY":
		return invalidParam("私钥带 passphrase（PKCS#8 加密），拒绝导入：请提供未加密私钥")
	case "OPENSSH PRIVATE KEY":
		return invalidParam("仅支持 PEM 私钥（PKCS#8 / PKCS#1 / SEC1），不支持 OpenSSH 私钥")
	default:
		return invalidParam(fmt.Sprintf("私钥 PEM 块类型 %q 不支持（仅接受未加密私钥）", block.Type))
	}
}

// isEncryptedPEMBlock 识别传统加密 PEM（Proc-Type: 4,ENCRYPTED / 带 DEK-Info）。
func isEncryptedPEMBlock(block *pem.Block) bool {
	if block == nil {
		return false
	}
	if strings.Contains(strings.ToUpper(block.Headers["Proc-Type"]), "ENCRYPTED") {
		return true
	}
	return block.Headers["DEK-Info"] != ""
}

// parseChainPEM 校验独立中间链：只能包含可解析的 CERTIFICATE 块。
func parseChainPEM(raw string) ([]byte, int, *CertError) {
	if strings.TrimSpace(raw) == "" {
		return nil, 0, nil
	}
	data := []byte(raw)
	rest := data
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, 0, invalidParam("chain_pem 只能包含 CERTIFICATE 块，发现 " + block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, 0, invalidParam("chain_pem 含无法解析的证书: " + err.Error())
		}
		count++
	}
	if count == 0 {
		return nil, 0, invalidParam("chain_pem 未包含任何 PEM 证书")
	}
	return data, count, nil
}
