package certs

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

// Renew 对已有证书续期，行为按证书归属严格区分，绝不假装成功：
//
//   - ACME 托管（issuer 命中 Let's Encrypt/ACME，或存在 <base>.acme 标记）：
//     返回 E_UNSUPPORTED，说明需要 ACME 客户端、v1.1 跟进；
//   - 自签证书：按原密钥类型重新签发（新密钥 + 新序列号），原子覆盖原文件；
//   - 其它证书（公共 CA / 企业 CA 签发）：返回 E_UNSUPPORTED，提示改用 ssl.import。
//
// days 为 0 时沿用原证书的有效期跨度（四舍五入到天，最少 1 天）。
func (s *Service) Renew(req RenewRequest) (*RenewResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	if perr := validateDomain(req.Domain); perr != nil {
		return nil, perr
	}
	if perr := validateDays(req.Days); perr != nil {
		return nil, perr
	}
	now := nowOr(s.now)
	path, info, err := s.store.findCert(req.Domain, now)
	if errors.Is(err, os.ErrNotExist) {
		return nil, notFoundErr("证书目录中未找到 domain " + req.Domain + " 的证书")
	}
	if err != nil {
		return nil, internalErr("定位证书失败: " + err.Error())
	}
	if info.Error != "" {
		return nil, invalidParam("证书 " + info.File + " 无法解析: " + info.Error)
	}
	if err := checkRenewable(info); err != nil {
		return nil, err
	}

	// 自签续期：沿用原文件名与原密钥类型，避免生成第二份证书或降级算法。
	certFileName := filepath.Base(path)
	keyType, perr := renewKeyTypeFromInfo(info)
	if perr != nil {
		return nil, perr
	}
	days := req.Days
	if days == 0 {
		days = originalSpanDays(info)
	}
	// 续期保留原证书的附加 SAN：多域名/回环联调证书不能因为续期丢掉覆盖范围。
	extra := extraSANsFromInfo(info, req.Domain)
	renewed, err := s.issueSelfSigned(req.Domain, certFileName, days, keyType, extra, now)
	if err != nil {
		return nil, internalErr("自签续期失败: " + err.Error())
	}
	return &RenewResult{CertInfo: renewed, Renewed: true}, nil
}

// extraSANsFromInfo 提取原证书中除主域名外的标识，供续期保留。
func extraSANsFromInfo(info CertInfo, domain string) []string {
	extra := make([]string, 0, len(info.Domains))
	for _, name := range info.Domains {
		if name == domain {
			continue
		}
		extra = append(extra, name)
	}
	return extra
}

// checkRenewable 判定证书是否可续期：ACME 与其它 CA 证书都按"不支持"如实返回。
func checkRenewable(info CertInfo) *CertError {
	if info.Source == "acme" {
		return unsupportedErr(fmt.Sprintf("%s（证书 %s，issuer=%s）", acmeRenewMessage, info.File, info.Issuer))
	}
	if !info.SelfSigned {
		return unsupportedErr(fmt.Sprintf(
			"证书 %s 不是自签证书（issuer=%s），v1 不支持自动续期；请用 ssl.import 导入新证书，ACME 自动续期需 v1.1 跟进",
			info.File, info.Issuer))
	}
	return nil
}

// renewKeyTypeFromInfo 把现有证书的公钥类型映射回 selfsign 支持的 key_type。
// 不支持的算法（如 P-384 / Ed25519）显式返回 E_UNSUPPORTED，不静默降级。
func renewKeyTypeFromInfo(info CertInfo) (string, *CertError) {
	switch info.KeyType {
	case "rsa":
		return keyTypeRSA2048, nil
	case "ecdsa":
		if info.KeyBits == 256 {
			return keyTypeECDSA256, nil
		}
		return "", unsupportedErr(fmt.Sprintf(
			"现有证书为 ECDSA P-%d，v1 自签仅支持 rsa2048 / ecdsa256，不静默降级；请用 ssl.selfsign 指定 key_type", info.KeyBits))
	default:
		return "", unsupportedErr("现有证书公钥算法 " + info.KeyType + " 不在 v1 自签支持范围（rsa2048 / ecdsa256）")
	}
}

// originalSpanDays 返回原证书有效期跨度（天，四舍五入，最少 1 天）。
func originalSpanDays(info CertInfo) int {
	notBefore, errBefore := time.Parse(time.RFC3339, info.NotBefore)
	notAfter, errAfter := time.Parse(time.RFC3339, info.NotAfter)
	if errBefore != nil || errAfter != nil {
		return defaultSelfSignDays
	}
	days := int(math.Round(notAfter.Sub(notBefore).Hours() / 24))
	if days < 1 {
		days = 1
	}
	if days > daysMax {
		days = daysMax
	}
	return days
}
