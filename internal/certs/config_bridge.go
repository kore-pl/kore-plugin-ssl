package certs

// config_bridge.go 把统一配置面板（PLUGIN-CONFIG）的字段桥接到本仓真实的 ACME
// 设置文件 <meta>/acme/settings.json。业务层每次签发/续期都重新读该文件，
// 因此 config.set 写回后下一次调用即生效（restart_required=false）。
//
// 这里刻意复用 internal/certs 已有的 acmeSettings / loadACMESettings /
// saveACMESettings，不另建第二份真相源，避免面板值与签发行为漂移。

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	acmeproto "github.com/pengtang1024/kore-plugin-ssl/internal/acme"
)

// ACMEConfigPatch 是配置面板允许修改的 ACME 字段子集。指针表示"本次未提供，不改"
// （与 ssl.acme.auto 的局部更新语义一致）。EABHMACKey 为空串表示不改；要清空用
// ClearEAB=true。
type ACMEConfigPatch struct {
	CA           *string
	DirectoryURL *string
	Webroot      *string
	SitesRoot    *string
	Email        *string
	KeyType      *string
	EABKid       *string
	EABHMACKey   *string
	ClearEAB     bool
	AutoRenew    *bool
	DaysBefore   *int
}

var acmeEmailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// ACMEConfigValues 是 config.get 展示用的 ACME 现值（不含任何密钥明文）。
type ACMEConfigValues struct {
	CA            string
	DirectoryURL  string
	Webroot       string
	SitesRoot     string
	Email         string
	KeyType       string
	EABKid        string
	EABConfigured bool
	AutoRenew     bool
	DaysBefore    int
}

// GetACMEConfig 读取当前 ACME 设置供 config.get 展示（只读，不联网）。
func (s *Service) GetACMEConfig() (*ACMEConfigValues, *CertError) {
	settings, perr := s.loadACMESettings()
	if perr != nil {
		return nil, perr
	}
	return &ACMEConfigValues{
		CA:            settings.CA,
		DirectoryURL:  settings.DirectoryURL,
		Webroot:       settings.Webroot,
		SitesRoot:     settings.SitesRoot,
		Email:         settings.Email,
		KeyType:       acmeKeyTypeOrDefault(settings.KeyType),
		EABKid:        settings.EABKid,
		EABConfigured: settings.EABKid != "" && settings.EABHMACKey != "",
		AutoRenew:     settings.AutoRenew,
		DaysBefore:    settings.DaysBefore,
	}, nil
}

// ApplyACMEConfig 校验并原子写回 ACME 设置；业务下一次读盘即生效。
// 校验规则与 ssl.acme.auto 同源（CA 枚举/绝对路径/邮箱/key_type/days_before/EAB 成对）。
func (s *Service) ApplyACMEConfig(patch ACMEConfigPatch) *CertError {
	settings, perr := s.loadACMESettings()
	if perr != nil {
		return perr
	}
	if patch.CA != nil {
		ca := strings.TrimSpace(*patch.CA)
		switch ca {
		case acmeproto.CAStaging, acmeproto.CA, acmeproto.CALiteSSL, acmeproto.CACustom:
		default:
			return invalidParam("acme_ca 只支持 letsencrypt-staging / letsencrypt / litessl / custom")
		}
		settings.CA = ca
	}
	if patch.DirectoryURL != nil {
		url := strings.TrimSpace(*patch.DirectoryURL)
		if url != "" && !strings.HasPrefix(url, "https://") {
			return invalidParam("acme_directory_url 必须是 https:// 开头的 URL")
		}
		settings.DirectoryURL = url
	}
	for _, field := range []struct {
		name  string
		value *string
		ptr   *string
	}{
		{"acme_webroot", &settings.Webroot, patch.Webroot},
		{"acme_sites_root", &settings.SitesRoot, patch.SitesRoot},
	} {
		if field.ptr == nil {
			continue
		}
		path := strings.TrimSpace(*field.ptr)
		if path == "" {
			*field.value = ""
			continue
		}
		if !filepath.IsAbs(path) {
			return invalidParam(field.name + " 必须是绝对路径")
		}
		*field.value = filepath.Clean(path)
	}
	if patch.Email != nil {
		email := strings.TrimSpace(*patch.Email)
		if email != "" && (len(email) > 254 || !acmeEmailPattern.MatchString(email)) {
			return invalidParam("acme_email 格式非法")
		}
		settings.Email = email
	}
	if patch.KeyType != nil {
		keyType := strings.TrimSpace(*patch.KeyType)
		if keyType != acmeproto.KeyTypeECDSA256 && keyType != acmeproto.KeyTypeRSA2048 {
			return invalidParam("acme_key_type 只支持 ecdsa256 / rsa2048")
		}
		settings.KeyType = keyType
	}
	if patch.ClearEAB {
		settings.EABKid, settings.EABHMACKey = "", ""
	}
	if patch.EABKid != nil {
		settings.EABKid = strings.TrimSpace(*patch.EABKid)
	}
	if patch.EABHMACKey != nil {
		settings.EABHMACKey = strings.TrimSpace(*patch.EABHMACKey)
	}
	if (settings.EABKid == "") != (settings.EABHMACKey == "") {
		return invalidParam("eab_kid 与 eab_hmac_key 必须同时提供；要清空用 clear_eab=true")
	}
	if patch.DaysBefore != nil {
		if *patch.DaysBefore < 1 || *patch.DaysBefore > daysMax {
			return invalidParam("acme_days_before 必须在 1.." + strconv.Itoa(daysMax))
		}
		settings.DaysBefore = *patch.DaysBefore
	}
	if patch.AutoRenew != nil {
		settings.AutoRenew = *patch.AutoRenew
	}
	if settings.AutoRenew {
		if strings.TrimSpace(settings.Webroot) == "" {
			return invalidParam("开启自动续期前必须先配置 acme_webroot（HTTP-01 校验要写进站点根）")
		}
		if preset, ok := acmeproto.Preset(settings.CA); ok && preset.RequiresEAB && settings.EABHMACKey == "" {
			return invalidParam(settings.CA + " 强制 EAB：请先配置 acme_eab_kid 与 acme_eab_hmac_key")
		}
	}
	// 先完成全量校验再落盘，非法值不改任何文件（PLUGIN-CONFIG §8）。
	if _, err := acmeproto.ResolveDirectoryURL(settings.CA, settings.DirectoryURL); err != nil {
		return invalidParam("无法解析 ACME directory_url：" + err.Error())
	}
	return s.saveACMESettings(settings)
}
