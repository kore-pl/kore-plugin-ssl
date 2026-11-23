package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	acmeproto "github.com/pengtang1024/kore-plugin-ssl/internal/acme"
)

// 内置 ACME 的持久化状态（G-31 零侵入：全部落在证书目录内，删安装目录即清零）。
//
//	<证书目录>/acme/
//	├── settings.json (0600)      CA / webroot / email / EAB / auto_renew / days_before
//	├── audit.jsonl (0600)        每次联网一条（时间/动作/CA/域名/结果/原因），超 256 KiB 轮转
//	├── accounts/<ca>/account.key (0600)  账户私钥（P-256）
//	└── accounts/<ca>/account.json (0600)  kid / directory / contact / created_at
const (
	// acmeSettingsFileName 是 ACME 设置文件名。
	acmeSettingsFileName = "settings.json"
	// acmeAuditFileName 是审计文件名（JSONL，只追加）。
	acmeAuditFileName = "audit.jsonl"
	// acmeAuditRotatedName 是轮转后的审计文件名（保留一代）。
	acmeAuditRotatedName = "audit.jsonl.1"
	// acmeAuditMaxBytes 是审计文件轮转阈值。
	acmeAuditMaxBytes = 256 << 10
	// acmeAuditTailMax 是 status 默认返回的最近审计条数。
	acmeAuditTailMax = 8
	// acmeAccountsDirName 是账户目录名。
	acmeAccountsDirName = "accounts"
	// acmeSettingsSchema 是设置文件 schema 版本。
	acmeSettingsSchema = 1
	// acmeDefaultDaysBefore 是未配置时的续期提前量（天）。
	acmeDefaultDaysBefore = 30
	// acmeAuditReasonMax 是审计 reason 的最大长度（避免把整段 CA 输出写进审计）。
	acmeAuditReasonMax = 300
	// acmeAccountKeyFileName / acmeAccountMetaFileName 是账户密钥与元数据文件名。
	acmeAccountKeyFileName  = "account.key"
	acmeAccountMetaFileName = "account.json"
	// acmeAutoTaskPrefix 是自动续期任务名前缀（≤64 字符，便于配额内识别）。
	acmeAutoTaskPrefix = "ssl-acme-auto-renew"
)

// caIDPattern 限定 CA 目录名（CA 名会拼进文件路径，必须白名单）。
var caIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// acmeSettings 是 ACME 配置的落盘形状（显式字段，不用 map）。
type acmeSettings struct {
	Schema       int    `json:"schema"`
	CA           string `json:"ca"`
	DirectoryURL string `json:"directory_url,omitempty"`
	Webroot      string `json:"webroot,omitempty"`
	Email        string `json:"email,omitempty"`
	KeyType      string `json:"key_type,omitempty"`
	EABKid       string `json:"eab_kid,omitempty"`
	EABHMACKey   string `json:"eab_hmac_key,omitempty"`
	AutoRenew    bool   `json:"auto_renew"`
	DaysBefore   int    `json:"days_before"`
	UpdatedAt    string `json:"updated_at"`
}

// defaultACMESettings 是出厂默认：Let's Encrypt staging + 30 天提前量 + 自动续期关闭。
//
// 默认 staging 是刻意的：先用不占生产配额的测试 CA 验证域名可达与 webroot，
// 验证通过后再把 ca 切到 letsencrypt/litessl，避免一上来就打满生产 rate limit。
// 自动续期默认关闭是 G-10 硬要求：不显式开启就不会有后台联网。
func defaultACMESettings() acmeSettings {
	return acmeSettings{Schema: acmeSettingsSchema, CA: acmeproto.CAStaging, DaysBefore: acmeDefaultDaysBefore}
}

// acmeAccount 是账户元数据（不含私钥）。
type acmeAccount struct {
	KID       string `json:"kid"`
	Directory string `json:"directory"`
	Contact   string `json:"contact,omitempty"`
	CreatedAt string `json:"created_at"`
}

// acmeAuditEntry 是"每次联网"的审计记录：谁（动作）、何时、对哪个 CA、哪个域名、结果。
type acmeAuditEntry struct {
	At        string `json:"at"`
	Action    string `json:"action"`
	CA        string `json:"ca,omitempty"`
	Directory string `json:"directory,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Result    string `json:"result"`
	Reason    string `json:"reason,omitempty"`
}

// acmeDir 返回 <证书目录>/acme。
func (s *certStore) acmeDir() string { return filepath.Join(s.dir, acmeDirName) }

// acmeSettingsPath 返回设置文件路径。
func (s *certStore) acmeSettingsPath() string {
	return filepath.Join(s.acmeDir(), acmeSettingsFileName)
}

// acmeAccountDir 返回某 CA 的账户目录。
func (s *certStore) acmeAccountDir(caID string) string {
	return filepath.Join(s.acmeDir(), acmeAccountsDirName, caID)
}

// sanitizeCAID 把 CA 名收敛为安全目录名；custom 统一落 custom 目录。
func sanitizeCAID(ca string) string {
	normalized := strings.ToLower(strings.TrimSpace(ca))
	if normalized == "" {
		return acmeproto.CAStaging
	}
	if normalized == acmeproto.CACustom || !caIDPattern.MatchString(normalized) {
		return acmeproto.CACustom
	}
	return normalized
}

// loadACMESettings 读取设置；文件不存在返回默认值（首次使用不报错）。
func (s *Service) loadACMESettings() (acmeSettings, *CertError) {
	settings := defaultACMESettings()
	raw, err := os.ReadFile(s.store.acmeSettingsPath())
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return acmeSettings{}, internalErr("读取 ACME 设置失败: " + err.Error())
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return settings, nil
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return acmeSettings{}, newCertHintError(codeInternal,
			"ACME 设置文件损坏: "+err.Error(),
			"删除 "+s.store.acmeSettingsPath()+" 后重新配置（证书与账户密钥不受影响）")
	}
	if settings.Schema == 0 {
		settings.Schema = acmeSettingsSchema
	}
	if settings.CA == "" {
		settings.CA = acmeproto.CAStaging
	}
	if settings.DaysBefore == 0 {
		settings.DaysBefore = acmeDefaultDaysBefore
	}
	return settings, nil
}

// saveACMESettings 原子写入设置（0600；目录 0700）。
func (s *Service) saveACMESettings(settings acmeSettings) *CertError {
	if err := ensurePrivateDir(s.store.acmeDir()); err != nil {
		return internalErr("创建 ACME 状态目录失败: " + err.Error())
	}
	path := s.store.acmeSettingsPath()
	if err := s.store.withinDir(path); err != nil {
		return internalErr("ACME 设置路径越界: " + err.Error())
	}
	settings.Schema = acmeSettingsSchema
	settings.UpdatedAt = nowOr(s.now).UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return internalErr("序列化 ACME 设置失败: " + err.Error())
	}
	if err := atomicWriteFile(path, append(raw, '\n'), keyFileMode); err != nil {
		return internalErr("写入 ACME 设置失败: " + err.Error())
	}
	return nil
}

// loadACMEAccount 读取账户元数据（不存在返回 ok=false）。
func (s *Service) loadACMEAccount(caID string) (acmeAccount, bool) {
	raw, err := os.ReadFile(filepath.Join(s.store.acmeAccountDir(caID), acmeAccountMetaFileName))
	if err != nil {
		return acmeAccount{}, false
	}
	var acct acmeAccount
	if err := json.Unmarshal(raw, &acct); err != nil || acct.KID == "" {
		return acmeAccount{}, false
	}
	return acct, true
}

// saveACMEAccount 原子写入账户元数据（0600）。
func (s *Service) saveACMEAccount(caID string, acct acmeAccount) error {
	dir := s.store.acmeAccountDir(caID)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dir, acmeAccountMetaFileName), append(raw, '\n'), keyFileMode)
}

// accountKey 读取或创建账户私钥（P-256，PKCS#8 PEM，0600，落在账户目录内）。
//
// 账户私钥是身份凭证：与证书私钥同等保护级别，绝不进返回值/日志/审计。
func (s *Service) accountKey(caID string) (*ecdsa.PrivateKey, error) {
	dir := s.store.acmeAccountDir(caID)
	path := filepath.Join(dir, acmeAccountKeyFileName)
	raw, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("账户私钥不是 PEM")
		}
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("账户私钥不是 ECDSA（只支持 P-256）")
		}
		if ecdsaKey.Curve != elliptic.P256() {
			return nil, errors.New("账户私钥不是 P-256")
		}
		if err := os.Chmod(path, keyFileMode); err != nil {
			return nil, err
		}
		return ecdsaKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	key, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if genErr != nil {
		return nil, genErr
	}
	der, marshalErr := x509.MarshalPKCS8PrivateKey(key)
	if marshalErr != nil {
		return nil, marshalErr
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := atomicWriteFile(path, encoded, keyFileMode); err != nil {
		return nil, err
	}
	return key, nil
}

// appendACMEAudit 追加一条审计记录；写失败不影响业务结果（审计是旁路，不是前置条件）。
func (s *Service) appendACMEAudit(entry acmeAuditEntry) {
	entry.At = nowOr(s.now).UTC().Format(time.RFC3339)
	if len(entry.Reason) > acmeAuditReasonMax {
		entry.Reason = entry.Reason[:acmeAuditReasonMax] + "..."
	}
	dir := s.store.acmeDir()
	if err := ensurePrivateDir(dir); err != nil {
		return
	}
	path := filepath.Join(dir, acmeAuditFileName)
	if info, err := os.Stat(path); err == nil && info.Size() > acmeAuditMaxBytes {
		_ = os.Rename(path, filepath.Join(dir, acmeAuditRotatedName))
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, keyFileMode)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	_, _ = file.Write(append(raw, '\n'))
}

// acmeAuditTail 读取最近 limit 条审计（解析失败的行跳过，不让坏记录拖垮 status）。
func (s *Service) acmeAuditTail(limit int) []acmeAuditEntry {
	if limit <= 0 {
		limit = acmeAuditTailMax
	}
	raw, err := os.ReadFile(filepath.Join(s.store.acmeDir(), acmeAuditFileName))
	if err != nil {
		return []acmeAuditEntry{}
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	entries := make([]acmeAuditEntry, 0, limit)
	for index := len(lines) - 1; index >= 0 && len(entries) < limit; index-- {
		line := strings.TrimSpace(lines[index])
		if line == "" {
			continue
		}
		var entry acmeAuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	// 最近的在前；调用方展示时按时间倒序即可。
	return entries
}
