package certs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DirFromEnv 返回证书根目录：KORE_SSL_CERT_DIR 覆盖，未配置时用 /etc/kore/ssl。
// 目录只来自运维环境变量，不接受任何 RPC 入参指定路径。
func DirFromEnv() string {
	if dir := strings.TrimSpace(os.Getenv(DirEnv)); dir != "" {
		return dir
	}
	return DefaultDir
}

// certStore 封装固定证书目录下的文件命名、原子写入与扫描。
// 所有写操作遵循：同目录临时文件 → fsync → rename；失败按快照恢复原状态。
type certStore struct {
	dir string
}

// newCertStore 构造 store；空目录回退默认目录。
func newCertStore(dir string) *certStore {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultDir
	}
	return &certStore{dir: dir}
}

// backupDirName 是续期前旧证书的备份子目录名。
// 放在证书目录下的独立子目录：scan 只读顶层文件并跳过目录，备份不会混进 ssl.list。
const backupDirName = "backups"

// backupKeep 是每张证书保留的历史备份份数上限（按时间戳倒序保留最新 N 份）。
const backupKeep = 5

// certPath 返回域名对应的证书路径（写 .crt）。
func (s *certStore) certPath(domain string) string {
	return filepath.Join(s.dir, domain+certSuffix)
}

// ensureDir 创建证书目录并强制 0700（已存在时也收紧权限，不让组/其他用户读私钥）。
func (s *certStore) ensureDir() error {
	if err := os.MkdirAll(s.dir, dirMode); err != nil {
		return fmt.Errorf("创建证书目录 %s: %w", s.dir, err)
	}
	if err := os.Chmod(s.dir, dirMode); err != nil {
		return fmt.Errorf("设置证书目录权限 %s: %w", s.dir, err)
	}
	return nil
}

// withinDir 确认路径落在证书目录内（双保险：即使 base 被污染也无法写出目录）。
func (s *certStore) withinDir(path string) error {
	dirAbs, err := filepath.Abs(s.dir)
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(dirAbs, pathAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("路径 %s 不在证书目录内", path)
	}
	return nil
}

// atomicWriteFile 把内容写到同目录临时文件（指定权限 + fsync）再 rename 覆盖目标。
func atomicWriteFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kore-ssl-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时文件: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("设置临时文件权限: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("写临时文件: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("同步临时文件: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("关闭临时文件: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("原子替换 %s: %w", path, err)
	}
	return nil
}

// fileState 记录单个文件被改动前的字节与权限，用于写入失败后的原样恢复。
type fileState struct {
	path   string
	data   []byte
	mode   os.FileMode
	exists bool
}

// snapshot 读取文件当前状态；不存在也是合法状态（exists=false）。
func snapshot(path string) (fileState, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileState{path: path}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fileState{}, err
	}
	return fileState{path: path, data: data, mode: info.Mode().Perm(), exists: true}, nil
}

// restore 把文件恢复成快照状态：原本存在则原子写回并还原权限，原本不存在则删除。
func (s fileState) restore() error {
	if !s.exists {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("删除 %s: %w", s.path, err)
		}
		return nil
	}
	if err := atomicWriteFile(s.path, s.data, s.mode); err != nil {
		return fmt.Errorf("恢复 %s: %w", s.path, err)
	}
	return nil
}

// restoreAll 按快照顺序恢复，多个错误合并上报。
func restoreAll(states []fileState) error {
	var problems []string
	for _, state := range states {
		if err := state.restore(); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// writePair 原子写入证书与私钥（可选独立链），任一步失败都恢复到写入前状态。
// certFileName 是证书目录内的文件名（.crt 或 .pem），私钥与链按同前缀派生；
// 传入文件名而不是前缀，是为了续期/覆盖导入时保住用户原有的文件后缀。
func (s *certStore) writePair(certFileName string, certPEM, keyPEM, chainPEM []byte) error {
	if certFileName == "" || certFileName != filepath.Base(certFileName) || strings.Contains(certFileName, "..") {
		return fmt.Errorf("非法证书文件名 %q", certFileName)
	}
	if !strings.HasSuffix(certFileName, certSuffix) && !strings.HasSuffix(certFileName, pemSuffix) {
		return fmt.Errorf("证书文件名必须以 %s 或 %s 结尾: %q", certSuffix, pemSuffix, certFileName)
	}
	if err := s.ensureDir(); err != nil {
		return err
	}
	base := trimCertSuffix(certFileName)
	certPath := filepath.Join(s.dir, certFileName)
	keyPath := filepath.Join(s.dir, base+keySuffix)
	chainPath := filepath.Join(s.dir, base+chainSuffix)
	for _, path := range []string{certPath, keyPath, chainPath} {
		if err := s.withinDir(path); err != nil {
			return err
		}
	}
	states := make([]fileState, 0, 3)
	for _, path := range []string{certPath, keyPath, chainPath} {
		state, err := snapshot(path)
		if err != nil {
			return fmt.Errorf("读取原状态 %s: %w", path, err)
		}
		states = append(states, state)
	}

	// 先写私钥（0600），再写证书（0644），最后写链；顺序不影响原子性，失败统一回滚。
	if err := atomicWriteFile(keyPath, keyPEM, keyFileMode); err != nil {
		_ = restoreAll(states)
		return fmt.Errorf("写入私钥失败: %w", err)
	}
	if err := atomicWriteFile(certPath, certPEM, certFileMode); err != nil {
		if rbErr := restoreAll(states); rbErr != nil {
			return fmt.Errorf("写入证书失败: %w；回滚失败: %v", err, rbErr)
		}
		return fmt.Errorf("写入证书失败: %w", err)
	}
	if len(chainPEM) > 0 {
		if err := atomicWriteFile(chainPath, chainPEM, certFileMode); err != nil {
			if rbErr := restoreAll(states); rbErr != nil {
				return fmt.Errorf("写入证书链失败: %w；回滚失败: %v", err, rbErr)
			}
			return fmt.Errorf("写入证书链失败: %w", err)
		}
	} else if states[2].exists {
		// 覆盖导入时显式去掉旧的独立链，避免证书与链版本错配。
		if err := os.Remove(chainPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			if rbErr := restoreAll(states); rbErr != nil {
				return fmt.Errorf("清理旧证书链失败: %w；回滚失败: %v", err, rbErr)
			}
			return fmt.Errorf("清理旧证书链失败: %w", err)
		}
	}
	return nil
}

// scan 扫描证书目录下所有 *.crt / *.pem（跳过独立 chain 文件），
// 单条解析失败只在该条目写 error，不影响其它条目。
func (s *certStore) scan(now time.Time) ([]CertInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return []CertInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	infos := make([]CertInfo, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !isCertFileName(name) {
			continue
		}
		path := filepath.Join(s.dir, name)
		info, parseErr := inspectCertFile(path, now)
		if parseErr != nil {
			infos = append(infos, CertInfo{
				Domain: trimCertSuffix(name),
				File:   name,
				Error:  parseErr.Error(),
			})
			continue
		}
		if _, ok := seen[info.FingerprintSHA256]; ok {
			// 同一张证书以不同文件名重复存放时只列一次，避免界面重复。
			continue
		}
		seen[info.FingerprintSHA256] = struct{}{}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Domain != infos[j].Domain {
			return infos[i].Domain < infos[j].Domain
		}
		return infos[i].File < infos[j].File
	})
	return infos, nil
}

// isCertFileName 判断文件名是否属于需要扫描的证书文件。
func isCertFileName(name string) bool {
	if strings.HasSuffix(name, keySuffix) || strings.HasSuffix(name, chainSuffix) {
		return false
	}
	return strings.HasSuffix(name, certSuffix) || strings.HasSuffix(name, pemSuffix)
}

// findCert 按域名定位已有证书：先精确匹配 <domain>.crt / <domain>.pem，
// 再扫描目录按主域名或 SAN 精确匹配（用于导入时使用了非标准文件名的场景）。
func (s *certStore) findCert(domain string, now time.Time) (string, CertInfo, error) {
	for _, path := range []string{s.certPath(domain), filepath.Join(s.dir, domain+pemSuffix)} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			parsed, parseErr := inspectCertFile(path, now)
			if parseErr != nil {
				return "", CertInfo{}, fmt.Errorf("%s 解析失败: %w", filepath.Base(path), parseErr)
			}
			return path, parsed, nil
		}
	}
	infos, err := s.scan(now)
	if err != nil {
		return "", CertInfo{}, err
	}
	for _, info := range infos {
		if info.Error != "" {
			continue
		}
		if info.Domain == domain || containsString(info.Domains, domain) {
			return filepath.Join(s.dir, info.File), info, nil
		}
	}
	return "", CertInfo{}, os.ErrNotExist
}

// containsString 判断切片是否包含目标值。
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// backupPair 在覆盖证书前把现有证书 / 私钥 / 独立链复制到 <dir>/backups/<base>-<ts>.*，
// 返回备份目录的绝对路径。证书文件不存在时返回空路径（无内容可备份，不算失败）。
//
// 备份先于续期执行：只有备份成功才允许覆盖，续期失败时旧证书仍在磁盘上可回滚。
// 超过 backupKeep 份的历史备份按时间戳倒序清理（清理失败不阻断续期，只影响体积）。
func (s *certStore) backupPair(certFileName string, now time.Time) (string, error) {
	base := trimCertSuffix(certFileName)
	certPath := filepath.Join(s.dir, certFileName)
	certData, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("读取待备份证书 %s: %w", certPath, err)
	}
	backupDir := filepath.Join(s.dir, backupDirName)
	if err := os.MkdirAll(backupDir, dirMode); err != nil {
		return "", fmt.Errorf("创建备份目录 %s: %w", backupDir, err)
	}
	if err := os.Chmod(backupDir, dirMode); err != nil {
		return "", fmt.Errorf("设置备份目录权限 %s: %w", backupDir, err)
	}
	stamp := now.UTC().Format("20060102T150405Z")
	stem := base + "-" + stamp
	// 证书 0644；私钥 0600（备份同样不能放宽私钥权限）；链 0644。
	if err := atomicWriteFile(filepath.Join(backupDir, stem+certSuffix), certData, certFileMode); err != nil {
		return "", fmt.Errorf("备份证书: %w", err)
	}
	for _, item := range []struct {
		suffix string
		mode   os.FileMode
	}{
		{keySuffix, keyFileMode},
		{chainSuffix, certFileMode},
	} {
		data, readErr := os.ReadFile(filepath.Join(s.dir, base+item.suffix))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return "", fmt.Errorf("读取待备份文件 %s: %w", base+item.suffix, readErr)
		}
		if err := atomicWriteFile(filepath.Join(backupDir, stem+item.suffix), data, item.mode); err != nil {
			return "", fmt.Errorf("备份 %s: %w", item.suffix, err)
		}
	}
	pruneBackups(backupDir, base)
	abs, absErr := filepath.Abs(backupDir)
	if absErr != nil {
		return backupDir, nil
	}
	return abs, nil
}

// pruneBackups 只保留某张证书最新的 backupKeep 份备份（按文件名里的时间戳排序）。
// 删除失败不返回错误：备份的价值在"有"，清理只是控制体积。
func pruneBackups(backupDir, base string) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return
	}
	stems := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, base+"-") {
			continue
		}
		for _, suffix := range []string{chainSuffix, certSuffix, keySuffix} {
			if trimmed, ok := strings.CutSuffix(name, suffix); ok {
				stems[trimmed] = struct{}{}
				break
			}
		}
	}
	if len(stems) <= backupKeep {
		return
	}
	ordered := make([]string, 0, len(stems))
	for stem := range stems {
		ordered = append(ordered, stem)
	}
	// 时间戳是 20060102T150405Z 定宽格式，字典序即时间序。
	sort.Sort(sort.Reverse(sort.StringSlice(ordered)))
	for _, stem := range ordered[backupKeep:] {
		for _, suffix := range []string{certSuffix, keySuffix, chainSuffix} {
			_ = os.Remove(filepath.Join(backupDir, stem+suffix))
		}
	}
}
