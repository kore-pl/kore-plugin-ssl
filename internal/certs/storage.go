package certs

import (
	"os"
	"path/filepath"
	"strings"
)

// 存储分层（ADR-0023 阶段 C）。
//
// 硬冲突：证书与私钥必须被 web server（nginx 以 www-data/root 运行）读取，而插件以
// kore-<id> 运行。把证书塞进 0700 的插件私有目录会让站点直接起不来——这不是"改默认值"
// 能解决的。因此分两类：
//
//   - **可迁**：插件自有元数据（backups/、bindings.json、acme/ 的设置/审计/账户密钥），
//     没有任何 web server 读取需求 → 默认落在 $KORE_PLUGIN_DATA（0700，属主 kore-<id>），
//     删安装目录即清零。
//   - **不可迁**：证书 / 私钥 / 链 / .acme 标记留在证书目录（系统路径）。这属于
//     ADR-0023 §3.5 豁免 #3「用户批准的宿主变更」——由用户显式指定路径，web server 读取；
//     本仓只在 status/list 里如实标注"哪些在外、为什么必须在外"。
const (
	// PluginDataEnv 是内核注入的插件数据根（0700，属主 kore-<id>）。
	PluginDataEnv = "KORE_PLUGIN_DATA"
	// InstallDirEnv 是内核注入的安装根，用于判断某路径是否已在安装目录内。
	InstallDirEnv = "KORE_INSTALL_DIR"
	// pluginDataSSLSubdir 是元数据在插件数据根下的子目录。
	pluginDataSSLSubdir = "ssl"
)

// ResolveMetaDir 解析"插件元数据根"：
//
//  1. 显式 MetaDir（Options，测试/高级配置）
//  2. $KORE_PLUGIN_DATA/ssl —— 内核阶段 C 的默认值
//  3. 回退证书目录（阶段 C 之前的行为，保持完全向后兼容）
func ResolveMetaDir(certDir string) string {
	if data := strings.TrimSpace(os.Getenv(PluginDataEnv)); data != "" {
		return filepath.Join(data, pluginDataSSLSubdir)
	}
	return certDir
}

// StoragePath 是"某个存储路径 + 它为什么在那里"的说明。
type StoragePath struct {
	Path          string `json:"path"`
	Kind          string `json:"kind"`
	InsideInstall bool   `json:"inside_install"`
	Reason        string `json:"reason"`
}

// StorageInfo 是 status/list 的存储标注：显式告诉前端哪些可迁、哪些必须留系统路径。
type StorageInfo struct {
	PortableRoot string        `json:"portable_root,omitempty"`
	InstallDir   string        `json:"install_dir,omitempty"`
	CertDir      string        `json:"cert_dir"`
	MetaDir      string        `json:"meta_dir"`
	Portable     bool          `json:"portable"`
	SystemPaths  []StoragePath `json:"system_paths"`
	Hint         string        `json:"hint"`
}

// storageInfo 汇总当前实例的存储分布（只读环境变量与已解析目录，不探测磁盘）。
func (s *Service) storageInfo() StorageInfo {
	portableRoot := strings.TrimSpace(os.Getenv(PluginDataEnv))
	installDir := strings.TrimSpace(os.Getenv(InstallDirEnv))
	info := StorageInfo{
		PortableRoot: portableRoot,
		InstallDir:   installDir,
		CertDir:      s.store.dir,
		MetaDir:      s.store.metaDir,
		Portable:     portableRoot != "" && pathWithin(s.store.metaDir, portableRoot),
		SystemPaths:  []StoragePath{},
	}
	if !pathWithin(info.CertDir, installDir) {
		info.SystemPaths = append(info.SystemPaths, StoragePath{
			Path: info.CertDir, Kind: "certs+keys", InsideInstall: false,
			Reason: "证书/私钥由 web server 读取（site 插件写站点配置并 reload，nginx 以 www-data/root 运行）：" +
				"属 ADR-0023 §3.5 豁免 #3 用户批准的宿主变更，不能放进 0700 的插件私有目录",
		})
	}
	if info.MetaDir != info.CertDir && !pathWithin(info.MetaDir, installDir) {
		info.SystemPaths = append(info.SystemPaths, StoragePath{
			Path: info.MetaDir, Kind: "metadata", InsideInstall: false,
			Reason: "元数据（备份/归属登记/ACME 状态）为兼容旧部署保留在旧位置；新装会落在 $KORE_PLUGIN_DATA",
		})
	}
	switch {
	case portableRoot == "":
		info.Hint = "未注入 KORE_PLUGIN_DATA：元数据仍与证书同目录（portable=false）；内核阶段 C 后自动迁到 <install>/data"
	case s.store.metaDir == s.store.dir:
		info.Hint = "KORE_PLUGIN_DATA 已注入但元数据仍与证书同目录：检查显式配置"
	case !pathWithin(info.CertDir, installDir):
		info.Hint = "元数据已 portable（$KORE_PLUGIN_DATA）；证书/私钥在系统路径供 web server 读取（system_paths 已标注原因）"
	default:
		info.Hint = "证书目录在安装目录内：若站点以独立用户（www-data）运行可能读不到证书，用 KORE_SSL_CERT_DIR 指向系统可读路径"
	}
	return info
}

// pathWithin 判断 path 是否落在 root 之内（root 为空或 path 为空时返回 false）。
func pathWithin(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	if absPath == absRoot {
		return true
	}
	return strings.HasPrefix(absPath, absRoot+string(filepath.Separator))
}
