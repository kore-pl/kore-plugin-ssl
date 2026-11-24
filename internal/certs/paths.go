package certs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// 证书目录解析（G-31 零侵入）：
//
//  1. KORE_SSL_CERT_DIR（显式覆盖，用户自己指定，可用于指回旧目录）
//  2. **<KORE_INSTALL_DIR>/data/ssl —— 默认值，也是唯一「契约位置」**：
//     ADR-0023 §3.4 方案 C 把证书钉在 `<install>/data/ssl`；ADR-0052 §104 要求站点配置里
//     的证书/私钥路径必须落在 kore 证书目录（`data/ssl`）内；
//     安装器 `scripts/install-root-once.sh` 注入的受控写白名单前缀正是
//     `<install>/data/ssl/`。三者必须是同一个目录，否则 site 绑定时被受控写拒绝。
//  3. <KORE_STATE_DIR>/ssl —— 兼容兜底（内核未注入 KORE_INSTALL_DIR 时）。
//     注意：内核实际注入的 state 是 `<install>/data/plugins/<id>`，直接拿它 join "ssl"
//     得到 `<install>/data/plugins/ssl/ssl`，**不在白名单内**——这正是本文件 0.7.1 修掉的
//     缺陷，所以它只能在拿不到 install 根时兜底，不能当默认值。
//  4. 便携兜底：<插件二进制目录>/../data/ssl（仍在安装目录内）
//
// 0.4.0 及以前默认写 /etc/kore/ssl。零侵入规范后**不再默认写该路径**：仍存在的旧安装
// 用 KORE_SSL_CERT_DIR=/etc/kore/ssl 显式指回即可（status 会提示检测到旧目录）。
const (
	// kernelStateEnv 是内核给插件注入的 state 目录环境变量名。
	kernelStateEnv = "KORE_STATE_DIR"
	// installDirEnv 是内核给插件注入的安装根（ADR-0023 §3.1 的 <install>）。
	installDirEnv = "KORE_INSTALL_DIR"
	// installCertSubdir 是安装根下的契约证书目录（ADR-0023 §3.4 / ADR-0052 §104），
	// 必须与 scripts/install-root-once.sh 默认注入的白名单前缀逐字一致。
	installCertSubdir = "data/ssl"
	// portableDataSubdir 是便携兜底相对可执行文件的路径（data/ssl）。
	portableDataSubdir = "data/ssl"
)

// CertDirSource 描述证书目录来自哪一层配置（展示与审计用）。
type CertDirSource string

const (
	// DirSourceEnv：KORE_SSL_CERT_DIR 显式指定。
	DirSourceEnv CertDirSource = "env"
	// DirSourceInstall：<KORE_INSTALL_DIR>/data/ssl（默认；与安装器受控写白名单同前缀）。
	DirSourceInstall CertDirSource = "install-dir"
	// DirSourceKernelState：<KORE_STATE_DIR>/ssl（兼容兜底，内核未注入 KORE_INSTALL_DIR 时）。
	DirSourceKernelState CertDirSource = "kernel-state"
	// DirSourcePortable：可执行文件旁的 data/ssl。
	DirSourcePortable CertDirSource = "portable"
)

// ResolveCertDir 返回证书目录与来源。
func ResolveCertDir() (string, CertDirSource) {
	if dir := strings.TrimSpace(os.Getenv(DirEnv)); dir != "" {
		return dir, DirSourceEnv
	}
	// 契约位置优先：安装器注入的受控写白名单前缀是 `<install>/data/ssl/`，
	// site 把本仓返回的 cert_path 写进站点配置时要过那道白名单，所以默认目录必须就是它。
	if install := strings.TrimSpace(os.Getenv(installDirEnv)); install != "" {
		return filepath.Join(install, installCertSubdir), DirSourceInstall
	}
	// 兜底：只在内核没注入安装根时使用（旧口径 `<state>/ssl`，可能不在白名单内）。
	if state := strings.TrimSpace(os.Getenv(kernelStateEnv)); state != "" {
		return filepath.Join(state, "ssl"), DirSourceKernelState
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Clean(filepath.Join(filepath.Dir(exe), "..", portableDataSubdir)), DirSourcePortable
	}
	return filepath.Clean(portableDataSubdir), DirSourcePortable
}

// legacyCertDir 是旧默认目录；仅用于"检测到但未启用"的提示，不再自动写入。
const legacyCertDir = "/etc/kore/ssl"

// legacyCertDirHasCerts 判断旧目录是否存在且至少有一张证书（只读探测）。
func legacyCertDirHasCerts() bool {
	entries, err := os.ReadDir(legacyCertDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, certSuffix) || strings.HasSuffix(name, pemSuffix) {
			return true
		}
	}
	return false
}

// stateDir 返回 <KORE_STATE_DIR>（未注入时为空字符串），供状态展示。
func stateDir() string { return strings.TrimSpace(os.Getenv(kernelStateEnv)) }

// errNoCertDir 是解析失败时的兜底错误（当前实现不会返回，保留给未来的显式校验）。
var errNoCertDir = errors.New("无法确定证书目录")
