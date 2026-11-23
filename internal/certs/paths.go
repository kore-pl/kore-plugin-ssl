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
//  2. <KORE_STATE_DIR>/ssl —— 内核注入 state 目录（ADR-0023 后即 <install>/data），
//     这是默认值：证书、ACME 账户密钥、审计、配置全在安装目录内，删安装目录即清零
//  3. 便携兜底：<插件二进制目录>/../data/ssl（仍在安装目录内）
//
// 0.4.0 及以前默认写 /etc/kore/ssl。零侵入规范后**不再默认写该路径**：仍存在的旧安装
// 用 KORE_SSL_CERT_DIR=/etc/kore/ssl 显式指回即可（status 会提示检测到旧目录）。
const (
	// kernelStateEnv 是内核给插件注入的 state 目录环境变量名。
	kernelStateEnv = "KORE_STATE_DIR"
	// portableDataSubdir 是便携兜底相对可执行文件的路径（data/ssl）。
	portableDataSubdir = "data/ssl"
)

// CertDirSource 描述证书目录来自哪一层配置（展示与审计用）。
type CertDirSource string

const (
	// DirSourceEnv：KORE_SSL_CERT_DIR 显式指定。
	DirSourceEnv CertDirSource = "env"
	// DirSourceKernelState：<KORE_STATE_DIR>/ssl（默认）。
	DirSourceKernelState CertDirSource = "kernel-state"
	// DirSourcePortable：可执行文件旁的 data/ssl。
	DirSourcePortable CertDirSource = "portable"
)

// ResolveCertDir 返回证书目录与来源。
func ResolveCertDir() (string, CertDirSource) {
	if dir := strings.TrimSpace(os.Getenv(DirEnv)); dir != "" {
		return dir, DirSourceEnv
	}
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
