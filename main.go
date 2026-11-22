// Package main 是 kore 的 ssl 插件：SSL 证书签发 / 自动续期 / 部署的骨架实现。
//
// 与 site（M4-B）同口径：只做参数校验 + 结构化结果，通过可注入的 Issuer 接口
// 预留 ACME 通道；当前默认 StubIssuer 不连任何真实 CA，不捆绑 certbot/acme 二进制。
// 续期触发由内核按 event:cert.renew_due 投递，插件内部不起 ticker（G-19）。
//
// 协议面（kore.plugin.v1）：连接内核注入的 UDS → kore.hello 握手 → 会话循环
// 读 request、按 method 分发并回 response；stdout 留给协议，日志一律写 stderr。
package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
)

// main 按退出码区分失败：0 优雅退出、1 启动或协议失败。
func main() {
	logger := newLogger(os.Getenv("KORE_LOG_LEVEL"))
	if err := run(logger); err != nil {
		logger.Error("插件退出", "err", err)
		os.Exit(1)
	}
}

// run 依次完成建连、hello 握手与会话循环；收到 kore.shutdown 后返回 nil。
func run(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	conn, err := net.Dial("unix", cfg.socket)
	if err != nil {
		return fmt.Errorf("连接主壳 socket %s: %w", cfg.socket, err)
	}
	defer func() { _ = conn.Close() }()
	if err := handshake(conn, cfg); err != nil {
		return err
	}
	logger.Info("hello 完成", "plugin_id", cfg.id, "version", cfg.version)
	svc := certs.NewService(nil) // 默认 StubIssuer：不连真实 CA
	return serve(conn, cfg, svc, logger)
}
