// Package main 是 kore 的 ssl 插件：TLS 证书真实管理（扫描 / 导入 / 自签 / 续期判定 / TLS 探测）。
//
// 业务层 internal/certs 只用 Go 标准库实现，不引入第三方 ACME 库、不捆绑
// certbot/acme 二进制；v1 不实现 ACME 自动签发与续期，ssl.renew 对 ACME 证书
// 如实返回 E_UNSUPPORTED（v1.1 跟进）。续期触发由内核按 event:cert.renew_due
// 投递，插件内部不起 ticker（G-19）。
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
	svc := certs.NewService(certs.Options{Fault: certs.ParseFault(cfg.fault)})
	return serve(conn, cfg, svc, logger)
}
