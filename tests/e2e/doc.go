//go:build linux && (amd64 || arm64 || riscv64 || loong64)

// Package e2e 用真实插件二进制 + UDS 跑 ssl 插件的完整闭环：
// 自签 → 列表 → 起真实 TLS 服务并用 curl 验证 → TLS 探测 → 导入（含不匹配拒绝）
// → 自签续期 → ACME 证书续期如实拒绝 → 优雅退出。
//
// 不依赖 docker / 外部网络：TLS 服务跑在本进程内，探测目标是 127.0.0.1 回环。
package e2e
