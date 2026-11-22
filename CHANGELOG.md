# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-22

### Added

- SSL 插件骨架：kore.plugin.v1 握手 + 会话循环 + lazy 生命周期，续期走
  `event:cert.renew_due` 事件触发。
- 三个业务方法 `ssl.list` / `ssl.issue` / `ssl.renew`：域名与邮箱参数校验 +
  结构化结果；签发通道抽象为 `Issuer` 接口，默认 `StubIssuer` 不连真实 CA
  （与 site M4-B 同口径）。
- 四类故障注入测试（G-20 / S-04）：kill / timeout / disk(ENOSPC) / cgroup(OOM)，
  方法级错误返回与状态污染断言。
- Makefile `build` / `dist` / `check`：确定性打包（`--sort=name` + 固定 mtime/uid/gid
  + `gzip -9n`），`GOWORK=off` 隔离外部 workspace。
- MIT LICENSE（pengtang1024）。
