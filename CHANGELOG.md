# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-11-23

- build: 位级可复现打包（stage chmod + tar --mode 归一、size_bytes 收敛），二进制改嵌 manifest.json，消除同版本 sha 漂移

## [0.2.0] - 2026-11-22

### Added

- **真实证书管理**（去骨架）：证书全部落盘在固定目录 `KORE_SSL_CERT_DIR`
  （默认 `/etc/kore/ssl`），不再只在内存维护桩记录。
- `ssl.list`：扫描目录下 `*.crt` / `*.pem`，用 `crypto/x509` 真实解析
  `domains(SAN+CN) / not_before / not_after / days_left / issuer / serial /
  is_ca / key_type+key_bits / chain_length / fingerprint_sha256 / self_signed /
  source`；过期与临期（<30 天）分别标记；单张解析失败只写该条目的 `error`，
  不影响其它条目；同一证书多文件名按指纹去重。
- `ssl.import`：证书 + 私钥三重校验后原子落盘——证书可解析、SAN 覆盖 domain
  （DNS 精确/通配符一级子域/IP SAN）、私钥为未加密 PEM 且与证书匹配
  （`tls.X509KeyPair`）；拒绝 PKCS#8 加密私钥、`Proc-Type: 4,ENCRYPTED`
  传统加密块与 OpenSSH 私钥；可选 `chain_pem` 写入独立链文件。
- `ssl.selfsign`：用 `crypto/rsa` 2048 或 `crypto/ecdsa` P-256 真签发证书
  （`x509.CreateCertificate`），支持 `days` 与可选 `extra_sans`（DNS/IP）；
  IP 主体进入 `IPAddresses`，可直接用于 TLS 握手。
- `ssl.renew`：自签证书重新签发（新密钥 + 新序列号，保留原文件名、密钥类型与
  附加 SAN）；ACME 证书返回 `E_UNSUPPORTED` 并说明"ACME 续期需要 ACME 客户端，
  当前版本未实现，请在 v1.1 跟进"；其它 CA 证书同样如实返回 `E_UNSUPPORTED`。
- `ssl.verify`：`tls.DialWithDialer` 真实握手探测 `host` 或 `host:port`
  （默认 443），10s 超时；返回 `reachable / matched / not_after / days_left /
  issuer / serial / self_signed / chain_length / fingerprint_sha256 / error`，
  连接失败是观测值（`reachable=false` + `error`），不返回 500。
- 真实 E2E（`tests/e2e`）：插件二进制 + UDS → 自签 → list → 起真实 TLS 服务
  并用 `curl -k` 验证 → verify → 导入不匹配私钥被拒 → 自签续期 → ACME 续期
  如实拒绝 → 优雅退出；含 TLS 握手真实验证。
- `ssl.issue` 兼容入口保留，但明确返回 `E_UNSUPPORTED`：ACME 签发未实现，
  不返回假证书（v1.1 跟进）。

### Security

- 私钥不进入任何返回结构、错误消息与日志（覆盖写入前仅做内存回滚快照）；
  `list` 只解析证书公钥信息。
- 写入权限：私钥 `0600`、证书/链 `0644`、证书目录 `0700`；同目录临时文件 +
  `fsync` + `rename` 原子替换，多文件写入失败按快照整组回滚。
- 目录固定（`KORE_SSL_CERT_DIR`），不接受 RPC 入参指定路径；域名白名单正则 +
  至少两个标签，文件名再经 `withinDir` 二次校验。
- 不联网：除 `ssl.verify` 的用户显式请求外无任何出站连接；不引入第三方 ACME
  库，仅依赖 Go 标准库 + `pluginapi`（G-17）。

### Changed

- 故障注入从 `StubIssuer` 改为方法入口的 `Fault`（`KORE_FAULT`），四类故障
  （kill / timeout / disk-full / cgroup-limit）驱动真实方法并断言不落半成品；
  timeout 另加一次真实 TLS 握手超时探测。
- 版本号 0.1.0 → 0.2.0（能力从占位升级为真实证书管理）。

### Removed

- `internal/certs` 的 `Issuer` / `StubIssuer` 桩签发通道（不再返回 `source=stub`
  的假证书）。

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
