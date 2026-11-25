> 状态: draft · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-ssl

本仓实现 kore 的 TLS 证书管理插件（id `ssl`）。证书目录固定为 `KORE_SSL_CERT_DIR`（默认 `/etc/kore/ssl`），RPC 不接受任意路径；所有操作读写真实文件，进程内不维护假清单。只用 Go 标准库 + pluginapi，不引入第三方 ACME 库、不捆绑 certbot/acme 二进制。`lifecycle=lazy`，续期由内核事件触发，插件内部不起 ticker。不写 web 服务器配置：站点绑定与 80→443 跳转归 site 插件，本仓只登记归属、给出推荐载荷、只读判定实际行为。

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## 它做什么

- **协议面**：`kore.plugin.v1`，`lifecycle=lazy`，`depth_level=production`。
- **方法**：`ssl.list` / `import` / `selfsign` / `renew` / `verify` / `expiring` / `renew.set` / `acme.status` / `acme.issue` 等；`verify` 做真实 TLS 握手探测。
- **真实文件**：证书目录固定，RPC 不接受任意路径；逐张解析真实证书，不维护内存假清单。
- **只读边界**：`site.bindSSL` / `unbindSSL` / `setRedirect` 属 site 插件；本仓只登记归属、给推荐载荷，越权路径由 `boundary_test.go` 断言拦住。
- **零 ticker**：续期由内核按 `event:cert.renew_due` 触发，插件不常驻、不起定时器。
- **ACME**：内置签发，也可 `engine=external` 走 certbot/acme.sh；`acme.status` 只读探测本机客户端。

## 快速开始

```bash
make check    # gofmt → vet → test
make build    # 构建插件二进制
make dist     # 产出发布 tarball
```

插件由 kore 主壳按需拉起；`info.json` 声明能力与 `requires_kore` 区间。

## 安全与边界

漏洞披露走 [SECURITY.md](../SECURITY.md)

## 文档导航

[SECURITY.md](../SECURITY.md) — 漏洞披露流程。
[CONTRIBUTING.md](../CONTRIBUTING.md) — 提交与发版规范。
[CHANGELOG.md](../CHANGELOG.md) — 版本变更记录。
[info.json](../info.json) — 能力与版本声明。

## 常见问题

**问：需要注册账号才能用吗？**
不需要。没有账号、无联网校验、无隐藏上报；配置明文，看得懂也改得动。

**问：插件住在哪？**
插件住在各自 `kore-plugin-<id>` 仓，只依赖 `kore/pkg/pluginapi`。

**问：我该先读什么？**
先看 README 的协议面与方法表，再看 `info.json` 的能力声明。
