# kore-plugin-ssl

kore 的 SSL 证书插件（M5 批 1 · 生产级）：SSL 证书签发 / 自动续期 / 部署的骨架实现。

## 定位（与 site M4-B 同口径）

- **只做参数校验 + 结构化结果**，通过可注入的 `Issuer` 接口预留 ACME 通道；
  默认 `StubIssuer` **不连接任何真实 CA**，真 CA 留后续。
- **不内置 web server / cert 工具二进制**（裁决 37），不捆绑 certbot / acme 客户端。
- `lifecycle=lazy`：不常驻；续期由内核按 `event:cert.renew_due` 事件触发，
  插件内部不起 ticker（G-19）。

## 协议面（kore.plugin.v1）

- 连接内核注入的 UDS（`KORE_PLUGIN_SOCK`）→ `kore.hello` 握手 → 会话循环。
- `stdout` 留给协议帧，日志一律写 `stderr`（`KORE_LOG_LEVEL` 控制级别）。
- 方法：

  | 方法 | 入参 | 结果 |
  | --- | --- | --- |
  | `ssl.list` | 无 | `{certs:[...], count:N}` |
  | `ssl.issue` | `{domain, email?}` | 证书结构化记录（source=stub） |
  | `ssl.renew` | `{domain}` | 续期后证书（status=renewed） |

- `domain` 强制小写、至少两个标签、拒绝路径穿越；错误码取 `pluginapi.E_*`。

## 构建与验收

```bash
gofmt -l .
go vet ./...
go test -timeout 200s ./...
make build
make dist
tar tzf dist/ssl-0.1.0.tar.gz | head -1   # 必须是 info.json
```

`make check` 聚合 gofmt / vet / test。`dist` 采用确定性打包
（`--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner` + `gzip -9n`），
同源码两次出包 SHA 一致。`info.json` 经 `go:embed` 进入二进制，故 `size_bytes`
为提交前按实测包体积一次性回写的定值，`dist` 不修改它，避免 SHA 漂移。

## 故障注入（G-20 / S-04）

`tests/fault/` 四类各一文件，做方法级错误返回断言（无空测试、无 `t.Skip`）：

- `kill_test.go` —— 进程被 kill：签发返回 `E_UPSTREAM`，不污染清单。
- `timeout_test.go` —— ACME 超时 / context 取消：返回 `E_UPSTREAM`。
- `disk_test.go` —— 落盘 ENOSPC：返回 `E_INTERNAL`，不写入清单。
- `cgroup_test.go` —— `memory.max` 触顶 OOM：续期返回 `E_INTERNAL`（含健康对照组）。

## 依赖

只依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1` + Go 标准库。
构建强制 `GOWORK=off`、`CGO_ENABLED=0`、`GOAMD64=v1`、`-trimpath -s -w`。
