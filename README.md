# kore-plugin-ssl

kore 的 TLS 证书管理插件（M5 批 1 · 生产级）：证书扫描解析、导入、自签、续期判定
与真实 TLS 握手探测。

## 能力

- 证书目录固定为 `KORE_SSL_CERT_DIR`（默认 `/etc/kore/ssl`），RPC 不接受任意路径。
- 全部操作读写的都是真实文件；进程内不维护"看起来存在"的清单。
- 只用 Go 标准库 + `pluginapi`（G-17），不引入第三方 ACME 库、不捆绑 certbot/acme
  二进制、不内置 web server（裁决 37）。
- `lifecycle=lazy`：不常驻；续期由内核按 `event:cert.renew_due` 事件触发，
  插件内部不起 ticker（G-19）。

## 方法（kore.plugin.v1）

| 方法 | 入参 | 结果 |
| --- | --- | --- |
| `ssl.list` | 无 | `{certs:[...], count:N}`，逐张真实解析 |
| `ssl.import` | `{domain, cert_pem, key_pem, chain_pem?}` | 落盘后的证书信息 |
| `ssl.selfsign` | `{domain, days?, key_type?, extra_sans?}` | 自签证书信息 + `self_signed=true` |
| `ssl.renew` | `{domain, days?}` | 续期后证书信息 + `renewed=true` |
| `ssl.verify` | `{domain}`（host 或 host:port） | `{reachable, matched, not_after, days_left, issuer, error, ...}` |
| `ssl.expiring` | `{days?}`（窗口，缺省 30） | `{expiring:[{name, path, not_after, days_left, severity}], checked}` |
| `ssl.renew.set` | `{name, days_before?}` | `{created:false, task_id:"", next_run_at, recommended_task, hint}`（待创建任务描述） |
| `ssl.acme.status` | 无 | `{available, tool, version}`（只读探测本机客户端） |
| `ssl.acme.issue` | `{domain, email, confirm:true}` | 签发结果（证书元数据 + 路径）；未确认 `E_INVALID`、无客户端 `E_UNSUPPORTED` |
| `ssl.issue` | 兼容入口 | `E_UNSUPPORTED` + hint：指向 `ssl.acme.status` / `ssl.acme.issue` |

`ssl.list` 条目字段：`domain / domains(SAN+CN) / file / not_before / not_after /
days_left / issuer / subject / serial / is_ca / key_type / key_bits /
chain_length / fingerprint_sha256 / self_signed / source / expired /
expiring_soon / error`。`days_left` 向上取整（刚签发的 365 天证书显示 365），
过期证书为负值并按 `expired=true` 标记；`< 30` 天标记 `expiring_soon=true`。

证书目录扫描 `*.crt` 与 `*.pem`：`*.key` 不扫描，`*.chain.pem` 作为叶子证书的
附属链计入 `chain_length` 而不单独列出；同一证书以多个文件名重复存放时按
SHA-256 指纹去重。单张证书无法解析只在该条目写 `error`，不影响其它条目。

## 到期告警（ssl.expiring）

聚合视图，不是 `ssl.list` 的替身：list 给逐张明细，expiring 回答"还差几天、要不要报警"。

- 入参 `days`（缺省 30，**严格小于**）：`days=30` 表示剩余不足 30 天，与 warning 阈值同边界。
- 分级固定：`<7` → `critical`、`<30` → `warning`、其余 → `ok`（`ok` 只在把窗口放到 30 天以上时出现）；
  已过期（负天数）归 `critical`。
- 剩余天数由 `NotAfter` 绝对时刻与当前时刻相减得到（与 `ssl.list` 同一函数），
  因此不受时区或日期格式影响；`not_after` 输出 UTC RFC3339，本地化交给前端。
- `checked` 是真正完成解析的证书张数；解析失败的条目只在 `ssl.list` 里带 `error`。

## 自动续期任务（ssl.renew.set）

插件**不能直接调内核 API**（调度归内核 `scheduler`，ADR-0019），所以该方法只返回
"待创建任务描述"，由前端调 `POST /api/v1/scheduler/tasks` 真正创建：

```json
{
  "created": false,
  "task_id": "",
  "next_run_at": "2026-11-24T03:00:00Z",
  "recommended_task": {
    "name": "ssl-renew-renew.kore.local",
    "plugin": "ssl",
    "method": "ssl.renew",
    "params": {"name": "renew.kore.local", "days_before": 30},
    "schedule": "0 3 * * *"
  },
  "hint": "插件不能直接创建内核任务：把 recommended_task 原样 POST 到 /api/v1/scheduler/tasks 才会真正生效"
}
```

- `next_run_at` 按本地时区算下一个 03:00（跨夏令时用日历日推进，不是 +24h）。
- 任务名 `ssl-renew-<name>`；域名过长会超过内核 `name ≤64` 限制，此时截断并附
  域名 SHA-256 前 8 位（确定性、不撞名）。
- `days_before`（缺省 30）写进任务参数；`ssl.renew` 收到它时先做到期判定，
  未到窗口返回 `{renewed:false, skipped:"not_due"}` 且不碰磁盘——定时任务每天调用
  不会天天重签。
- 证书不存在直接 `E_NOTFOUND` + hint，不返回指向空证书的任务定义。

## ACME（骨架，必须用户显式触发）

内置 ACME 协议实现**没有做**（G-10 无联网 / G-17 依赖白名单）；方案对比与取舍见
kore 仓库 `docs/DECISIONS/0020-acme.md`（ADR-0020）。插件只做两件事：

1. `ssl.acme.status`：探测本机 `certbot` / `acme.sh`（PATH → `/usr/bin`、`/usr/local/bin`、
   `/snap/bin`、`~/.acme.sh`），跑 `<tool> --version` 取版本；缺工具 `available=false`，不是错误。
2. `ssl.acme.issue`：`confirm=true` 且客户端可用时，以 argv 数组调用
   `certbot certonly --standalone`（或 `acme.sh --issue --standalone`），工作目录固定
   `<证书目录>/acme/<tool>`（0700），签出的证书经 `ssl.import` 纳入管理并写
   `<base>.acme` 归属标记（此后 `ssl.renew` 不会把它当自签重签）。
   未确认 `E_INVALID`、无客户端 `E_UNSUPPORTED`（均带 hint）；工具失败 `E_UPSTREAM`
   并回传输出尾部。**私钥内容绝不进返回值**，只给路径与指纹。

## 续期前备份

`ssl.renew` 真正覆盖前，把旧证书 / 私钥 / 链复制到 `<证书目录>/backups/<base>-<UTC 时间戳>.*`：

- 备份目录 0700、证书与链 0644、私钥 0600；结果返回 `backup_path`。
- **备份失败即中止续期**（宁可这次不续，也不让旧证书消失）。
- 每张证书保留最近 5 份，超出自动清理。
- `backups/` 是子目录，`ssl.list` / `ssl.expiring` 的扫描不会把它当证书。

## 校验链（ssl.import）

1. `cert_pem` 必须能被 `x509.ParseCertificate` 解析（允许 fullchain，首块为叶子）；
2. 证书 SAN 必须覆盖 `domain`：DNS 精确匹配、`*.example.com` 覆盖一级子域、
   IP 主体匹配 `IPAddresses`（不把 CN 当覆盖依据——现代 TLS 栈已忽略 CN）；
3. 私钥必须是未加密 PEM（PKCS#8 / PKCS#1 / SEC1），拒绝
   `Proc-Type: 4,ENCRYPTED`、`ENCRYPTED PRIVATE KEY` 与 OpenSSH 私钥；
4. `tls.X509KeyPair` 校验证书与私钥匹配，不匹配一律 `E_INVALID`；
5. 原子落盘：私钥 `0600`、证书/链 `0644`、目录 `0700`；失败按快照整组回滚。

## 自签与续期

- `ssl.selfsign` 真签发：`crypto/rsa` 2048 或 `crypto/ecdsa` P-256，
  `x509.CreateCertificate`，`NotAfter=now+days`，默认 365 天；
  `extra_sans` 可附加 DNS/IP（内网/回环联调时让证书同时覆盖多个名字）；
  IP 主体写入 `IPAddresses`，可直接用于 TLS 握手。
- `ssl.renew` 支持可选 `days_before`（到期窗口判定）；按证书归属严格区分：
  - 自签证书 → 重新签发（新密钥 + 新序列号），保留原文件名、密钥类型与附加 SAN；
  - ACME 证书（issuer 命中 Let's Encrypt/ACME，或存在 `<base>.acme` 标记）→
    `E_UNSUPPORTED`，message 为"ACME 续期需要 ACME 客户端，当前版本未实现，
    请在 v1.1 跟进"；
  - 其它 CA 证书 → `E_UNSUPPORTED`，提示改用 `ssl.import` 导入新证书。
   **不假装成功**：拒绝时不改动任何文件。
- `ssl.verify` 用 `tls.DialWithDialer` 做真实握手（10s 预算，`InsecureSkipVerify`
  只为在自签/过期场景取到元数据），`matched` 是 `leaf.VerifyHostname(host)` 的
  真实结果，不代表信任链通过；连接失败返回 `reachable=false + error`，不报 500。

## 安全边界

- 私钥绝不进返回值、错误消息或日志（覆盖写入前只在内存做回滚快照）；
  `ssl.list` 只解析证书公钥信息。
- 域名白名单：小写字母数字/连字符/点，至少两个标签，拒绝 `..` 与路径分隔符；
  文件名落盘前再经 `withinDir` 二次校验。
- 不联网：除 `ssl.verify` 的用户显式请求外无任何出站连接。

## 构建与验收

```bash
gofmt -l .
go vet ./...
go test -timeout 200s ./...     # 单元 + 故障注入 + 真实 E2E（插件二进制 + UDS + TLS）
make build
make dist
tar tzf dist/ssl-0.3.0.tar.gz | head -1   # 必须是 info.json
```

`make check` 聚合 gofmt / vet / test。`dist` 采用确定性打包
（`--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner` + `gzip -9n`），
同源码两次出包 SHA 一致。`info.json` 经 `go:embed` 进入二进制，故 `size_bytes`
为提交前按实测包体积回写的定值，`dist` 不修改它，避免 SHA 漂移。

## 测试

- `internal/certs/*_test.go`：自签回读字段/权限、TLS 握手、import 三种拒绝
  （私钥不匹配 / SAN 不含 domain / 加密私钥）、过期与临期标记、多证书扫描、
  指纹去重、ACME 标记、续期分支与 SAN 保留、探测匹配与不匹配、
  到期分级与窗口边界、任务描述（含超长域名截断）、续期前备份与保留份数、
  ACME 工具探测（真脚本替身）与签发导入 + 未确认/缺工具拒绝。
- `tests/fault/`：四类故障注入（kill / timeout / disk-full / cgroup-limit）
  驱动真实方法，断言错误码、关键词与"不落半成品"，附无故障对照组与真实
  握手超时探测。
- `tests/e2e/`：真实插件二进制 + UDS 的完整闭环（见 `doc.go`）。

## 依赖

只依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1` + Go 标准库。
构建强制 `GOWORK=off`、`CGO_ENABLED=0`、`GOAMD64=v1`、`-trimpath -s -w`。
