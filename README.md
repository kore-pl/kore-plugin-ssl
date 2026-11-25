# kore-plugin-ssl

语言：[简体中文](docs/DETAIL.md) · [English](docs/DETAIL.en.md) · [Español](docs/DETAIL.es.md) · [Français](docs/DETAIL.fr.md) · [Deutsch](docs/DETAIL.de.md) · [Русский](docs/DETAIL.ru.md) · [Português](docs/DETAIL.pt.md)
kore 的 TLS 证书管理插件（M5 批 1 · 生产级）：证书扫描解析、导入、自签、续期判定、
真实 TLS 握手探测，以及「证书 → 站点」归属登记与强制 HTTPS 的**只读判定**。

## 能力

- 证书目录固定为 `KORE_SSL_CERT_DIR`（默认 `/etc/kore/ssl`），RPC 不接受任意路径。
- 全部操作读写的都是真实文件；进程内不维护"看起来存在"的清单。
- 只用 Go 标准库 + `pluginapi`（G-17），不引入第三方 ACME 库、不捆绑 certbot/acme
  二进制、不内置 web server（裁决 37）。
- `lifecycle=lazy`：不常驻；续期由内核按 `event:cert.renew_due` 事件触发，
  插件内部不起 ticker（G-19）。
- **不写 web 服务器配置**：站点绑定、443 监听、80→443 跳转的唯一归属方是 `site`
  插件（`site.bindSSL` / `site.unbindSSL` / `site.setRedirect`）。本仓只登记归属、
  给出推荐载荷、只读判定实际行为，越权路径由 `boundary_test.go` 断言拦住。

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
| `ssl.acme.issue` | `{site?, domain?, confirm:true, webroot?, email?, ca?, key_type?, engine?, alt_names?, skip_precheck?}` | **一键签发**：域名从 `site` 带出、webroot 从站点根约定带出、邮箱/CA/密钥类型从已存配置带出；默认内置 ACME（`engine=external` 才走 certbot/acme.sh）。结果含 `resolved{*_source}` 解释每个字段来源 |
| `ssl.issue` | 兼容入口 | `E_UNSUPPORTED` + hint：指向 `ssl.acme.status` / `ssl.acme.issue` |
| `ssl.bind.set` | `{cert, site, note?, probe?:{http_port,https_port}}` | 归属登记（一对一冲突校验）+ 站点侧推荐载荷 `site_bind`；显式给 `probe` 时附带只读 HTTPS 判定 |
| `ssl.bind.remove` | `{cert?, site?}`（至少一个） | `{removed, binding, hint}`；只解除本仓登记，站点侧需 `site.unbindSSL` |
| `ssl.bind.list` | 无 | `{bindings:[{cert, site, note, created_at, updated_at, cert_path, key_path, cert_exists}], count}` |
| `ssl.https.enforce` | `{domain}` | 登记"该域名应强制 HTTPS"的期望状态 + 返回站点侧 `apply_hint`（需先有证书；幂等） |
| `ssl.https.unenforce` | `{domain}` | 只清除本仓登记（不影响站点配置与其它域名；幂等） |
| `ssl.https.status` | `{domain, http_port?, https_port?}` | `{https:{reachable,matched,...}, http:{status_code,location,redirects_to_https}, force_https, verdict, site_action, hint}` |
| `ssl.acme.builtin.issue` | `{domain, alt_names?, email?, ca?, directory_url?, webroot?, key_type?, skip_precheck?, confirm:true}` | 内置 ACME 签发：证书/私钥/链路径 + 有效期 + 链长度（需 confirm） |
| `ssl.acme.builtin.renew` | `{name?}` | 续期所有到期的 ACME 证书（自动续期开启后才工作）：`{renewed, skipped, failed, certs[]}` |
| `ssl.acme.builtin.status` | 无 | 只读状态：证书目录/来源、CA、directory、webroot、EAB 是否配置（脱敏）、自动续期、最近审计、CA 预设 |
| `ssl.acme.auto` | `{enabled?, days_before?, ca?, directory_url?, webroot?, email?, key_type?, eab_kid?, eab_hmac_key?, clear_eab?, confirm:true}` | 保存 ACME 配置 + 自动续期开关；开启时返回联网警告与待创建的内核任务 |

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

## ACME（内置客户端 + 一键签发）

两条通道，默认走内置：

1. **内置 ACME（默认，0.5.0 起）**：`ssl.acme.builtin.issue` 用本仓 `internal/acme`
   直接跑 RFC 8555（HTTP-01），不依赖任何外部二进制。账户密钥 / 设置 / 审计都在
   `<证书目录>/acme/`（0600），删安装目录即清零。自动续期默认关闭，由 `ssl.acme.auto`
   显式开启后交给内核 scheduler（G-19 不允许插件自己起 ticker）。
2. **外部客户端（可选，`engine=external`）**：`ssl.acme.status` 探测本机
   `certbot` / `acme.sh`，`ssl.acme.issue` 以 argv 数组调用
   `certbot certonly --standalone`（或 `acme.sh --issue --standalone`），工作目录固定
   `<证书目录>/acme/<tool>`（0700）。缺工具 `E_UNSUPPORTED` + 安装指引。

### 一键申请（0.7.0）

站点页只需要一个站点域名 + 一次确认：

```json
{"site": "example.com", "confirm": true}
```

字段来源按 param → 站点约定 → 已存配置 的顺序推断，结果里用
`resolved.domain_source` / `resolved.webroot_source` / `resolved.email_source` /
`resolved.ca_source` 逐项说明"为什么没让用户填"：

| 字段 | 默认来源 |
| --- | --- |
| domain | `domain` → `site` → `<sites_root>` 下唯一站点（`inferred_single_site`） |
| webroot | `webroot` → `<sites_root>/<domain>`（存在即用）→ 已存 `webroot` |
| sites_root | `KORE_SITES_DIR` 环境变量 → `ssl.acme.auto` 的 `sites_root` → `<state>/plugin-data/site/sites`（站点插件默认布局） |
| email | `email` → 已存配置（可为空） |
| ca | `ca` → 已存配置（用户改过才尊重）→ `letsencrypt` |
| key_type | `key_type` → 已存配置 → `ecdsa256` |

`confirm=true` 仍是硬门（G-10：联网必须由用户显式触发），一次点击就是确认。
**失败一律给「怎么办」**：域名解析未生效给 `dig +short A <domain>`；80 端口不通给
防火墙/安全组与 `curl` 验证命令；限流给「先用 `letsencrypt-staging` 跑通」。
**绝不真打生产配额做验证**：测试全部用本地 mock CA（`internal/acme/acmetest`）。

## 续期前备份

`ssl.renew` 真正覆盖前，把旧证书 / 私钥 / 链复制到 `<证书目录>/backups/<base>-<UTC 时间戳>.*`：

- 备份目录 0700、证书与链 0644、私钥 0600；结果返回 `backup_path`。
- **备份失败即中止续期**（宁可这次不续，也不让旧证书消失）。
- 每张证书保留最近 5 份，超出自动清理。
- `backups/` 是子目录，`ssl.list` / `ssl.expiring` 的扫描不会把它当证书。

## 站点归属登记（ssl.bind.*）

**归本仓的**：记「这张证书属于哪个站点」——一条记录只含 `cert` / `site` / `note` /
时间戳，落在 `<证书目录>/bindings.json`（0600，目录 0700）。
**不归本仓的**：写站点配置。把证书写进 443 监听、生成 80→443 跳转，只有 `site`
插件能做（`site.bindSSL`，其中 `force_https` 默认 `true`）。

- 一对一约束：一张证书只能属于一个站点，一个站点也只能挂一张证书；
  违反返回 `E_CONFLICT` + hint（先 `ssl.bind.remove` 解除旧归属）。
- 同对重复登记幂等：`created=false`，只刷新 `note` / `updated_at`，`created_at` 不变。
- `cert` 必须真实存在于证书目录，否则 `E_NOTFOUND`（不允许登记指向空气的归属）。
- 结果里的 `site_bind` 是**建议载荷**（`plugin/method/params`，含证书与私钥绝对路径），
  由用户在站点页发起；本仓既不 dial `site` 的 socket（协议层禁止插件间直连），
  也不替它写配置。
- 证书被删除后归属仍保留但 `cert_exists=false`（陈旧归属可见、可清理）。

## 强制 HTTPS（ssl.https.status，只读判定）

- 判定口径：443 能否完成 TLS 握手、80 是否把 `/` 3xx 跳到 `https://`。
  `verdict` 三值：`force-https`（已生效）/ `https-without-redirect`（443 可用但 80 未跳）/
  `https-unreachable`（443 不可握手）。
- **只读**：不跟随跳转（只读第一跳状态码与 `Location`）、不改任何配置、不 reload。
- 开启跳转在站点侧：全局 80→443 用 `site.bindSSL` 的 `force_https`（默认 `true`）；
  只需某条路径跳转时用 `site.setRedirect`（精确路径匹配，`to_url` 只接受
  `http(s)://` 或站内路径）。结果里的 `site_action` 给出这个建议载荷。
- 端口默认 80 / 443，可显式给（联调与测试用）；探测失败是观测值
  （`reachable=false + error`），不映射成协议错误。
- 显式触发才出站：登记时的 `probe` 是可选参数，`ssl.bind.list` 永不联网。
- **强制 HTTPS 下发**：`ssl.https.enforce` / `unenforce` 只登记**期望状态**并返回
  `apply_hint`（`site.bindSSL` 的 `force_https=true/false`）——写站点配置、reload 仍是
  site 插件的职责（G-13），本仓不写片段、不自行 reload。`ssl.https.status` 用
  `enforced` / `source`（plugin｜manual｜none）/ `redirect_code` 复核实际效果。

## 内置 ACME 客户端（0.5.0）

不再依赖外部 certbot/acme.sh：`internal/acme` 用标准库实现了 RFC 8555 的最小可用子集——
ES256 JWS、JWK 指纹、nonce 复用与 badNonce 重试、账号注册/复用、EAB、订单、HTTP-01、
CSR/finalize、证书链下载。

- **多 CA**：`ca` 取 `letsencrypt-staging`（默认）/ `letsencrypt` / `litessl` / `custom`。
  LiteSSL 的 directory 是 `https://acme.litessl.com/acme/v2/directory`，**强制 EAB**
  （在 FreeSSL「证书自动化 → ACME 账户管理」创建账号取 `eab_kid` + `eab_hmac_key`）。
  `custom` 需要同时给 `directory_url`（只接受 https，仅回环允许 http 用于本地测试）。
- **HTTP-01**：token 写到 `webroot/.well-known/acme-challenge/<token>`，通知 CA 前先本地
  预检该 URL；token 无论成败都会删除。DNS-01 / 通配符未实现（会明确拒绝并给 hint）。
- **自动续期默认关闭**：`ssl.acme.auto {enabled:true, confirm:true}` 显式开启后，内核
  scheduler 才会按 `0 3 * * *` 调 `ssl.acme.builtin.renew`（插件不起 ticker）。
  续期顺序：到期判定 → 备份旧证书 → 签发 → 验证（密钥/域名/链完整性/本地 TLS 握手）
  → 落盘；失败保留旧证书并写审计。
- **审计**：`<证书目录>/acme/audit.jsonl`（0600）记录每次联网的动作/CA/域名/结果/原因。

### 证书目录结构（零侵入，G-31 / ADR-0023）

目录分两层（ADR-0023 阶段 C）：

- **证书目录**（web server 要读）：`KORE_SSL_CERT_DIR` > `<KORE_STATE_DIR>/ssl`
  > 可执行文件旁 `data/ssl`。**不迁入 0700 插件私有目录**——nginx 以 www-data/root 运行，
  读不到就等于站点挂掉；属 ADR-0023 §3.5 豁免 #3 用户批准的宿主变更。
- **元数据目录**（插件自有，可迁）：`$KORE_PLUGIN_DATA/ssl`（内核注入，0700）；
  未注入时回退证书目录（旧部署零迁移）。`Options.MetaDir` 可显式覆盖。

`ssl.list` / `ssl.acme.builtin.status` 的 `storage` 字段会显式标注：
`portable`、`portable_root`、`cert_dir`、`meta_dir`、`system_paths[]`（每条带
"为什么必须在外"）与 `hint`。**不再默认写 `/etc/kore/ssl`**；旧安装设
`KORE_SSL_CERT_DIR=/etc/kore/ssl` 即可继续使用（status 会提示检测到旧目录）。

```
<证书目录>/  = KORE_SSL_CERT_DIR（web server 读取，系统路径）
├── <domain>.crt (0644) / .key (0600) / .chain.pem
└── <domain>.acme                      归属标记（续期不当自签重签）

<元数据目录>/ = $KORE_PLUGIN_DATA/ssl（0700，可迁；未注入时回退证书目录）
├── backups/                           续期前旧证书备份（保留 5 份）
├── bindings.json (0600)               站点归属登记
└── acme/ (0700)
    ├── settings.json (0600)           ca / directory_url / webroot / email / EAB / auto_renew
    ├── audit.jsonl (0600)             每次联网一条审计，256 KiB 轮转
    └── accounts/<ca>/account.key(0600) + account.json(0600)   账户私钥与 KID
```

不写 `/etc/letsencrypt`、不写家目录、不调外部 ACME 客户端；删安装目录即清零。

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
- 不联网：只有 `ssl.verify`、`ssl.https.status`、`ssl.acme.builtin.issue` 与
  `ssl.acme.builtin.renew`（后者只在自动续期显式开启后由 scheduler 触发）会出站，
  全部由用户显式动作发起；没有后台轮询、没有隐式上报（G-10）。
- 内置 ACME 的账户私钥与 EAB hmac key 与证书私钥同级保护（0600），不进返回值/日志/审计。
- 不写 web 服务器配置：由 `boundary_test.go` 静态断言把关——Go 代码里不得出现
  配置目录 / 配置指令 / reload 命令片段；`net.Dial` 只允许 `main.go` 连内核 UDS；
  `exec` 只允许 ACME 客户端（ADR-0020）；生产代码不得出现 `time.NewTicker` 等周期来源。

## 构建与验收

```bash
gofmt -l .
go vet ./...
go test -timeout 200s ./...     # 单元 + 故障注入 + 真实 E2E（插件二进制 + UDS + TLS）
make build
make dist
tar tzf dist/ssl-0.7.0.tar.gz | head -1   # 必须是 info.json
```

`make check` 聚合 gofmt / vet / test。`dist` 采用确定性打包
（`--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner` + `gzip -9n`），
同源码两次出包 SHA 一致。`manifest.json` 经 `go:embed` 进入二进制；`info.json`
的 `size_bytes` 由 `dist` 迭代收敛后回写（与包体实际字节差 ≤2），因此重复执行
`make dist` 幂等、SHA 不漂移。

## 测试

- `internal/certs/*_test.go`：自签回读字段/权限、TLS 握手、import 三种拒绝
  （私钥不匹配 / SAN 不含 domain / 加密私钥）、过期与临期标记、多证书扫描、
  指纹去重、ACME 标记、续期分支与 SAN 保留、探测匹配与不匹配、
  到期分级与窗口边界、任务描述（含超长域名截断）、续期前备份与保留份数、
  ACME 工具探测（真脚本替身）与签发导入 + 未确认/缺工具拒绝、
  内置 ACME（本地 mock CA 全链路、badNonce 重试、challenge/finalize/下载失败、EAB、
  rate limit、预检、自动续期默认关闭/零联网/到期续期/失败保留旧证书）、
  站点归属登记（落盘/幂等/一对一冲突/上限/陈旧证书/解除）、
  强制 HTTPS 判定（httptest 模拟 80/443：已跳转 / 未跳转 / 443 不可达 /
  302 到 http 不算跳转 / 不跟随跳转）。
- 仓根 `methodcaps_test.go`：`method_capabilities` 与 `businessVerb` 双向一致
  （含 config 契约的漏声明陷阱）；`boundary_test.go`：本仓不写 web 服务器配置、
  无后台定时器、无插件间直连、外部命令只用于 ACME。
- `tests/fault/`：四类故障注入（kill / timeout / disk-full / cgroup-limit）
  驱动真实方法，断言错误码、关键词与"不落半成品"，附无故障对照组与真实
  握手超时探测。
- `tests/e2e/`：真实插件二进制 + UDS 的完整闭环（见 `doc.go`）。

## 依赖

只依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1` + Go 标准库。
构建强制 `GOWORK=off`、`CGO_ENABLED=0`、`GOAMD64=v1`、`-trimpath -s -w`。

<!-- oss:begin -->
## 开源与贡献

[![CI](https://github.com/kore-pl/kore-plugin-ssl/actions/workflows/ci.yml/badge.svg)](https://github.com/kore-pl/kore-plugin-ssl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)

本仓库是 **kore** 的 `TLS 证书管理插件`（id `ssl`），独立仓库、独立版本线、独立 CI：GitHub Actions 只手动触发（`workflow_dispatch`），按版本 tag 自动触发在 Gitea Actions（`.gitea/workflows/ci.yml`，push `v*` + 手动）。内核与协议见 [kore](https://github.com/kore-pl/kore)。

- **许可**：MIT（inbound = outbound，不要求 CLA）；提交用 `git commit -s` 签 DCO。
- **贡献**：[CONTRIBUTING.md](CONTRIBUTING.md)（构建、门禁、发版、边界）。
- **安全**：[SECURITY.md](SECURITY.md)——漏洞不要开公开 issue。
- **行为准则**：[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
- **兼容性**：`protocol: kore.plugin.v1` · `requires_kore: >=0.1.0 <0.2.0` · `lifecycle: lazy` · 深度等级 `production`。
- **验证方式**：本地 `make check` 优先（GitHub CI 只手动触发，Gitea CI 按版本 tag 触发；发布前 `make dist` 连跑两次核对 sha 一致）。
- **发布产物**：`make dist` → `dist/ssl-0.8.0.tar.gz` + `.sha256`（位级可复现，连跑两次 sha 相同）。
- **相关仓库**：[索引 kore-plugins](https://github.com/kore-pl/kore-plugins) · [协议文档](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-PROTOCOL.md) · [SDK 指南](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-SDK.md)

<!-- oss:end -->

## 支持本项目

如果证书插件帮你把 TLS 续期这件烦心事理顺了，欢迎给仓库点一个 ⭐ star——你的支持会让更多人看见 kore 的插件生态；想参与就从 [CONTRIBUTING.md](CONTRIBUTING.md) 开始。
