# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-11-24

### Added

- **`ssl.acme.issue` 一键签发（零字段路径）**：站点页只需 `{site, confirm:true}`，
  域名 / webroot / 邮箱 / CA / 密钥类型全部按「param → 站点约定 → 已存配置」推断；
  结果新增 `resolved{domain_source, webroot_source, email_source, ca_source, engine}`，
  逐项说明每个字段从哪来。此前必须手填 `domain`+`email` 且**只认外部 certbot/acme.sh**
  （本机没装就整条链路不可用），这是「站点页申请不了证书」的根因。
  - 默认引擎改为**内置 ACME**（`internal/acme`，0.5.0 已具备），零外部依赖；
    `engine=external` 保留原外部客户端通道，行为不变。
  - 新增 `site`（站点域名）、`alt_names`、`webroot`、`ca`、`directory_url`、
    `key_type`、`engine`、`skip_precheck` 入参，全部可选。
  - **真零参数**：既不传 `site` 也不传 `domain` 时，从 `<sites_root>` 枚举站点，
    恰好一个就采用（`domain_source=inferred_single_site`）；多个站点则拒绝猜测并列候选，
    要求带 `site`——猜错站点会把 challenge 写进别人的站点根。
  - webroot 推断链：显式 `webroot` → `<sites_root>/<domain>`（存在即用）→ 已存 `webroot`；
    `sites_root` 解析链：`KORE_SITES_DIR` → `ssl.acme.auto.sites_root` →
    `<KORE_STATE_DIR>/plugin-data/site/sites`（站点插件默认布局）。
  - `ssl.acme.auto` 新增 `sites_root`（绝对路径，落 0600 settings.json，一次配置、后续复用）；
    `ssl.acme.builtin.status` 暴露 `sites_root` 与 `sites_root_hint`（说明来源）。
- **失败提示改成「怎么办」**：新增 `enrichIssueError`——域名解析类给
  `dig +short A <domain>`，80 端口类给防火墙/安全组 + `curl -I http://<domain>/.well-known/acme-challenge/ping`，
  限流（`E_RATELIMIT`）给「先用 `letsencrypt-staging` 跑通、不占生产配额」并在 hint 里写明
  「同组域名每周 5 张 / 每小时 5 次」的口径。
- 默认 CA 口径：未配置过 ACME 时一键路径用 `letsencrypt`（站点页目标是拿到浏览器信任的证书），
  配置过则尊重 `settings.ca`；生产配额风险由签发前的本地 HTTP-01 预检兜住。

### Changed

- `ssl.acme.issue` 成功提示统一收敛到 `acmeIssueNextStepHint`（staging / 生产两种文案单点维护），
  不再在两处各写一份。
- README 的 ACME 章节同步为「内置客户端 + 一键签发」（原文仍写"内置 ACME 没有做"，与 0.5.0 代码不符）。

### Tests

- `internal/certs/acme_quick_test.go`（7 条）：
  - 零字段（只给 `site` + `confirm`）用**本地 mock CA** 真实走完 HTTP-01 并落盘；
  - 真零参数（只给 `confirm`，单站点）同样签发成功；多站点时拒绝猜测并列候选；
  - 反例：`confirm=false` 拒绝且 **0 个网络请求**、缺站点域名给可操作提示、
    预检不通的 hint 必含 `dig +short A` 与防火墙、限流 hint 必含 staging、
    外部引擎无客户端时 `E_UNSUPPORTED`、默认 CA 与用户覆盖可区分。
- 全部用 `internal/acme/acmetest` 本地 CA，**不真申请 Let's Encrypt**（不消耗配额）。
- 既有 boundary 断言未放宽：`site.bindSSL` 只允许出现在建议载荷文件里——本轮把成功文案
  收敛到 `acme_issue.go`（白名单内），新文件不出现该字面量。

## [0.6.0] - 2026-11-23

### Added

- **强制 HTTPS 下发（期望状态 + 站点侧载荷）**：新增 `ssl.https.enforce` /
  `ssl.https.unenforce`（均 `system:admin`），入参 `{domain}`。
  - 选 **(b) 只登记期望状态 + 返回 `apply_hint`**，不写站点配置：写独立 drop-in 片段需要在
    kore 的 `pkg/pluginapi` 形状表里新增 root_action 形状（ADR-0022），超出本仓写域；
    且站点配置的唯一归属方是 site 插件（G-13），另写一份片段再自行 reload 会与 site 的
    站点状态脱节（site 认为 force_https=false，下次 apply 覆盖）——两个写入方各管一半
    配置正是 0.4.0 已否决的路。`apply_hint` 指向 `site.bindSSL` 的 `force_https`
    （真正生成 80→443 跳转的开关）或 `force_https:false`（关闭）。
  - 前置校验：本仓必须有该域名的证书，否则 `E_INVALID` + hint「先到站点页绑证书」
    （没有证书的站点不可能有 443 server 块）。
  - 幂等：重复 enforce 返回 `created=false, changed=false`，不产生重复登记；
    `unenforce` 只删本仓自己的登记（按域名精确匹配），不影响其它域名与站点配置，
    重复卸载 `removed=false` 且不报错。
  - 落盘：`<元数据目录>/https-state.json`（0600，schema=1，与 bindings.json 同级、可迁）。
  - 所有写动作进审计（`https-enforce` / `https-unenforce`）。
- **`ssl.https.status` 扩展**：新增 `enforced`（本仓登记的期望状态）、
  `source`（`plugin` / `manual` / `none`）、`redirect_code`（80 侧第一跳状态码）；
  原有 `verdict` / `force_https` / `https{}` / `http{}` 字段保持不变。
- 方法级能力声明 20 条（7 read / 13 admin）。

### Not done / Boundary

- 未新增 `root_actions`（因此也不需要改 kore 的形状表）；未写任何 nginx 片段、
  未自行 reload。
- 实际跳转仍由 site 插件落地；本仓只在事后用 `ssl.https.status` 复核
  （`source=manual` 表示"没登记但实测在跳"）。

### Tests

- `internal/certs/https_state_test.go`：无证书拒绝（hint 指向先绑证书）、幂等
  （created/changed 二次为 false + 状态文件 0600 与内容快照 + apply_hint 形状快照）、
  卸载只删自己（两域名互不影响、重复卸载幂等）、status 三态
  （plugin / manual / none + redirect_code 301/200）、写操作进审计。

## [0.5.1] - 2026-11-23

### Changed

- **存储分层（ADR-0023 阶段 C）**：证书目录与插件元数据目录拆开。
  - 可迁项默认落在 `$KORE_PLUGIN_DATA/ssl`（0700，属主 kore-<id>）：`backups/`、
    `bindings.json`、`acme/`（settings / audit / 账户密钥）——这些没有 web server 读取需求。
  - 证书/私钥/链仍留在证书目录（系统路径）：web server（nginx 以 www-data/root 运行）必须读取，
    属 ADR-0023 §3.5 豁免 #3「用户批准的宿主变更」，**不迁**。
  - 未注入 `KORE_PLUGIN_DATA` 时元数据回退证书目录（与 0.5.0 完全兼容；旧部署零迁移成本）。
  - `Options.MetaDir` 可显式覆盖（测试与高级配置）。
- `ssl.list` 与 `ssl.acme.builtin.status` 新增 `storage` 字段：`portable`（元数据是否在
  `$KORE_PLUGIN_DATA` 下）、`portable_root`、`install_dir`、`cert_dir`、`meta_dir`、
  `system_paths[]`（每条含路径、种类、是否在安装目录内、**为什么必须在外**）与 `hint`。

### Security / Boundary

- 未放宽任何文件权限：证书仍按 0644、私钥 0600，目录 0700/0755 维持原样。
  **候选方案（未实施，待 lead 裁决）**：证书 0640 + 共享组（www-data）可让插件与 web server
  共用安装目录内的证书；但这是权限放宽，属于安全决策，本轮不做。

### Tests

- `TestResolveMetaDir`：无/有 `KORE_PLUGIN_DATA` 的默认根解析 + `Options.MetaDir` 显式优先。
- `TestMetaFilesStayPortable`：证书落证书目录、`bindings.json` 与 `acme/settings.json` 落元数据目录。
- `TestStorageInfoPortableAndSystemPaths` / `TestStorageInfoLegacyFallback`：storage 标注
  （portable、meta_dir、system_paths 含证书目录且理由写明 web server 读取 + ADR 豁免）。
- `TestStorageExposedInListAndStatus`：list 与 status 的 storage 一致且非空。

## [0.5.0] - 2026-11-23

### Added

- **内置 ACME 客户端（RFC 8555 最小可用子集，零第三方依赖）**：`internal/acme` 只用标准库
  实现 ES256 JWS、JWK 指纹、nonce 管理（newNonce + Replay-Nonce 复用 + badNonce 换新重试）、
  账号复用/注册（`onlyReturnExisting` → 创建）、EAB（HS256）、订单 → HTTP-01 → CSR →
  finalize → 下载证书链全流程。
- **多 CA**：内置预设 `letsencrypt-staging`（默认，避免生产 rate limit）/ `letsencrypt` /
  `litessl` / `custom`。LiteSSL 的 directory 为 `https://acme.litessl.com/acme/v2/directory`
  （来源：lego 官方 CA 清单，并于 2026-11-23 直接请求验证返回 RFC 8555 directory，
  `meta.externalAccountRequired=true` → 必须 EAB）。
- **新方法**：`ssl.acme.builtin.issue`（显式签发，需 confirm）、`ssl.acme.builtin.renew`
  （scheduler 入口，自动续期开启后才工作）、`ssl.acme.builtin.status`（只读状态，零网络，
  输出脱敏）、`ssl.acme.auto`（配置 + 自动续期开关，需 confirm）。方法级能力声明同步到
  18 条（7 read / 11 admin）。
- **HTTP-01**：token 写进用户配置的 webroot（`<webroot>/.well-known/acme-challenge/<token>`，
  一次性使用、无论成败都清理）；通知 CA 前先本地预检 token URL，把"域名不可达 / 80 未监听 /
  webroot 配错"暴露成可操作错误，而不是等 CA 回笼统的 unauthorized。
- **自动续期默认关闭**：`auto_renew=false` 出厂值；只有 `ssl.acme.auto {enabled:true,
  confirm:true}` 显式开启后，内核 scheduler 才允许调用 `ssl.acme.builtin.renew`（本仓不起
  ticker，G-19）。开启时返回"每天会联网一次"的明确警告 + 待创建任务描述。
- **续期护栏**：到期判定（`days_before`）→ 备份旧证书 → 签发 → 验证（密钥匹配、域名覆盖、
  链逐级签名关联、真实本地 TLS 握手自检）→ 落盘 + `.acme` 标记；任一步失败**保留旧证书**，
  并在 `acme/audit.jsonl` 记失败原因。
- **审计**：每次联网写 `acme/audit.jsonl`（0600）：时间 / 动作（issue/renew/auto-enable/
  auto-disable/config）/ CA / directory / 域名 / 结果 / 原因；超 256 KiB 轮转为 `.1`。
- **零侵入路径**（G-31 / ADR-0023）：证书目录解析改为
  `KORE_SSL_CERT_DIR` > `<KORE_STATE_DIR>/ssl`（即 `<install>/data/ssl`）> 可执行文件旁
  `data/ssl`；**不再默认写 `/etc/kore/ssl`**（旧安装显式设 `KORE_SSL_CERT_DIR=/etc/kore/ssl`
  即可继续使用，status 会提示检测到旧目录）。ACME 账户密钥、设置、审计全部在
  `<证书目录>/acme/`（0700/0600），删安装目录即清零。

### Changed

- 版本 0.4.0 → 0.5.0（内置 ACME 客户端 + 4 个新方法，feat → minor）。
- 证书目录默认值从 `/etc/kore/ssl` 改为 `<KORE_STATE_DIR>/ssl`（零侵入）。
- `main_test.go` 握手版本断言改为跟随 `testConfig().version`，不再硬编码。

### Security

- 联网只发生在用户显式调用（`acme.builtin.issue` / `acme.auto` 开启后的 scheduler 调用），
  没有后台轮询；自动续期关闭时 `acme.builtin.renew` 直接 `E_UNSUPPORTED` 且**零网络请求**。
- 账户私钥 / EAB hmac key 绝不进返回值、日志或审计；`status` 只回 `eab_configured` 布尔。
- 不写 `/etc/letsencrypt`、不调外部 certbot/acme.sh；token 文件用完即删。
- 落盘前验证新证书：密钥匹配 + 域名覆盖 + 链完整性 + 本地 TLS 握手，失败不覆盖旧证书。

### Boundaries（未做 / 未验证）

- **只支持 HTTP-01**：DNS-01、通配符证书、ARI（RFC 9773）未实现；通配符续期会明确拒绝。
- **真实 CA 未验证**：本机无公网可解析域名与 80 端口，内置客户端的端到端只有本地
  mock ACME CA 的证据（`internal/acme/acmetest`）。staging/生产/LiteSSL 的真机签发
  仍需在有域名与 80 端口的环境补验。
- **站点绑定仍归 site 插件**：本仓只产证书 + `.acme` 标记，写 vhost 由 `site.bindSSL` 完成。

### Tests

- `internal/acme`：JWK 指纹向量（独立实现算出）、ES256 r||s 长度与自校验、EAB HMAC 向量、
  CSR SAN、域名归一化；本地 mock ACME CA 上的完整签发、badNonce 重试、challenge 失败、
  finalize 被拒、证书下载失败、rateLimited、EAB 缺失/正确/错误、预检成功与失败（回环）、
  webroot 缺失时零联网。
- `internal/certs`：自动续期默认关闭且零联网、confirm 必填、开启需 webroot、LiteSSL 强制
  EAB、status 脱敏、签发落盘/标记/来源/审计、签发失败不落证书、未到期跳过零联网、
  到期续期（含备份）、续期失败保持旧证书字节不变。
- 静态门禁 `boundary_test.go` 继续覆盖：无后台定时器、net.Dial 唯一、exec 仅 ACME、
  不写站点配置指令。

## [0.4.0] - 2026-11-23

### Added

- **站点归属登记**：`ssl.bind.set` / `ssl.bind.remove` / `ssl.bind.list`。本仓只登记
  「证书 → 站点域名」的归属关系（`<证书目录>/bindings.json`，0600，schema=1），
  不写任何 web 服务器配置。
  - 一对一约束：一张证书只能属于一个站点、一个站点只能挂一张证书，冲突返回
    `E_CONFLICT` + hint；同对重复登记幂等（`created=false`，只刷新 note / updated_at）。
  - 证书必须真实存在（否则 `E_NOTFOUND`）；证书被删除后归属保留但 `cert_exists=false`。
  - 结果带 `site_bind` 建议载荷（`site.bindSSL` 的 domain / cert_path / key_path /
    force_https=true），由用户到站点页发起实际绑定。
- **强制 HTTPS 只读判定**：`ssl.https.status`（domain，端口缺省 80/443）。真实探测
  「443 能否 TLS 握手」与「80 是否把 `/` 3xx 跳到 https://」，返回
  `verdict` ∈ `force-https` / `https-without-redirect` / `https-unreachable` +
  两侧探测事实 + 指向站点侧的建议载荷 + 可操作 hint。
  - 只读：不跟随跳转（只读第一跳状态码与 Location）、不改配置、不 reload。
  - 探测失败是观测值（`reachable=false + error`），不映射成协议错误。
- **方法级能力声明**（`info.json.method_capabilities`，14 条）：只读方法
  `list` / `verify` / `expiring` / `acme.status` / `bind.list` / `https.status` =
  `system:read`；写方法 `import` / `selfsign` / `renew` / `issue` / `renew.set` /
  `acme.issue` / `bind.set` / `bind.remove` = `system:admin`。未声明的方法会回退
  插件级 `capabilities`（`system:admin`），只读操作会因此进管理审计——这次逐条补齐。

### Changed

- 版本号 0.3.0 → 0.4.0（新增 4 个方法，feat → minor）。
- `methods.go` 的参数结构与 `parse*` 解析函数原样移到新文件 `params.go`
  （纯搬移、零语义变化；方法分发表 `handleSSLVerb` 与 `businessVerb` 仍在
  `methods.go`），为新增 4 个方法留出可读空间。
- `ssl.bind.set` 的 `probe` 是**可选**参数：不显式给就不发起任何探测（G-10：
  出站只由用户显式动作触发）；`ssl.bind.list` 永不联网。

### 边界决策（本仓不越权）

- **绑定站点选 (A)：只登记归属 + 给建议载荷，不写配置、不直调 site。**
  - 被否决 (B)「本仓经内核调用 `site.bindSSL`」：`PLUGIN-PROTOCOL §2` 明确
    「不做插件间直连，跨插件调用一律经内核 bus 转发并做 capabilities 校验」，
    插件到内核只有 `kore.event` 单向通道、没有"代我调另一个插件"的接口。
    从插件侧发起只能靠伪造 HTTP 会话，那是绕过鉴权，绝对不能做。
  - 被否决 直写 nginx vhost：G-13 仓库边界 + 插件能力边界——写站点配置、管
    443 监听、管 reload 是 `site` 插件的职责；两个插件各写一份 vhost 必然互相覆盖。
- **强制 HTTPS 选「只读判定 + 指向站点侧」：** 开启跳转的真开关是
  `site.bindSSL` 的 `force_https`（默认 true，见 site `info.json` / `render.go`）；
  `site.setRedirect` 是**精确路径**重定向（`to_url` 只接受 `http(s)://` 或站内路径），
  不适合当全局强制 HTTPS（会丢原路径），因此 `site_action` 以 `bindSSL` 为主、
  在 note 里给出 setRedirect 的适用场景。本仓只判定、不改配置、不 reload。
- **ACME 自动续期保持 G-10 口径：** `ssl.renew.set` 仍只产「待创建任务描述」交内核
  scheduler，不自己起 ticker；`ssl.acme.issue` 仍需 `confirm=true` 且只调本机
  certbot/acme.sh（ADR-0020）。本轮**没有**新增任何后台签发 / 后台续期路径，
  scheduler 侧对 ACME 证书仍由 `ssl.renew` 如实拒绝。

### Security

- `https.status` 的 80 侧探测只发一个 `GET /`、只读响应头（上限 16 KiB），
  不跟随跳转、不带凭据；443 侧只做握手取元数据（`InsecureSkipVerify`，与
  `ssl.verify` 同口径，`matched` 只表示证书覆盖主机名）。
- 归属登记文件 0600、目录 0700，路径经 `withinDir` 二次校验；`note` 限 200 字符
  且拒绝控制字符。

### Tests

- 新增 `methodcaps_test.go`：`method_capabilities` 与 `businessVerb` **双向**一致，
  并单独覆盖 config 契约（实现了却没声明 → 回退 admin 审计；声明了却没实现 → 漂移）。
- 新增 `boundary_test.go`：静态断言本仓 Go 代码**不含 web 服务器配置指令 / 配置目录 /
  reload 片段**、无 `time.NewTicker` 等周期来源、`net.Dial` 只有 `main.go` 连内核
  UDS 一处、`exec` 只出现在 ACME 调用点——用测试而不是注释证明"本仓不写 nginx 配置"。
- 新增 `internal/certs/binding_test.go`：落盘形状 / 权限 / schema、幂等、一对一冲突、
  上限、证书缺失、陈旧归属、解除口径、`probe` 可选性。
- 新增 `internal/certs/https_status_test.go`：用 `httptest` 在回环模拟 80/443
  （已跳转 / 未跳转 / 443 不可达 / 302 到 http / 不跟随跳转 / 端口校验），不连外网。
- `tests/fault`：四类故障下 `bind.set` / `bind.list` / `https.status` 均被入口拦截，
  故障路径不落 `bindings.json`，附无故障对照组。

## [0.3.0] - 2026-11-23

### Added

- `ssl.expiring`：到期聚合视图 `{expiring:[{name, path, not_after, days_left,
  severity}], checked}`。窗口 `days`（缺省 30，严格小于）决定纳入范围，分级按固定
  阈值：`<7` critical、`<30` warning、其余 ok；已过期落在 critical。剩余天数用证书
  `NotAfter` 绝对时刻相减（与 `ssl.list` 同一口径，不受时区/格式影响），
  `not_after` 统一 UTC RFC3339。
- `ssl.renew.set`：生成"待创建自动续期任务"描述，**不直接调内核 API**（调度归内核
  ADR-0019）。返回 `{created:false, task_id:"", next_run_at, recommended_task:{name,
  plugin:"ssl", method:"ssl.renew", params:{name, days_before}, schedule:"0 3 * * *"},
  hint}`；任务名 `ssl-renew-<name>`，超 64 字符时截断并附域名 SHA-256 前 8 位；
  `next_run_at` 按本地时区算下一个 03:00。证书不存在返回 `E_NOTFOUND` + hint。
- `ssl.acme.status`：只读探测本机 `certbot` / `acme.sh`（PATH → 固定安装位置 →
  家目录），返回 `{available, tool, version}`；缺工具不是错误，`available=false`。
- `ssl.acme.issue`：**需 `confirm=true` 显式确认**（G-10 无联网，只能用户触发）后
  调用外部客户端（certbot `certonly --standalone` / acme.sh `--issue --standalone`），
  工作目录限制在 `<证书目录>/acme/<tool>`（0700），签出的证书经 `ssl.import` 纳入
  管理并写 `<base>.acme` 归属标记（此后 `ssl.renew` 不会当自签重签）。未确认
  `E_INVALID`、无客户端 `E_UNSUPPORTED`，两者都带 hint；工具失败 `E_UPSTREAM` +
  输出尾部。私钥内容绝不进返回值，只给路径与指纹。
- `ssl.renew` 新增可选 `days_before`：剩余天数大于窗口时返回
  `{renewed:false, skipped:"not_due"}`，不碰磁盘（定时任务每天调用不会天天重签）。
- 续期前备份：覆盖前把旧证书/私钥/链复制到 `<证书目录>/backups/<base>-<时间戳>.*`
  （证书 0644、私钥 0600、目录 0700），结果返回 `backup_path`；备份失败则中止续期，
  绝不丢旧证书；每张证书保留最近 5 份（自动清理）。

### Changed

- 版本号 0.2.1 → 0.3.0（新能力为 feat，minor）。
- `ssl.issue` 兼容入口的说明改为指向 `ssl.acme.status` / `ssl.acme.issue`
  （内置 ACME 仍未实现，不返回假证书）。
- 协议错误支持 `detail.hint`：`E_UNSUPPORTED` / `E_INVALID` / `E_UPSTREAM` 现在带
  可操作下一步（内核映射为 HTTP 错误体的 `hint` 字段）。

### Security

- ACME 签发双闸门：`confirm=true` + 本机客户端存在；不做后台自动申请（G-10）。
- 外部客户端以 argv 数组执行（不经 shell），账号/证书/日志目录 0700。
- 备份私钥同样 0600，续期失败时旧证书可回滚。

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
