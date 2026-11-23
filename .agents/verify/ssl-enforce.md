# SSL `https.enforce` 真实跳转验证（task-184）

> 首行归属：`[agent:kore-impl-ssl]`｜仓库：`kore-plugin-ssl`｜版本：0.6.0（未改代码）
> 结论先行：**跳转行为未在真 nginx 上验证**（本机没有 nginx，按任务要求未安装）。
> 已实证的是：enforce 只登记期望状态、幂等；301 由 site 侧产生；unenforce 不撤销站点跳转。
> **未验证项已明确挂账**，所需条件见 §5。

## 1. enforce 实际改什么（读实现 + 实测文件快照）

`https.enforce` **不写 nginx、不写站点配置、不 reload**。它只做三件事：

| 动作 | 位置 | 实测结果 |
| --- | --- | --- |
| 写期望状态 `<元数据目录>/https-state.json`（0600，schema=1） | `internal/certs/https_state.go:177` | 新增文件，权限 0600 ✅ |
| 写审计 `<元数据目录>/acme/audit.jsonl`（action=`https-enforce`） | `internal/certs/https_state.go:180` | 每次调用追加一条 ✅ |
| 返回站点侧载荷 `apply_hint`（`site.bindSSL` + `force_https=true`） | `internal/certs/https_state.go:188-193` | 载荷字段完整 ✅ |

**回滚方式**：`ssl.https.unenforce` 只删除本仓登记（`https_state.go:200-260`），
**不会也无法撤销站点侧跳转**（站点配置归 site 插件）。要真正关掉跳转，仍需在站点页按
`apply_hint`（`force_https:false`）操作。

实测文件快照（证书目录 / 元数据目录）：

```
BASELINE        certDir=[127.0.0.1.crt 127.0.0.1.key]  metaDir=[]
AFTER_ENFORCE   certDir=[127.0.0.1.crt 127.0.0.1.key]  metaDir=[acme/audit.jsonl https-state.json]
```

→ **证书目录零改动**，元数据只多两个文件；不存在“改错文件”。

## 2. 降级验证方式（为什么不是 nginx）

```bash
$ systemctl is-active nginx   → inactive
$ nginx -v                    → bash: nginx: 未找到命令（未安装，按任务要求不安装）
$ ss -ltnp | grep :8081       → 已被其它进程占用（未触碰）
```

因此改用**真实 HTTP 服务（Go httptest，随机端口）**复现站点侧行为，验证链路：
`enforce（登记）→ 站点侧应用 apply_hint（301）→ status 判定 → unenforce（清登记）→ 站点侧回滚（200）`。
这不是“配置生成成功就算跳转生效”：**跳转是站点侧那次应用产生的，本仓只负责登记与判定**。

## 3. 实测状态码与判定（原始输出）

```
BASELINE          http=200
ENFORCE_1         created=true changed=true source=plugin applied_hint=site.bindSSL force_https=true
AFTER_ENFORCE     http=200        ← enforce 本身不改变站点行为（see §1）
ENFORCE_2         created=false changed=false sameFile=true   ← 幂等（状态文件字节不变）
AFTER_SITE_APPLY  http=301 location=https://127.0.0.1:18443/  ← 跳转由 site 侧产生
STATUS_AFTER_APPLY {"enforced":true,"source":"plugin","redirect_code":301,"verdict":"https-unreachable"}
UNENFORCE         removed=true enforced=false
AFTER_UNENFORCE   http=301 location=https://127.0.0.1:18443/  ← 站点跳转仍在（site 所有）
STATE_AFTER_UNENFORCE {"entries": []}
AFTER_SITE_ROLLBACK http=200      ← 站点侧回滚后恢复
UNENFORCE_2       removed=false   ← 幂等
AUDIT             https-enforce ×2、https-unenforce ×1（最近在前）
```

结论：
- **幂等**：重复 enforce 不产生重复条目、状态文件字节不变；重复 unenforce 返回 `removed=false` 不报错。
- **回滚**：本仓登记可完整回滚（`STATE_AFTER_UNENFORCE` 为空）；**站点跳转无自动回滚**（见 §4 缺陷 3）。
- **status 三态**：`source=plugin`（本仓登记）已实测；`manual`（未登记但实测在跳）与 `none` 由单测覆盖（`internal/certs/https_state_test.go:TestHTTPSStatusThreeStates`）。

## 4. 发现的问题（只报告，未改代码）

1. **hint 文案自相矛盾**：`internal/certs/https_state.go:194`
   写成「source 会从 plugin 变为 plugin」，应为「从 none/manual 变为 plugin」。属文案缺陷。
2. **`enforced` 是“期望”不是“已生效”**：`internal/certs/https_status.go:134-137` 只按登记判定
   `enforced/source=plugin`，即使 80 侧仍是 200（`force_https=false`）也返回 `enforced=true`。
   当前语义可辩（source=登记来源），但字段名容易被读成“已生效”；建议 v1.1 拆
   `desired` / `effective` 或加 `applied` 字段（本任务不改）。
3. **无自动回滚**（设计如此，非缺陷但需挂账）：`unenforce` 只清本仓登记，
   站点跳转必须由 site 侧再应用一次 `force_https:false`；本仓无法回滚站点配置。

## 5. 未验证项 + 完整验证所需条件（挂账）

| 未验证 | 原因 | 完整验证所需条件 |
| --- | --- | --- |
| 真 nginx 返回 301/308 | 本机未安装 nginx（按要求未装） | 装 nginx 的机器；`nginx -t` 语法校验 + 独立 `nginx -c /tmp/x.conf` 实例（避开在跑的服务） |
| 443 证书能被站点加载 | 无 8443/443 可监听的真实站点 | 一张覆盖测试域名的证书 + 一个可控站点（或 site 插件实例） |
| `apply_hint` 被 site 插件真实执行 | 本仓不依赖 site 插件，测试环境无插件实例 | 装上 `site` 插件并在站点页执行 `site.bindSSL{force_https:true}`，再用 `curl -sI` 复核 |
| enforce 后 `source=manual` 的实机路径 | 依赖 site 已下发而本仓未登记 | 上述环境 + 手工配置跳转后调用 `ssl.https.status` |

## 6. 清理

- 一次性验证测试文件 `internal/certs/zz_verify_enforce_test.go` **已删除**（不提交）。
- 验证用临时目录由 `t.TempDir()` 自动清理；未在 `/tmp` 留站点目录。
- 未启动/停止/修改任何系统 nginx（本机无 nginx 服务）；未触碰已占用 8081 的进程。
