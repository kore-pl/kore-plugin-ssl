// Package boundary 承载 ssl 插件的四类边界用例（PLUGIN-CATALOG §6.1 升级判据①）：
// 异常输入、并发、权限不足、资源耗尽，各 ≥1 例且随 `go test ./...` 进 CI。
//
// 与其他测试目录的分工：
//   - tests/fault    —— 故障注入（kill -9 / 超时 / 磁盘满 / cgroup 超限）；
//   - tests/e2e      —— 真实插件二进制 + UDS 的端到端闭环；
//   - tests/boundary —— 不变量型边界：坏输入必须被结构化拒绝、并发下不丢更新且无
//     数据竞争、权限不足时必须给出明确错误码、资源耗尽时失败而不是写坏文件。
//
// 并发用例需要 -race 才有说服力：go test -race ./tests/boundary/ -count=1。
// 本包不发起真实 ACME 申请（不消耗 CA 配额）：异常/并发/资源用例全部在临时目录上
// 用本地自签证书完成；权限用例只做 webroot 本地可写性预检，不联网。
package boundary
