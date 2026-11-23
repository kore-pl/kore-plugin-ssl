package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 本文件补齐 ssl 20 个方法里最后 7 个「有 faultError 守卫但缺故障用例」的入口：
//
//	ssl.bind.remove            → RemoveBinding   (binding.go:301-302)
//	ssl.https.enforce          → HTTPSEnforce    (https_state.go:134-135)
//	ssl.https.unenforce        → HTTPSUnenforce  (https_state.go:200-201)
//	ssl.acme.builtin.issue     → ACMEBuiltinIssue  (acme_issue.go:208-209)
//	ssl.acme.builtin.renew     → ACMEBuiltinRenew  (acme_issue.go:340-341)
//	ssl.acme.builtin.status    → ACMEBuiltinStatus (acme_auto.go:43-44)
//	ssl.acme.auto              → ACMEAuto          (acme_auto.go:142-143)
//
// 第 8 个缺口 ssl.issue 不做注入（理由见下方 TestFaultLegacyIssueNeedsNoInjection 注释）：
// 它在 methods.go:83-91 的 dispatch 层直接返回 E_UNSUPPORTED，不经 certs.Service、
// 没有 faultError 守卫、不读不写任何状态；注入任意 Fault 输出完全相同，断言无区分力。
//
// 每个用例都对既有状态做「种子 → 故障调用 → 快照比对 → 清故障后正常调用」四段：
//  1. 用无故障实例把证书 / 归属登记 / HTTPS 期望状态 / ACME 设置落盘（真实状态，不是手工造文件）；
//  2. 同目录换故障实例调用目标方法，断言返回 nil + 结构化协议错误码与关键词；
//  3. 对目录内全部文件做 sha256 快照比对，证明失败路径没有半成品、没改写既有状态；
//  4. 再换回无故障实例，证明同一目录上的状态仍可被正常读写（失败不阻塞后续调用）。
//
// 故障码映射（internal/certs/types.go:198-213）：kill/timeout → E_UPSTREAM；disk-full/cgroup-limit → E_INTERNAL。

// faultCase 是四类故障的统一期望：注入类型、协议错误码、错误消息关键词。
type faultCase struct {
	name     string
	kind     certs.FaultKind
	wantCode string
	wantHint string
}

// fourFaults 是 G-20 要求的四类故障注入表，与既有 kill/timeout/disk/cgroup 用例同一口径。
var fourFaults = []faultCase{
	{"kill", certs.FaultKill, pluginapi.E_UPSTREAM, "kill"},
	{"timeout", certs.FaultTimeout, pluginapi.E_UPSTREAM, "超时"},
	{"disk-full", certs.FaultDiskFull, pluginapi.E_INTERNAL, "ENOSPC"},
	{"cgroup-limit", certs.FaultCgroupLimit, pluginapi.E_INTERNAL, "OOM"},
}

// faultService 返回指向既有目录（含已落盘状态）的故障实例。
func faultService(dir string, kind certs.FaultKind) *certs.Service {
	return certs.NewService(certs.Options{Dir: dir, Fault: certs.Fault(kind)})
}

// snapshotFiles 对目录内全部普通文件取 sha256，返回「相对路径 → 摘要」。
// 只比文件内容：故障路径要么不写，要么就是改了内容，文件名集合与字节都覆盖到。
func snapshotFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		sum := sha256.Sum256(raw)
		files[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("快照证书目录失败: %v", err)
	}
	return files
}

// assertFilesUnchanged 断言故障调用前后目录内容逐文件一致：不新增、不删除、不改写。
func assertFilesUnchanged(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	after := snapshotFiles(t, dir)
	for name, want := range before {
		got, ok := after[name]
		switch {
		case !ok:
			t.Errorf("故障路径删除了既有文件 %s", name)
		case got != want:
			t.Errorf("故障路径改写了既有文件 %s（sha256 %s → %s）", name, want, got)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("故障路径新增了文件 %s（半成品或状态污染）", name)
		}
	}
}

// seedCertificate 用无故障实例真实签出证书，作为归属 / HTTPS / ACME 用例的共同前置状态。
func seedCertificate(t *testing.T, svc *certs.Service, domain string) {
	t.Helper()
	info, perr := svc.SelfSign(certs.SelfSignRequest{Domain: domain, Days: 30})
	if perr != nil {
		t.Fatalf("准备自签证书失败: %v", perr)
	}
	if info == nil || info.Domain != domain {
		t.Fatalf("准备自签证书返回异常: %+v", info)
	}
}

// TestFaultCoversBindRemove 校验 ssl.bind.remove：故障下必须返回协议错误，
// 且既有归属登记（bindings.json）与证书文件一字不改；清故障后登记仍能被正常解除。
func TestFaultCoversBindRemove(t *testing.T) {
	const certName = "fault.kore.local"
	const siteName = "www.kore.local"
	for _, tc := range fourFaults {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			seed := healthyService(dir)
			seedCertificate(t, seed, certName)
			if _, perr := seed.SetBinding(certs.SetBindingRequest{Cert: certName, Site: siteName}); perr != nil {
				t.Fatalf("准备站点归属登记失败: %v", perr)
			}
			before := snapshotFiles(t, dir)

			got, perr := faultService(dir, tc.kind).RemoveBinding(certs.RemoveBindingRequest{Cert: certName, Site: siteName})
			if got != nil {
				t.Fatalf("故障下 bind.remove 不应返回结果: %+v", got)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			assertFilesUnchanged(t, dir, before)

			// 清故障后：登记仍在，解除必须成功且返回唯一命中。
			healthy := healthyService(dir)
			removed, perr := healthy.RemoveBinding(certs.RemoveBindingRequest{Cert: certName, Site: siteName})
			if perr != nil {
				t.Fatalf("清故障后 bind.remove 应成功: %v", perr)
			}
			if removed == nil || removed.Removed != 1 {
				t.Fatalf("清故障后应解除 1 条登记，实际 %+v", removed)
			}
			list, perr := healthy.Bindings()
			if perr != nil || list == nil || list.Count != 0 {
				t.Fatalf("解除后登记应为空，实际 %+v / %+v", list, perr)
			}
		})
	}
}

// seedHTTPSEnforced 建立真实前置状态：证书 + 已登记的「该域名强制 HTTPS」期望状态。
func seedHTTPSEnforced(t *testing.T, dir, domain string) {
	t.Helper()
	seed := healthyService(dir)
	seedCertificate(t, seed, domain)
	result, perr := seed.HTTPSEnforce(domain)
	if perr != nil {
		t.Fatalf("准备强制 HTTPS 期望状态失败: %v", perr)
	}
	if result == nil || !result.Enforced || !result.Created {
		t.Fatalf("准备强制 HTTPS 期望状态返回异常: %+v", result)
	}
}

// TestFaultCoversHTTPSState 校验 ssl.https.enforce / ssl.https.unenforce：
// 故障下不写 https-state.json（也不动证书与审计），且状态保持原样；
// 清故障后幂等 enforce 仍报 enforced=true/changed=false、unenforce 仍能真正移除。
func TestFaultCoversHTTPSState(t *testing.T) {
	const domain = "fault.kore.local"

	t.Run("enforce", func(t *testing.T) {
		for _, tc := range fourFaults {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				seedHTTPSEnforced(t, dir, domain)
				before := snapshotFiles(t, dir)

				got, perr := faultService(dir, tc.kind).HTTPSEnforce(domain)
				if got != nil {
					t.Fatalf("故障下 https.enforce 不应返回结果: %+v", got)
				}
				assertError(t, perr, tc.wantCode, tc.wantHint)
				assertFilesUnchanged(t, dir, before)

				healthy := healthyService(dir)
				again, perr := healthy.HTTPSEnforce(domain)
				if perr != nil || again == nil || !again.Enforced || again.Changed {
					t.Fatalf("清故障后幂等 enforce 应 enforced=true/changed=false，实际 %+v / %+v", again, perr)
				}
				if _, perr := healthy.HTTPSUnenforce(domain); perr != nil {
					t.Fatalf("清故障后 https.unenforce 应成功: %v", perr)
				}
			})
		}
	})

	t.Run("unenforce", func(t *testing.T) {
		for _, tc := range fourFaults {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				seedHTTPSEnforced(t, dir, domain)
				before := snapshotFiles(t, dir)

				got, perr := faultService(dir, tc.kind).HTTPSUnenforce(domain)
				if got != nil {
					t.Fatalf("故障下 https.unenforce 不应返回结果: %+v", got)
				}
				assertError(t, perr, tc.wantCode, tc.wantHint)
				assertFilesUnchanged(t, dir, before)

				// 期望状态没被故障路径清掉：幂等 enforce 仍是 changed=false。
				healthy := healthyService(dir)
				again, perr := healthy.HTTPSEnforce(domain)
				if perr != nil || again == nil || !again.Enforced || again.Changed {
					t.Fatalf("故障后期望状态应仍为 enforced，实际 %+v / %+v", again, perr)
				}
				removed, perr := healthy.HTTPSUnenforce(domain)
				if perr != nil || removed == nil || !removed.Removed {
					t.Fatalf("清故障后 unenforce 应真正移除，实际 %+v / %+v", removed, perr)
				}
			})
		}
	})
}

// seedACMEState 建立内置 ACME 的真实前置状态：证书 + settings.json + audit.jsonl。
// 自动续期开启（且 webroot 指向独立临时站点根），这样 acme.builtin.renew 在清故障后
// 走的是「正常检查、零到期」分支，而不是被「自动续期未开启」的 E_UNSUPPORTED 挡住。
func seedACMEState(t *testing.T, dir, domain, webroot string) {
	t.Helper()
	seed := healthyService(dir)
	seedCertificate(t, seed, domain)
	enabled := true
	result, perr := seed.ACMEAuto(certs.ACMEAutoRequest{
		Enabled: &enabled, Webroot: webroot, Email: "ops@example.com", Confirm: true,
	})
	if perr != nil {
		t.Fatalf("准备 ACME 设置失败: %v", perr)
	}
	if result == nil || !result.AutoRenew {
		t.Fatalf("准备 ACME 设置返回异常: %+v", result)
	}
}

// TestFaultCoversACMEBuiltin 校验 ssl.acme.builtin.status / issue / renew 三个入口：
// 故障下全部在方法首行返回协议错误，不落 ACME 账户/证书/审计等任何文件；
// 清故障后 status 与 renew 仍能正常返回（issue 需真联网向 CA 签发，不属于离网故障用例，
// 用同目录上的 status/renew 证明实例与配置未被失败路径污染）。
func TestFaultCoversACMEBuiltin(t *testing.T) {
	const domain = "fault.kore.local"
	for _, tc := range fourFaults {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			webroot := t.TempDir()
			seedACMEState(t, dir, domain, webroot)
			before := snapshotFiles(t, dir)
			svc := faultService(dir, tc.kind)

			status, perr := svc.ACMEBuiltinStatus()
			if status != nil {
				t.Fatalf("故障下 acme.builtin.status 不应返回结果: %+v", status)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)

			issued, perr := svc.ACMEBuiltinIssue(certs.ACMEBuiltinIssueRequest{
				Domain: domain, Email: "ops@example.com", Webroot: webroot, Confirm: true,
			})
			if issued != nil {
				t.Fatalf("故障下 acme.builtin.issue 不应返回结果: %+v", issued)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)

			renewed, perr := svc.ACMEBuiltinRenew(certs.ACMEBuiltinRenewRequest{})
			if renewed != nil {
				t.Fatalf("故障下 acme.builtin.renew 不应返回结果: %+v", renewed)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)

			assertFilesUnchanged(t, dir, before)

			// 清故障后：配置与实例仍可用，renew 走正常检查且没有到期 ACME 证书。
			healthy := healthyService(dir)
			status, perr = healthy.ACMEBuiltinStatus()
			if perr != nil || status == nil || !status.AutoRenew || status.CA == "" {
				t.Fatalf("清故障后 acme.builtin.status 应成功且配置完好，实际 %+v / %+v", status, perr)
			}
			renewed, perr = healthy.ACMEBuiltinRenew(certs.ACMEBuiltinRenewRequest{})
			if perr != nil || renewed == nil || !renewed.AutoRenew || renewed.Checked != 0 {
				t.Fatalf("清故障后 acme.builtin.renew 应成功且 checked=0，实际 %+v / %+v", renewed, perr)
			}
		})
	}
}

// TestFaultCoversACMEAuto 校验 ssl.acme.auto：故障下拒绝配置变更，
// settings.json 与 audit.jsonl 保持原样；清故障后同一目录仍能正常关闭自动续期。
func TestFaultCoversACMEAuto(t *testing.T) {
	for _, tc := range fourFaults {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			seedACMEState(t, dir, "fault.kore.local", t.TempDir())
			before := snapshotFiles(t, dir)

			disabled := false
			got, perr := faultService(dir, tc.kind).ACMEAuto(certs.ACMEAutoRequest{
				Enabled: &disabled, Confirm: true,
			})
			if got != nil {
				t.Fatalf("故障下 acme.auto 不应返回结果: %+v", got)
			}
			assertError(t, perr, tc.wantCode, tc.wantHint)
			assertFilesUnchanged(t, dir, before)

			healthy := healthyService(dir)
			updated, perr := healthy.ACMEAuto(certs.ACMEAutoRequest{Enabled: &disabled, Confirm: true})
			if perr != nil || updated == nil || updated.AutoRenew {
				t.Fatalf("清故障后 acme.auto 应能关闭自动续期，实际 %+v / %+v", updated, perr)
			}
		})
	}
}

// 注意：第 8 个缺口 ssl.issue 不写注入用例，理由（代码事实，非省事）：
//   - methods.go:83-91 在 dispatch 里直接构造 E_UNSUPPORTED 返回，从未调用 certs.Service；
//   - 因此它没有 faultError 守卫（本仓「守卫已全部接好」指的是其余 19 个 svc 方法），
//     不读 fault 字段、不做任何 I/O、不写任何状态；
//   - 对四种故障注入，输出逐字节相同，断言通过与否与故障无关 —— 硬凑只会制造假覆盖；
//   - tests/fault 是独立包，无法 import package main 的 dispatch 函数，本写域内也没有可注入点。
// 既有 main_test.go:146 已覆盖 ssl.issue 的 E_UNSUPPORTED 契约（错误码 + 不返回结果）。
