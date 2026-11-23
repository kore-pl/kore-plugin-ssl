package certs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedNow 是到期计算的基准时刻（UTC），所有用例的相对天数都相对它构造。
var fixedNow = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

// writeExpiringCert 在目录写一张指定剩余天数的自签证书（<name>.crt + .key）。
func writeExpiringCert(t *testing.T, dir, name string, notAfter time.Time) {
	t.Helper()
	certPEM, keyPEM := makeTestPair(t, testPairOptions{
		domain:    name,
		notBefore: notAfter.Add(-365 * 24 * time.Hour),
		notAfter:  notAfter,
	})
	writeTestFile(t, dir, name+".crt", certPEM)
	writeTestFile(t, dir, name+".key", keyPEM)
}

// TestSeverityForThresholds 固定阈值边界：<7 critical、<30 warning、其余 ok。
func TestSeverityForThresholds(t *testing.T) {
	cases := []struct {
		days int
		want string
	}{
		{-1, SeverityCritical},
		{0, SeverityCritical},
		{6, SeverityCritical},
		{7, SeverityWarning},
		{29, SeverityWarning},
		{30, SeverityOK},
		{365, SeverityOK},
	}
	for _, tc := range cases {
		if got := SeverityFor(tc.days); got != tc.want {
			t.Fatalf("SeverityFor(%d)=%q，期望 %q", tc.days, got, tc.want)
		}
	}
}

// TestExpiringRealDays 用不同 not_after 构造真实证书，验证剩余天数与分级。
func TestExpiringRealDays(t *testing.T) {
	svc, dir := testService(t)
	svc.now = func() time.Time { return fixedNow }
	writeExpiringCert(t, dir, "expired.kore.local", fixedNow.Add(-1*time.Hour))
	writeExpiringCert(t, dir, "six.kore.local", fixedNow.Add(6*24*time.Hour))
	writeExpiringCert(t, dir, "seven.kore.local", fixedNow.Add(7*24*time.Hour))
	writeExpiringCert(t, dir, "twentynine.kore.local", fixedNow.Add(29*24*time.Hour))
	writeExpiringCert(t, dir, "thirty.kore.local", fixedNow.Add(30*24*time.Hour))
	writeExpiringCert(t, dir, "far.kore.local", fixedNow.Add(90*24*time.Hour))

	result, perr := svc.Expiring(ExpiringRequest{})
	if perr != nil {
		t.Fatalf("ssl.expiring 失败: %v", perr)
	}
	if result.Checked != 6 {
		t.Fatalf("checked=%d，期望 6（全部证书都完成解析）", result.Checked)
	}
	// 默认窗口严格小于 30 天：第 30 天那张不进列表（与 warning 阈值同边界）。
	if len(result.Expiring) != 4 {
		t.Fatalf("默认 30 天窗口应纳入 4 张，实际 %d: %+v", len(result.Expiring), result.Expiring)
	}
	want := []struct {
		name     string
		days     int
		severity string
		notAfter time.Time
	}{
		{"expired.kore.local", -1, SeverityCritical, fixedNow.Add(-1 * time.Hour)},
		{"six.kore.local", 6, SeverityCritical, fixedNow.Add(6 * 24 * time.Hour)},
		{"seven.kore.local", 7, SeverityWarning, fixedNow.Add(7 * 24 * time.Hour)},
		{"twentynine.kore.local", 29, SeverityWarning, fixedNow.Add(29 * 24 * time.Hour)},
	}
	for i, w := range want {
		got := result.Expiring[i]
		if got.Name != w.name || got.DaysLeft != w.days || got.Severity != w.severity {
			t.Fatalf("第 %d 条=%+v，期望 name=%s days=%d severity=%s",
				i, got, w.name, w.days, w.severity)
		}
		if got.NotAfter != w.notAfter.Format(time.RFC3339) {
			t.Fatalf("第 %d 条 not_after=%q 与构造值不一致", i, got.NotAfter)
		}
		if !filepath.IsAbs(got.Path) {
			t.Fatalf("第 %d 条 path=%q 必须是绝对路径", i, got.Path)
		}
		if _, statErr := os.Stat(got.Path); statErr != nil {
			t.Fatalf("第 %d 条 path=%q 不存在: %v", i, got.Path, statErr)
		}
	}
}

// TestExpiringWindowBoundary 校验窗口边界：days=30 不含第 30 天，days=31 才纳入且判 ok。
func TestExpiringWindowBoundary(t *testing.T) {
	svc, dir := testService(t)
	svc.now = func() time.Time { return fixedNow }
	writeExpiringCert(t, dir, "thirty.kore.local", fixedNow.Add(30*24*time.Hour))
	edge, perr := svc.Expiring(ExpiringRequest{Days: 30})
	if perr != nil {
		t.Fatalf("窗口 30 失败: %v", perr)
	}
	if len(edge.Expiring) != 0 {
		t.Fatalf("days=30 不应包含第 30 天证书: %+v", edge.Expiring)
	}
	next, perr := svc.Expiring(ExpiringRequest{Days: 31})
	if perr != nil {
		t.Fatalf("窗口 31 失败: %v", perr)
	}
	if len(next.Expiring) != 1 || next.Expiring[0].Severity != SeverityOK {
		t.Fatalf("days=31 应包含 1 条 ok，实际 %+v", next.Expiring)
	}
}

// TestExpiringWideWindowIncludesOK 放大窗口后能拿到 severity=ok 的远期证书。
func TestExpiringWideWindowIncludesOK(t *testing.T) {
	svc, dir := testService(t)
	svc.now = func() time.Time { return fixedNow }
	writeExpiringCert(t, dir, "sixty.kore.local", fixedNow.Add(60*24*time.Hour))
	writeExpiringCert(t, dir, "hundred.kore.local", fixedNow.Add(100*24*time.Hour))

	narrow, perr := svc.Expiring(ExpiringRequest{})
	if perr != nil {
		t.Fatalf("默认窗口失败: %v", perr)
	}
	if len(narrow.Expiring) != 0 || narrow.Checked != 2 {
		t.Fatalf("默认窗口应 0 条/2 张，实际 %d 条/%d 张", len(narrow.Expiring), narrow.Checked)
	}
	wide, perr := svc.Expiring(ExpiringRequest{Days: 90})
	if perr != nil {
		t.Fatalf("90 天窗口失败: %v", perr)
	}
	if len(wide.Expiring) != 1 || wide.Expiring[0].Severity != SeverityOK {
		t.Fatalf("90 天窗口应含 1 条 ok，实际 %+v", wide.Expiring)
	}
}

// TestExpiringBadWindowAndEmptyDir 校验窗口参数与空目录返回形状。
func TestExpiringBadWindowAndEmptyDir(t *testing.T) {
	svc, _ := testService(t)
	if _, perr := svc.Expiring(ExpiringRequest{Days: -5}); perr == nil || perr.Code != codeInvalid {
		t.Fatalf("days=-5 应 E_INVALID，实际 %+v", perr)
	}
	if _, perr := svc.Expiring(ExpiringRequest{Days: 4000}); perr == nil || perr.Code != codeInvalid {
		t.Fatalf("days=4000 应 E_INVALID，实际 %+v", perr)
	}
	result, perr := svc.Expiring(ExpiringRequest{})
	if perr != nil {
		t.Fatalf("空目录应成功: %v", perr)
	}
	if result.Expiring == nil {
		t.Fatal("expiring 必须是空数组而不是 null（前端遍历不能判空对象）")
	}
	if len(result.Expiring) != 0 || result.Checked != 0 {
		t.Fatalf("空目录应 0 条/0 张，实际 %d/%d", len(result.Expiring), result.Checked)
	}
}

// TestExpiringSkipsUnparsable 解析失败的条目不算 checked，也不会伪造天数。
func TestExpiringSkipsUnparsable(t *testing.T) {
	svc, dir := testService(t)
	svc.now = func() time.Time { return fixedNow }
	writeExpiringCert(t, dir, "good.kore.local", fixedNow.Add(5*24*time.Hour))
	writeTestFile(t, dir, "broken.kore.local.crt", "not a pem certificate")
	result, perr := svc.Expiring(ExpiringRequest{})
	if perr != nil {
		t.Fatalf("ssl.expiring 失败: %v", perr)
	}
	if result.Checked != 1 || len(result.Expiring) != 1 {
		t.Fatalf("checked=%d 条数=%d，期望 1/1（坏证书只影响自己）", result.Checked, len(result.Expiring))
	}
	if result.Expiring[0].Name != "good.kore.local" {
		t.Fatalf("条目 name=%q，期望 good.kore.local", result.Expiring[0].Name)
	}
}
