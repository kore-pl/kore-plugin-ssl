package certs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newFixedService 返回时钟固定在 fixedNow 服务实例（证书与任务时间都可确定复现）。
func newFixedService(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	return NewService(Options{Dir: dir, Now: func() time.Time { return fixedNow }}), dir
}

// TestRenewalTaskRecommendedShape 校验待创建任务的字段、提前量与下次执行时刻。
func TestRenewalTaskRecommendedShape(t *testing.T) {
	svc, _ := newFixedService(t)
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "renew.kore.local"}); perr != nil {
		t.Fatalf("准备证书失败: %v", perr)
	}
	result, perr := svc.RenewalTask(RenewalTaskRequest{Name: "renew.kore.local"})
	if perr != nil {
		t.Fatalf("ssl.renew.set 失败: %v", perr)
	}
	if result.Created || result.TaskID != "" {
		t.Fatalf("插件不能创建内核任务：created=%v task_id=%q 必须为 false/空", result.Created, result.TaskID)
	}
	if result.Hint == "" {
		t.Fatal("必须给出" + "把 recommended_task POST 到 scheduler" + "的可操作 hint")
	}
	task := result.RecommendedTask
	if task.Name != "ssl-renew-renew.kore.local" || task.Plugin != "ssl" ||
		task.Method != "ssl.renew" || task.Schedule != "0 3 * * *" {
		t.Fatalf("任务定义不符：%+v", task)
	}
	if task.Params.Name != "renew.kore.local" || task.Params.DaysBefore != 30 {
		t.Fatalf("任务参数不符：%+v", task.Params)
	}
	assertNextDailyThree(t, result.NextRunAt)

	custom, perr := svc.RenewalTask(RenewalTaskRequest{Name: "renew.kore.local", DaysBefore: 15})
	if perr != nil {
		t.Fatalf("自定义 days_before 失败: %v", perr)
	}
	if custom.RecommendedTask.Params.DaysBefore != 15 {
		t.Fatalf("days_before 应原样进任务参数，实际 %d", custom.RecommendedTask.Params.DaysBefore)
	}
}

// assertNextDailyThree 断言 next_run_at 是 now 之后最近一个本地 03:00。
func assertNextDailyThree(t *testing.T, raw string) {
	t.Helper()
	next, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("next_run_at=%q 不是 RFC3339: %v", raw, err)
	}
	if !next.After(fixedNow) {
		t.Fatalf("next_run_at=%s 必须晚于 now=%s", next, fixedNow)
	}
	if next.Sub(fixedNow) > 24*time.Hour {
		t.Fatalf("next_run_at=%s 距现在超过 24h", next)
	}
	local := next.In(time.Local)
	if local.Hour() != 3 || local.Minute() != 0 || local.Second() != 0 {
		t.Fatalf("next_run_at 本地时间=%02d:%02d:%02d，期望 03:00:00",
			local.Hour(), local.Minute(), local.Second())
	}
}

// TestRenewalTaskValidation 校验前置条件：证书不存在、提前量越界都不返回任务。
func TestRenewalTaskValidation(t *testing.T) {
	svc, _ := newFixedService(t)
	missing, perr := svc.RenewalTask(RenewalTaskRequest{Name: "absent.kore.local"})
	if missing != nil || perr == nil || perr.Code != codeNotFound {
		t.Fatalf("证书不存在应 E_NOTFOUND，实际 %+v / %+v", missing, perr)
	}
	if perr.Hint == "" {
		t.Fatal("证书不存在时必须给 hint（先 selfsign/import）")
	}
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "renew.kore.local"}); perr != nil {
		t.Fatalf("准备证书失败: %v", perr)
	}
	for _, days := range []int{-1, 5000} {
		if _, perr := svc.RenewalTask(RenewalTaskRequest{Name: "renew.kore.local", DaysBefore: days}); perr == nil || perr.Code != codeInvalid {
			t.Fatalf("days_before=%d 应 E_INVALID，实际 %+v", days, perr)
		}
	}
	if _, perr := svc.RenewalTask(RenewalTaskRequest{Name: "BAD DOMAIN"}); perr == nil || perr.Code != codeInvalid {
		t.Fatalf("非法域名应 E_INVALID，实际 %+v", perr)
	}
}

// TestRenewTaskNameLength 覆盖内核 name ≤64 约束：超长域名截断 + 指纹，仍不撞名。
func TestRenewTaskNameLength(t *testing.T) {
	longA := strings.Repeat("a", 50) + ".kore.local"
	longB := strings.Repeat("b", 50) + ".kore.local"
	nameA := renewTaskName(longA)
	nameB := renewTaskName(longB)
	if len(nameA) > schedulerNameMaxLen || len(nameB) > schedulerNameMaxLen {
		t.Fatalf("任务名超长：%d / %d（上限 %d）", len(nameA), len(nameB), schedulerNameMaxLen)
	}
	if !strings.HasPrefix(nameA, renewTaskNamePrefix) {
		t.Fatalf("任务名 %q 缺少前缀", nameA)
	}
	if nameA == nameB {
		t.Fatalf("不同域名生成了相同任务名：%q", nameA)
	}
	if again := renewTaskName(longA); again != nameA {
		t.Fatalf("任务名必须确定性：%q != %q", again, nameA)
	}
	if short := renewTaskName("short.kore.local"); short != "ssl-renew-short.kore.local" {
		t.Fatalf("短域名应直接拼接，实际 %q", short)
	}
}

// TestRenewDaysBeforeSkips 未到窗口时不改文件、不产生备份。
func TestRenewDaysBeforeSkips(t *testing.T) {
	svc, dir := newFixedService(t)
	info, perr := svc.SelfSign(SelfSignRequest{Domain: "skip.kore.local"})
	if perr != nil {
		t.Fatalf("准备证书失败: %v", perr)
	}
	before := info.FingerprintSHA256
	result, perr := svc.Renew(RenewRequest{Domain: "skip.kore.local", DaysBefore: 30})
	if perr != nil {
		t.Fatalf("未到期续期不应报错: %v", perr)
	}
	if result.Renewed || result.Skipped != "not_due" {
		t.Fatalf("未到期应 renewed=false skipped=not_due，实际 %+v", result)
	}
	if result.FingerprintSHA256 != before {
		t.Fatalf("跳过时证书不应变化：%s -> %s", before, result.FingerprintSHA256)
	}
	if _, err := os.Stat(filepath.Join(dir, backupDirName)); !os.IsNotExist(err) {
		t.Fatalf("跳过时不应创建备份目录，stat err=%v", err)
	}
}

// TestRenewBacksUpBeforeOverwrite 到点续期必须先落备份：旧证书字节可回滚、密钥 0600。
func TestRenewBacksUpBeforeOverwrite(t *testing.T) {
	svc, dir := newFixedService(t)
	first, perr := svc.SelfSign(SelfSignRequest{Domain: "due.kore.local", Days: 10})
	if perr != nil {
		t.Fatalf("准备证书失败: %v", perr)
	}
	oldCert := readTestFile(t, filepath.Join(dir, "due.kore.local.crt"))
	oldKey := readTestFile(t, filepath.Join(dir, "due.kore.local.key"))

	renewed, perr := svc.Renew(RenewRequest{Domain: "due.kore.local", Days: 90, DaysBefore: 30})
	if perr != nil {
		t.Fatalf("到点续期失败: %v", perr)
	}
	if !renewed.Renewed || renewed.Skipped != "" {
		t.Fatalf("应真正重签，实际 %+v", renewed)
	}
	if renewed.FingerprintSHA256 == first.FingerprintSHA256 {
		t.Fatal("续期后指纹必须变化（新密钥 + 新序列号）")
	}
	if renewed.BackupPath == "" || !filepath.IsAbs(renewed.BackupPath) {
		t.Fatalf("backup_path=%q 必须是绝对路径", renewed.BackupPath)
	}
	entries, err := os.ReadDir(renewed.BackupPath)
	if err != nil {
		t.Fatalf("读备份目录失败: %v", err)
	}
	var backupCert, backupKey string
	for _, entry := range entries {
		switch {
		case strings.HasSuffix(entry.Name(), ".crt"):
			backupCert = filepath.Join(renewed.BackupPath, entry.Name())
		case strings.HasSuffix(entry.Name(), ".key"):
			backupKey = filepath.Join(renewed.BackupPath, entry.Name())
		}
	}
	if backupCert == "" || backupKey == "" {
		t.Fatalf("备份目录缺证书或私钥：%v", entries)
	}
	if readTestFile(t, backupCert) != oldCert {
		t.Fatal("备份里的证书必须是覆盖前的旧证书字节")
	}
	if readTestFile(t, backupKey) != oldKey {
		t.Fatal("备份里的私钥必须是覆盖前的旧私钥字节")
	}
	if mode := fileMode(t, backupKey); mode != keyFileMode {
		t.Fatalf("备份私钥权限=%o，期望 %o（不得放宽）", mode, keyFileMode)
	}
	if mode := fileMode(t, renewed.BackupPath); mode != dirMode {
		t.Fatalf("备份目录权限=%o，期望 %o", mode, dirMode)
	}
	newNotAfter, err := time.Parse(time.RFC3339, renewed.NotAfter)
	if err != nil {
		t.Fatalf("新证书 not_after 非法: %v", err)
	}
	if !newNotAfter.After(fixedNow.Add(30 * 24 * time.Hour)) {
		t.Fatalf("新证书 not_after=%s 未延后（期望 90 天）", newNotAfter)
	}
}

// TestRenewBackupPruning 备份份数有上限，不会无限增长。
func TestRenewBackupPruning(t *testing.T) {
	dir := t.TempDir()
	clock := fixedNow
	svc := NewService(Options{Dir: dir, Now: func() time.Time { return clock }})
	if _, perr := svc.SelfSign(SelfSignRequest{Domain: "prune.kore.local", Days: 10}); perr != nil {
		t.Fatalf("准备证书失败: %v", perr)
	}
	for i := 0; i < backupKeep+2; i++ {
		clock = clock.Add(time.Minute)
		if _, perr := svc.Renew(RenewRequest{Domain: "prune.kore.local", Days: 90}); perr != nil {
			t.Fatalf("第 %d 次续期失败: %v", i+1, perr)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, backupDirName))
	if err != nil {
		t.Fatalf("读备份目录失败: %v", err)
	}
	certs := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".crt") {
			certs++
		}
	}
	if certs != backupKeep {
		t.Fatalf("备份证书份数=%d，期望保留 %d 份", certs, backupKeep)
	}
}
