package certs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"time"
)

// 续期任务的口径：固定每天 03:00 检查一次，到期前 days_before 天才真正重签。
// 插件不能直接调内核 API（G-01：调度归内核 scheduler，ADR-0019），
// 所以 ssl.renew.set 只返回"待创建任务描述"，由前端 POST /api/v1/scheduler/tasks。
const (
	// RenewTaskSchedule 是推荐的 5 段表达式：每天 03:00。
	RenewTaskSchedule = "0 3 * * *"
	// RenewTaskPlugin / RenewTaskMethod 是任务要调的目标。
	RenewTaskPlugin = "ssl"
	RenewTaskMethod = "ssl.renew"
	// defaultRenewDaysBefore 是未传 days_before 时的提前量（天）。
	defaultRenewDaysBefore = 30
	// renewTaskNamePrefix 是任务名前缀，前端据此识别本插件创建的任务。
	renewTaskNamePrefix = "ssl-renew-"
	// schedulerNameMaxLen 与内核 scheduler 的 name ≤64 字符校验对齐。
	schedulerNameMaxLen = 64
	// renewTaskHashLen 是超长域名截断后附加的指纹长度（8 位十六进制）。
	renewTaskHashLen = 8
)

// RenewalTaskRequest 是 ssl.renew.set 的入参：name 为证书主域名，days_before 为提前量。
type RenewalTaskRequest struct {
	Name       string `json:"name"`
	DaysBefore int    `json:"days_before"`
}

// RenewTaskParams 是任务执行时传给 ssl.renew 的参数。
// DaysBefore 与 ssl.renew 的同名参数同口径：未到窗口就跳过，不天天重签。
type RenewTaskParams struct {
	Name       string `json:"name"`
	DaysBefore int    `json:"days_before,omitempty"`
}

// RecommendedTask 是前端可直接 POST 到内核的任务定义（字段与 scheduler.CreateInput 对齐）。
type RecommendedTask struct {
	Name     string          `json:"name"`
	Plugin   string          `json:"plugin"`
	Method   string          `json:"method"`
	Params   RenewTaskParams `json:"params"`
	Schedule string          `json:"schedule"`
}

// RenewalTaskResult 是 ssl.renew.set 的结果。
// created 恒为 false、task_id 恒为空：插件没有创建内核任务的能力，如实返回而不是假装成功。
type RenewalTaskResult struct {
	Created         bool            `json:"created"`
	TaskID          string          `json:"task_id"`
	NextRunAt       string          `json:"next_run_at"`
	RecommendedTask RecommendedTask `json:"recommended_task"`
	Hint            string          `json:"hint"`
}

// RenewalTask 生成"待创建自动续期任务"的描述，不写任何状态、不调内核 API。
//
// 校验顺序刻意先查证书再算任务：证书不存在时给出 E_NOTFOUND，避免前端拿到一份
// 指向不存在证书的任务定义，装到 scheduler 里每天报错。
func (s *Service) RenewalTask(req RenewalTaskRequest) (*RenewalTaskResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	name, perr := validateRenewTaskName(req.Name)
	if perr != nil {
		return nil, perr
	}
	daysBefore := req.DaysBefore
	if daysBefore == 0 {
		daysBefore = defaultRenewDaysBefore
	}
	if perr := validateDaysBefore(daysBefore); perr != nil {
		return nil, perr
	}
	now := nowOr(s.now)
	if _, _, err := s.store.findCert(name, now); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, newCertHintError(codeNotFound,
				"证书目录中未找到 domain "+name+" 的证书",
				"先用 ssl.selfsign 创建或 ssl.import 导入，再设置自动续期")
		}
		return nil, internalErr("定位证书失败: " + err.Error())
	}
	next := nextDailyRun(now, renewTaskHour)
	return &RenewalTaskResult{
		Created:   false,
		TaskID:    "",
		NextRunAt: next.UTC().Format(time.RFC3339),
		RecommendedTask: RecommendedTask{
			Name:     renewTaskName(name),
			Plugin:   RenewTaskPlugin,
			Method:   RenewTaskMethod,
			Params:   RenewTaskParams{Name: name, DaysBefore: daysBefore},
			Schedule: RenewTaskSchedule,
		},
		Hint: "插件不能直接创建内核任务：把 recommended_task 原样 POST 到 /api/v1/scheduler/tasks 才会真正生效",
	}, nil
}

// renewTaskHour 是每日检查时刻（本地时区 03:00），与 RenewTaskSchedule 保持一致。
const renewTaskHour = 3

// validateRenewTaskName 校验证书标识：与 ssl.renew 的 domain 同口径。
func validateRenewTaskName(name string) (string, *CertError) {
	if perr := validateDomain(name); perr != nil {
		return "", perr
	}
	return name, nil
}

// validateDaysBefore 校验提前量：1..3650 天（0 已由调用方折算默认值）。
func validateDaysBefore(days int) *CertError {
	if days < 1 || days > daysMax {
		return invalidParam("days_before 必须在 1..3650（缺省 30）")
	}
	return nil
}

// renewTaskName 生成符合内核约束（≤64 字符）的任务名。
// 域名最长 253 字符，直接拼接会超过 scheduler 的 name 上限；超长时保留前缀 +
// 域名前段 + 域名的 SHA-256 前 8 位，保证确定性且不与其他域名撞名。
func renewTaskName(domain string) string {
	name := renewTaskNamePrefix + domain
	if len(name) <= schedulerNameMaxLen {
		return name
	}
	digest := sha256.Sum256([]byte(domain))
	suffix := "-" + hex.EncodeToString(digest[:])[:renewTaskHashLen]
	head := schedulerNameMaxLen - len(renewTaskNamePrefix) - len(suffix)
	return renewTaskNamePrefix + domain[:head] + suffix
}

// nextDailyRun 返回 now 之后（严格大于）最近一个本地时区的 hour:00。
// 用 AddDate 而非 +24h，跨夏令时切换时仍然是"当地的 3 点"。
func nextDailyRun(now time.Time, hour int) time.Time {
	local := now.In(time.Local)
	next := time.Date(local.Year(), local.Month(), local.Day(), hour, 0, 0, 0, time.Local)
	if !next.After(local) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}
