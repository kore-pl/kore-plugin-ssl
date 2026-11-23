package certs

import (
	"path/filepath"
	"sort"
)

// 到期告警阈值（天）：不足 7 天 critical、不足 30 天 warning、其余 ok。
// 阈值是口径而不是配置项——前端与后端必须给出同一个分级，避免两处各算一套。
const (
	// SeverityCriticalDays 是 critical 判定上界（days_left < 7）。
	SeverityCriticalDays = 7
	// SeverityWarningDays 是 warning 判定上界（days_left < 30）。
	SeverityWarningDays = 30
	// defaultExpiringWindowDays 是 ssl.expiring 未传 days 时的纳入窗口（与 warning 阈值同口径）。
	defaultExpiringWindowDays = SeverityWarningDays
)

// 严重级别取值；ok 只在调用方把窗口放大到 >30 天时才会出现。
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityOK       = "ok"
)

// ExpiringRequest 是 ssl.expiring 的入参：Days 是纳入窗口（天），0 取 30。
// 窗口是"严格小于"：days=30 表示剩余不足 30 天（与 warning 阈值同边界），
// 窗口只决定"哪些证书进列表"，分级始终按固定阈值算。
type ExpiringRequest struct {
	Days int
}

// ExpiringEntry 是一张证书的到期聚合视图项。
// Name 取证书主域名（与 ssl.renew 的入参同口径，可直接拿去续期/设任务）；
// Path 是证书文件绝对路径（只含公钥信息，不涉及私钥）。
type ExpiringEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	NotAfter string `json:"not_after"`
	DaysLeft int    `json:"days_left"`
	Severity string `json:"severity"`
}

// ExpiringResult 是 ssl.expiring 的结果。
// Checked 是本次真正完成解析的证书张数（解析失败的条目只在 ssl.list 里带 error，
// 无法算天数，不计入 Checked 也不进 Expiring）。
type ExpiringResult struct {
	Expiring []ExpiringEntry `json:"expiring"`
	Checked  int             `json:"checked"`
}

// SeverityFor 按剩余天数分级：<7 critical、<30 warning、其余 ok。
// 已过期（负数）落在 critical——过期比临期更需要立刻处理，不单独设级别。
func SeverityFor(daysLeft int) string {
	switch {
	case daysLeft < SeverityCriticalDays:
		return SeverityCritical
	case daysLeft < SeverityWarningDays:
		return SeverityWarning
	default:
		return SeverityOK
	}
}

// Expiring 扫描全部已管理证书，返回窗口内到期条目的聚合视图。
//
// 与 ssl.list 的分工：list 是逐张明细，expiring 是"还差多少天、要不要报警"的视图。
// 剩余天数由证书 NotAfter 的绝对时刻与当前时刻相减得到（daysLeft 口径与 list 完全一致），
// 因此不受解析端时区影响；not_after 统一以 UTC RFC3339 输出，展示时区交给前端。
func (s *Service) Expiring(req ExpiringRequest) (*ExpiringResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	window := req.Days
	if window == 0 {
		window = defaultExpiringWindowDays
	}
	if window < 1 || window > daysMax {
		return nil, invalidParam("days 必须在 1..3650（缺省 30）")
	}
	now := nowOr(s.now)
	infos, err := s.store.scan(now)
	if err != nil {
		return nil, internalErr("扫描证书目录失败: " + err.Error())
	}
	result := &ExpiringResult{Expiring: make([]ExpiringEntry, 0, len(infos))}
	for _, info := range infos {
		if info.Error != "" {
			continue
		}
		result.Checked++
		if info.DaysLeft >= window {
			continue
		}
		result.Expiring = append(result.Expiring, ExpiringEntry{
			Name:     info.Domain,
			Path:     s.store.certAbsPath(info.File),
			NotAfter: info.NotAfter,
			DaysLeft: info.DaysLeft,
			Severity: SeverityFor(info.DaysLeft),
		})
	}
	// 最紧急的排在最前；同天数按名字保证输出确定性。
	sort.SliceStable(result.Expiring, func(i, j int) bool {
		if result.Expiring[i].DaysLeft != result.Expiring[j].DaysLeft {
			return result.Expiring[i].DaysLeft < result.Expiring[j].DaysLeft
		}
		return result.Expiring[i].Name < result.Expiring[j].Name
	})
	return result, nil
}

// certAbsPath 返回证书文件绝对路径；目录本身是相对路径时尽量转成绝对路径，
// 转不出来就按原样返回（绝不因为取绝对路径失败而让整个方法失败）。
func (s *certStore) certAbsPath(file string) string {
	path := filepath.Join(s.dir, file)
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
