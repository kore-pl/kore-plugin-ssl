package certs

import (
	"context"
	"sync"
	"time"
)

// Service 是 ssl 业务方法层的服务：持有可注入 Issuer 与进程内证书清单。
// 清单只在内存维护（骨架口径），不写宿主磁盘、不接真实 CA。
type Service struct {
	Issuer Issuer

	mu    sync.RWMutex
	store map[string]CertInfo
}

// NewService 构造服务；issuer 为 nil 时回退 StubIssuer，保证零依赖可用。
func NewService(issuer Issuer) *Service {
	if issuer == nil {
		issuer = &StubIssuer{}
	}
	return &Service{Issuer: issuer, store: make(map[string]CertInfo)}
}

// ListResult 是 ssl.list 的结构化结果。
type ListResult struct {
	Certs []CertInfo `json:"certs"`
	Count int        `json:"count"`
}

// List 返回全部证书；按域名排序保证输出确定性。
func (s *Service) List() (*ListResult, *CertError) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	certs := make([]CertInfo, 0, len(s.store))
	for _, c := range s.store {
		certs = append(certs, c)
	}
	sortByDomain(certs)
	return &ListResult{Certs: certs, Count: len(certs)}, nil
}

// Issue 校验 domain/email 后经 Issuer 签发一张证书并写入清单。
func (s *Service) Issue(ctx context.Context, domain, email string) (*CertInfo, *CertError) {
	if perr := validateDomain(domain); perr != nil {
		return nil, perr
	}
	if perr := validateEmail(email); perr != nil {
		return nil, perr
	}
	cert, perr := s.Issuer.Issue(ctx, domain)
	if perr != nil {
		return nil, perr
	}
	s.mu.Lock()
	s.store[domain] = *cert
	s.mu.Unlock()
	return cert, nil
}

// Renew 校验 domain 后重新签发并覆盖清单，用于 event:cert.renew_due 续期触发。
func (s *Service) Renew(ctx context.Context, domain string) (*CertInfo, *CertError) {
	if perr := validateDomain(domain); perr != nil {
		return nil, perr
	}
	cert, perr := s.Issuer.Issue(ctx, domain)
	if perr != nil {
		return nil, perr
	}
	renewed := *cert
	renewed.Status = "renewed"
	renewed.NotBefore = time.Now().UTC().Format(time.RFC3339)
	renewed.RenewDue = false
	s.mu.Lock()
	s.store[domain] = renewed
	s.mu.Unlock()
	return &renewed, nil
}

// sortByDomain 按域名升序就地排序（插入排序，避免引入 sort 之外的复杂度）。
func sortByDomain(certs []CertInfo) {
	for i := 1; i < len(certs); i++ {
		for j := i; j > 0 && certs[j].Domain < certs[j-1].Domain; j-- {
			certs[j], certs[j-1] = certs[j-1], certs[j]
		}
	}
}
