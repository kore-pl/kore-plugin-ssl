package certs

import (
	"sync"
	"time"
)

// Options 是服务构造参数。Dir 为空时回退 KORE_SSL_CERT_DIR / 默认目录；
// Fault 只由运行期 KORE_FAULT 注入；VerifyTimeout/Now 供测试替换，生产留零值。
type Options struct {
	Dir           string
	Fault         Fault
	VerifyTimeout time.Duration
	Now           func() time.Time
	// ACMETools 是 ACME 客户端路径覆盖（键为工具名 certbot / acme.sh）：nil 走生产逻辑
	// （PATH + 固定位置 + 家目录），非 nil 时只认这里显式给出的路径，
	// 让"装了/没装客户端"两种情形都能确定性测试。
	ACMETools map[string]string
}

// Service 是 ssl 业务方法层：所有状态都在固定证书目录里，进程内不缓存清单，
// 每次调用都读磁盘，保证 list 看到的就是真实文件状态。
type Service struct {
	store         *certStore
	fault         Fault
	verifyTimeout time.Duration
	now           func() time.Time
	acmeTools     map[string]string
	// bindMu 串行化站点归属登记的读改写：同一进程内多请求并发时不丢更新。
	bindMu sync.Mutex
}

// NewService 构造服务；空参数得到"默认目录 + 无故障注入"的生产实例。
func NewService(opts Options) *Service {
	dir := opts.Dir
	if dir == "" {
		dir = DirFromEnv()
	}
	return &Service{
		store:         newCertStore(dir),
		fault:         opts.Fault,
		verifyTimeout: opts.VerifyTimeout,
		now:           opts.Now,
		acmeTools:     opts.ACMETools,
	}
}

// List 扫描证书目录，逐条真实解析证书并返回公钥信息。
// 单张证书解析失败只把 error 写进该条目，不影响其它条目。
func (s *Service) List() (*ListResult, *CertError) {
	if perr := faultError(s.fault); perr != nil {
		return nil, perr
	}
	infos, err := s.store.scan(nowOr(s.now))
	if err != nil {
		return nil, internalErr("扫描证书目录失败: " + err.Error())
	}
	return &ListResult{Certs: infos, Count: len(infos)}, nil
}
