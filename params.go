package main

import (
	"encoding/json"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
)

// 协议层入参形状与解析。所有 params 都先做"必须是 JSON 对象"的形状校验，
// 再按显式结构体反序列化（G-24：不用 map[string]any 承载业务字段）。
//
// importParams 是 ssl.import 的入参：证书与私钥必填，链选填。
type importParams struct {
	Domain   string `json:"domain"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
	ChainPEM string `json:"chain_pem"`
}

// selfSignParams 是 ssl.selfsign 的入参：domain 必填，其余按默认值。
type selfSignParams struct {
	Domain    string   `json:"domain"`
	Days      int      `json:"days"`
	KeyType   string   `json:"key_type"`
	ExtraSANs []string `json:"extra_sans"`
}

// renewParams 是 ssl.renew 的入参：domain 必填，days 为 0 时沿用原有效期跨度；
// days_before > 0 时只在剩余天数不超过它时才真正重签（定时任务用）。
type renewParams struct {
	Domain     string `json:"domain"`
	Days       int    `json:"days"`
	DaysBefore int    `json:"days_before"`
}

// verifyParams 是 ssl.verify 的入参：host 或 host:port。
type verifyParams struct {
	Domain string `json:"domain"`
}

// expiringParams 是 ssl.expiring 的入参：days 是纳入窗口（天），缺省 30。
type expiringParams struct {
	Days int `json:"days"`
}

// renewSetParams 是 ssl.renew.set 的入参：name 为证书主域名，days_before 为提前量。
type renewSetParams struct {
	Name       string `json:"name"`
	DaysBefore int    `json:"days_before"`
}

// acmeStatusParams 是 ssl.acme.status 的入参（无字段，保留形状校验）。
type acmeStatusParams struct{}

// acmeIssueParams 是 ssl.acme.issue 的入参：confirm 必须为 true 才联网签发。
type acmeIssueParams struct {
	Domain  string `json:"domain"`
	Email   string `json:"email"`
	Confirm bool   `json:"confirm"`
}

// parseImportParams 校验 ssl.import 入参形状并反序列化。
func parseImportParams(raw json.RawMessage) (importParams, *certs.CertError) {
	var p importParams
	if perr := unmarshalParams(raw, &p, "ssl.import"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseSelfSignParams 校验 ssl.selfsign 入参形状并反序列化。
func parseSelfSignParams(raw json.RawMessage) (selfSignParams, *certs.CertError) {
	var p selfSignParams
	if perr := unmarshalParams(raw, &p, "ssl.selfsign"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseRenewParams 校验 ssl.renew 入参形状并反序列化。
func parseRenewParams(raw json.RawMessage) (renewParams, *certs.CertError) {
	var p renewParams
	if perr := unmarshalParams(raw, &p, "ssl.renew"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseVerifyParams 校验 ssl.verify 入参形状并反序列化。
func parseVerifyParams(raw json.RawMessage) (verifyParams, *certs.CertError) {
	var p verifyParams
	if perr := unmarshalParams(raw, &p, "ssl.verify"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseExpiringParams 校验 ssl.expiring 入参形状并反序列化。
func parseExpiringParams(raw json.RawMessage) (expiringParams, *certs.CertError) {
	var p expiringParams
	if perr := unmarshalParams(raw, &p, "ssl.expiring"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseRenewSetParams 校验 ssl.renew.set 入参形状并反序列化。
func parseRenewSetParams(raw json.RawMessage) (renewSetParams, *certs.CertError) {
	var p renewSetParams
	if perr := unmarshalParams(raw, &p, "ssl.renew.set"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseACMEStatusParams 校验 ssl.acme.status 入参形状（不接受数组/标量）。
func parseACMEStatusParams(raw json.RawMessage) (acmeStatusParams, *certs.CertError) {
	var p acmeStatusParams
	if perr := unmarshalParams(raw, &p, "ssl.acme.status"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseACMEIssueParams 校验 ssl.acme.issue 入参形状并反序列化。
func parseACMEIssueParams(raw json.RawMessage) (acmeIssueParams, *certs.CertError) {
	var p acmeIssueParams
	if perr := unmarshalParams(raw, &p, "ssl.acme.issue"); perr != nil {
		return p, perr
	}
	return p, nil
}

// unmarshalParams 要求 params 是 JSON 对象（或空/null 交由业务层判必填）。
func unmarshalParams(raw json.RawMessage, dst any, method string) *certs.CertError {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] != '{' {
		return certsInvalid(method + " params 必须是 JSON 对象")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return certsInvalid(method + " params 解析失败: " + err.Error())
	}
	return nil
}

// bindSetParams 是 ssl.bind.set 的入参：cert 为本仓证书主域名，site 为站点域名。
// probe 只有显式给出时才在登记后附带一次只读 HTTPS 判定（不产生隐式出站）。
type bindSetParams struct {
	Cert  string           `json:"cert"`
	Site  string           `json:"site"`
	Note  string           `json:"note"`
	Probe *bindProbeParams `json:"probe,omitempty"`
}

// bindProbeParams 是绑定登记时附带探测的端口（缺省 80 / 443，仅联调与测试需要显式给）。
type bindProbeParams struct {
	HTTPPort  int `json:"http_port"`
	HTTPSPort int `json:"https_port"`
}

// bindRemoveParams 是 ssl.bind.remove 的入参：cert / site 至少给一个。
type bindRemoveParams struct {
	Cert string `json:"cert"`
	Site string `json:"site"`
}

// httpsStatusParams 是 ssl.https.status 的入参：domain 为 host 或 IP。
type httpsStatusParams struct {
	Domain    string `json:"domain"`
	HTTPPort  int    `json:"http_port"`
	HTTPSPort int    `json:"https_port"`
}

// parseBindSetParams 校验 ssl.bind.set 入参形状并反序列化。
func parseBindSetParams(raw json.RawMessage) (bindSetParams, *certs.CertError) {
	var p bindSetParams
	if perr := unmarshalParams(raw, &p, "ssl.bind.set"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseBindRemoveParams 校验 ssl.bind.remove 入参形状并反序列化。
func parseBindRemoveParams(raw json.RawMessage) (bindRemoveParams, *certs.CertError) {
	var p bindRemoveParams
	if perr := unmarshalParams(raw, &p, "ssl.bind.remove"); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseHTTPSStatusParams 校验 ssl.https.status 入参形状并反序列化。
func parseHTTPSStatusParams(raw json.RawMessage) (httpsStatusParams, *certs.CertError) {
	var p httpsStatusParams
	if perr := unmarshalParams(raw, &p, "ssl.https.status"); perr != nil {
		return p, perr
	}
	return p, nil
}
