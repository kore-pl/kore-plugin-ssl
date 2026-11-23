package main

import (
	"encoding/json"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"github.com/pengtang1024/kore-plugin-ssl/internal/certs"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// statusResult 是 kore.ping 的结果（PLUGIN-PROTOCOL §7.1）。
type statusResult struct {
	Status     string `json:"status"`
	UptimeS    int64  `json:"uptime_s"`
	Goroutines int    `json:"goroutines"`
	RSSKB      int64  `json:"rss_kb"`
}

// dispatch 把请求分发为响应帧；第二个返回值表示收到 kore.shutdown。
func dispatch(request *pluginapi.Request, cfg config, svc *certs.Service, logger *slog.Logger) (*pluginapi.Response, bool) {
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID}
	switch request.Method {
	case "kore.shutdown":
		response.Result = json.RawMessage(`{"ok":true}`)
		logger.Info("收到 kore.shutdown，优雅退出")
		return response, true
	case "kore.ping":
		response.Result = encode(statusResult{
			Status: "ready", UptimeS: int64(time.Since(cfg.startedAt).Seconds()),
			Goroutines: runtime.NumGoroutine(), RSSKB: rssKB(),
		})
		return response, false
	case "kore.reload":
		response.Result = json.RawMessage(`{"ok":true,"config_digest":""}`)
		return response, false
	}
	verb, ok := businessVerb(request.Method, cfg.id)
	if !ok {
		response.Error = notFound(request.Method)
		return response, false
	}
	if perr := handleSSLVerb(verb, request.Params, svc, response); perr != nil {
		response.Error = perr
		response.Result = nil
	}
	return response, false
}

// businessVerb 把 <id>.<verb> 或裸 <verb> 归一为动词名。
// issue 保留为兼容入口：ACME 签发未实现，返回 E_UNSUPPORTED 而不是假装成功。
func businessVerb(method, id string) (string, bool) {
	verb := strings.TrimPrefix(method, id+".")
	switch verb {
	case "list", "import", "selfsign", "renew", "verify", "issue",
		"expiring", "renew.set", "acme.status", "acme.issue",
		"bind.set", "bind.remove", "bind.list", "https.status":
		return verb, true
	default:
		return "", false
	}
}

// errorDetail 是协议错误 detail 的形状：只承载 hint，内核据此填 HTTP 错误体的 hint 字段。
type errorDetail struct {
	Hint string `json:"hint"`
}

// handleSSLVerb 执行 ssl 方法；业务层返回的 CertError 统一转成协议错误体。
func handleSSLVerb(verb string, params json.RawMessage, svc *certs.Service, response *pluginapi.Response) *pluginapi.Error {
	switch verb {
	case "list":
		result, perr := svc.List()
		if perr != nil {
			return toProtocolError(perr)
		}
		response.Result = encode(result)
		return nil
	case "issue":
		// 兼容入口：老调用方可能仍发 ssl.issue。内置 ACME 未实现就如实说，不返回假证书；
		// hint 指向本轮新增的显式通道（ssl.acme.status / ssl.acme.issue）。
		return &pluginapi.Error{
			Code: pluginapi.E_UNSUPPORTED,
			Message: "内置 ACME 签发未实现：请先 ssl.acme.status 检查本机客户端，" +
				"再用 ssl.acme.issue（需 confirm=true）调用 certbot / acme.sh",
			Detail: encode(errorDetail{Hint: "无 ACME 客户端时用 ssl.selfsign 生成自签证书，或用 ssl.import 导入已有证书"}),
		}
	case "expiring":
		p, perr := parseExpiringParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		result, cerr := svc.Expiring(certs.ExpiringRequest{Days: p.Days})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "renew.set":
		p, perr := parseRenewSetParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		result, cerr := svc.RenewalTask(certs.RenewalTaskRequest{Name: p.Name, DaysBefore: p.DaysBefore})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "acme.status":
		if _, perr := parseACMEStatusParams(params); perr != nil {
			return toProtocolError(perr)
		}
		result, cerr := svc.ACMEStatus()
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "acme.issue":
		p, perr := parseACMEIssueParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		result, cerr := svc.ACMEIssue(certs.ACMEIssueRequest{Domain: p.Domain, Email: p.Email, Confirm: p.Confirm})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "import":
		p, perr := parseImportParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		info, cerr := svc.Import(certs.ImportRequest{
			Domain: p.Domain, CertPEM: p.CertPEM, KeyPEM: p.KeyPEM, ChainPEM: p.ChainPEM,
		})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(info)
		return nil
	case "selfsign":
		p, perr := parseSelfSignParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		info, cerr := svc.SelfSign(certs.SelfSignRequest{
			Domain: p.Domain, Days: p.Days, KeyType: p.KeyType, ExtraSANs: p.ExtraSANs,
		})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(info)
		return nil
	case "renew":
		p, perr := parseRenewParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		result, cerr := svc.Renew(certs.RenewRequest{Domain: p.Domain, Days: p.Days, DaysBefore: p.DaysBefore})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "verify":
		p, perr := parseVerifyParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		result, cerr := svc.Verify(certs.VerifyRequest{Domain: p.Domain})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "bind.set":
		p, perr := parseBindSetParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		var probe *certs.BindingProbeRequest
		if p.Probe != nil {
			probe = &certs.BindingProbeRequest{HTTPPort: p.Probe.HTTPPort, HTTPSPort: p.Probe.HTTPSPort}
		}
		result, cerr := svc.SetBinding(certs.SetBindingRequest{
			Cert: p.Cert, Site: p.Site, Note: p.Note, Probe: probe,
		})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "bind.remove":
		p, perr := parseBindRemoveParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		result, cerr := svc.RemoveBinding(certs.RemoveBindingRequest{Cert: p.Cert, Site: p.Site})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "bind.list":
		result, cerr := svc.Bindings()
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	case "https.status":
		p, perr := parseHTTPSStatusParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		result, cerr := svc.HTTPSStatus(certs.HTTPSStatusRequest{
			Domain: p.Domain, HTTPPort: p.HTTPPort, HTTPSPort: p.HTTPSPort,
		})
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(result)
		return nil
	default:
		return notFound(verb)
	}
}

// encode / certsInvalid / notFound / toProtocolError 是协议层错误与结果转换工具。
func encode(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func certsInvalid(msg string) *certs.CertError {
	return &certs.CertError{Code: pluginapi.E_INVALID, Message: msg}
}

func notFound(method string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法：" + method}
}

// toProtocolError 把业务错误转成协议错误，并把 hint 放进 detail（内核映射成 HTTP hint 字段）。
func toProtocolError(cerr *certs.CertError) *pluginapi.Error {
	if cerr == nil {
		return nil
	}
	perr := &pluginapi.Error{Code: cerr.Code, Message: cerr.Message}
	if cerr.Hint != "" {
		perr.Detail = encode(errorDetail{Hint: cerr.Hint})
	}
	return perr
}
