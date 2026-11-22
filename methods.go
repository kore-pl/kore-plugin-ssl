package main

import (
	"context"
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

// methodTimeout 是业务方法调用 ACME 通道的上下文上限（非周期定时器，G-19）。
const methodTimeout = 3 * time.Second

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
func businessVerb(method, id string) (string, bool) {
	verb := strings.TrimPrefix(method, id+".")
	switch verb {
	case "list", "issue", "renew":
		return verb, true
	default:
		return "", false
	}
}

// issueParams 是 ssl.issue 的入参：domain 必填，email 选填。
type issueParams struct {
	Domain string `json:"domain"`
	Email  string `json:"email"`
}

// renewParams 是 ssl.renew 的入参：domain 必填。
type renewParams struct {
	Domain string `json:"domain"`
}

// handleSSLVerb 执行 ssl 方法：list/issue/renew，全部走可注入 Service。
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
		p, perr := parseIssueParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), methodTimeout)
		defer cancel()
		cert, cerr := svc.Issue(ctx, p.Domain, p.Email)
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(cert)
		return nil
	case "renew":
		p, perr := parseRenewParams(params)
		if perr != nil {
			return toProtocolError(perr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), methodTimeout)
		defer cancel()
		cert, cerr := svc.Renew(ctx, p.Domain)
		if cerr != nil {
			return toProtocolError(cerr)
		}
		response.Result = encode(cert)
		return nil
	default:
		return notFound(verb)
	}
}

// parseIssueParams 校验 ssl.issue 入参对象形状并反序列化。
func parseIssueParams(raw json.RawMessage) (issueParams, *certs.CertError) {
	var p issueParams
	if perr := decodeParams(raw, "ssl.issue"); perr != nil {
		return p, perr
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, certsInvalid("params 解析失败: " + err.Error())
	}
	return p, nil
}

// parseRenewParams 校验 ssl.renew 入参对象形状并反序列化。
func parseRenewParams(raw json.RawMessage) (renewParams, *certs.CertError) {
	var p renewParams
	if perr := decodeParams(raw, "ssl.renew"); perr != nil {
		return p, perr
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, certsInvalid("params 解析失败: " + err.Error())
	}
	return p, nil
}

// decodeParams 检查 params 必须是 JSON 对象（或空/null 交由业务层判必填）。
func decodeParams(raw json.RawMessage, method string) *certs.CertError {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] != '{' {
		return certsInvalid(method + " params 必须是 JSON 对象")
	}
	return nil
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

func toProtocolError(cerr *certs.CertError) *pluginapi.Error {
	if cerr == nil {
		return nil
	}
	return &pluginapi.Error{Code: cerr.Code, Message: cerr.Message}
}
