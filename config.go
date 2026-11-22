package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// embeddedInfo 是随二进制发布的内嵌清单：握手用的 version / requires_kore /
// capabilities 与安装期 info.json 同源。size_bytes 属于打包期字段，不参与运行。
//
//go:embed info.json
var embeddedInfo []byte

// manifest 是 info.json 中插件运行期真正需要的字段，其余字段归内核校验。
type manifest struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Protocol     string   `json:"protocol"`
	RequiresKore string   `json:"requires_kore"`
	Capabilities []string `json:"capabilities"`
}

// config 是插件运行期配置：环境变量 + 内嵌清单，不读任何配置文件。
type config struct {
	socket       string
	id           string
	token        string
	version      string
	requiresKore string
	capabilities []string
	startedAt    time.Time
}

// loadConfig 读取 3 个协议环境变量并解析内嵌 info.json。
func loadConfig() (config, error) {
	var m manifest
	if err := json.Unmarshal(embeddedInfo, &m); err != nil {
		return config{}, fmt.Errorf("解析内嵌 info.json: %w", err)
	}
	if m.Protocol != pluginapi.Protocol {
		return config{}, fmt.Errorf("info.json.protocol=%q 与 SDK 协议 %q 不一致", m.Protocol, pluginapi.Protocol)
	}
	cfg := config{
		socket:       os.Getenv("KORE_PLUGIN_SOCK"),
		id:           os.Getenv("KORE_PLUGIN_ID"),
		token:        os.Getenv("KORE_PLUGIN_TOKEN"),
		version:      m.Version,
		requiresKore: m.RequiresKore,
		capabilities: m.Capabilities,
		startedAt:    time.Now(),
	}
	if cfg.id == "" {
		cfg.id = m.ID
	}
	if cfg.socket == "" {
		return config{}, fmt.Errorf("缺少环境变量 KORE_PLUGIN_SOCK")
	}
	return cfg, nil
}
