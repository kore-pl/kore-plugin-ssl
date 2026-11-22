# kore-plugin-ssl 构建入口：build / dist / check / clean。
# 确定性纪律（SHA-DRIFT）：info.json 经 go:embed 进入二进制，
# 故 dist 不修改根 info.json（size_bytes 为提交前按实测包体积回写的定值），
# 只把它原样 cp 进 stage，保证同源码两次出包字节一致。
SHELL := /bin/bash

ID := ssl
BIN := bin/$(ID)
DIST := dist
VERSION := $(shell sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' info.json | head -n 1)
PACKAGE := $(DIST)/$(ID)-$(VERSION).tar.gz

.PHONY: build dist check clean

# 静态构建：G-16 基线 + GOWORK=off（隔离外部 workspace，避免依赖漂移）。
build:
	CGO_ENABLED=0 GOWORK=off GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o $(BIN) .

# 确定性打包：--sort=name/固定 mtime/uid/gid + gzip -9n；
# 显式列条目 info.json bin SHA256SUMS（无 ./ 前缀，tar 首条目为 info.json）。
dist: build
	@set -eo pipefail; \
	rm -rf $(DIST)/stage $(PACKAGE) $(PACKAGE).sha256; \
	mkdir -p $(DIST)/stage/bin; \
	cp $(BIN) $(DIST)/stage/bin/$(ID); \
	cp info.json $(DIST)/stage/info.json; \
	chmod 755 $(DIST)/stage/bin/$(ID); \
	chmod 644 $(DIST)/stage/info.json; \
	( cd $(DIST)/stage && sha256sum info.json bin/$(ID) > SHA256SUMS ); \
	tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - -C $(DIST)/stage info.json bin SHA256SUMS | gzip -9n > $(PACKAGE); \
	( cd $(DIST) && sha256sum $(ID)-$(VERSION).tar.gz > $(ID)-$(VERSION).tar.gz.sha256 ); \
	rm -rf $(DIST)/stage; \
	echo "打包完成: $(PACKAGE)"

# 门禁：gofmt（有输出即失败）→ go vet → go test。
check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt 需要格式化："; echo "$$out"; exit 1; fi; echo "gofmt: clean"
	GOWORK=off go vet ./...
	GOWORK=off go test -timeout 200s ./...

clean:
	rm -rf bin dist
	rm -f go.work.sum
