# unmask 一括ビルド.
#
# targets:
#   make build              admin (host arch)
#   make build-admin        admin (= GOARCH に従う)
#   make build-module       ja4 nginx module (.so) for current GOARCH
#   make build-all          admin + module (= release 用 set)
#   make package            nfpm で rpm + deb + apk 生成 (要 nfpm)
#   make test               go test
#   make clean              dist/, build/ を消す
#
# 環境変数:
#   UNMASK_VERSION   (default: 0.1.0)  package version
#   GOOS             (default: linux)
#   GOARCH           (default: 検出した host arch.  amd64 / arm64 / 386 等)
#   NGINX_VERSION    (default: 1.26.2) nginx ソース version (module build 用)
#   NGINX_SRC        (default: build/nginx-$(NGINX_VERSION)) ソース展開先
#   NFPM             (default: nfpm) nfpm binary path
#

UNMASK_VERSION ?= 0.1.0
GOOS           ?= linux
GOARCH         ?= $(shell go env GOARCH 2>/dev/null || echo amd64)

NGINX_VERSION  ?= 1.26.2
NGINX_SRC      ?= build/nginx-$(NGINX_VERSION)
NFPM           ?= nfpm

DIST            = dist
ADMIN_BIN       = $(DIST)/unmask-admin-$(GOOS)-$(GOARCH)
MODULE_SO       = $(DIST)/ngx_http_ja4_module-$(GOOS)-$(GOARCH).so

GOFLAGS = -trimpath -ldflags="-s -w -X main.Version=$(UNMASK_VERSION)"

.PHONY: build build-all build-admin build-module package package-rpm package-deb package-apk test vet fmt clean help

help:
	@printf "unmask Makefile targets:\n\n"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'

## build         - admin binary (host arch)
build: build-admin

## build-all     - admin + ja4 module (release set)
build-all: build-admin build-module

## build-admin   - Go static admin server
build-admin:
	mkdir -p $(DIST)
	cd admin && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build $(GOFLAGS) -o ../$(ADMIN_BIN) ./cmd/unmask-admin
	@echo "built $(ADMIN_BIN)"

## build-module  - nginx dynamic module .so (downloads nginx source as needed)
# 注意: target host nginx と同じ nginx version + 同じ openssl ABI で build しないと
# load_module で reject される. NGINX_VERSION を target に合わせること.
# `nginx -V 2>&1 | tr -- - '\n' | grep with-` で本番 build options を確認できる.
build-module: $(NGINX_SRC)/configure
	cd $(NGINX_SRC) && \
		./configure --with-compat --with-http_ssl_module \
		            --add-dynamic-module=$(CURDIR)/ja4-module && \
		$(MAKE) modules
	mkdir -p $(DIST)
	cp $(NGINX_SRC)/objs/ngx_http_ja4_module.so $(MODULE_SO)
	@echo "built $(MODULE_SO)"

$(NGINX_SRC)/configure: | build
	curl -sSL "https://nginx.org/download/nginx-$(NGINX_VERSION).tar.gz" \
		-o build/nginx-$(NGINX_VERSION).tar.gz
	tar -xzf build/nginx-$(NGINX_VERSION).tar.gz -C build
	rm build/nginx-$(NGINX_VERSION).tar.gz
	touch $(NGINX_SRC)/configure

build:
	mkdir -p build

## package       - rpm + deb + apk
package: package-rpm package-deb package-apk

package-rpm: build-all
	cd rpm && UNMASK_VERSION=$(UNMASK_VERSION) $(NFPM) pkg --packager rpm --target ../$(DIST)
package-deb: build-all
	cd rpm && UNMASK_VERSION=$(UNMASK_VERSION) $(NFPM) pkg --packager deb --target ../$(DIST)
package-apk: build-all
	cd rpm && UNMASK_VERSION=$(UNMASK_VERSION) $(NFPM) pkg --packager apk --target ../$(DIST)

## test          - go test
test:
	cd admin && go test ./...

## vet           - go vet
vet:
	cd admin && go vet ./...

## fmt           - gofmt -l (= unstaged 未整形 ファイル一覧)
fmt:
	cd admin && gofmt -l . | tee /dev/stderr | (! read x)

## clean         - dist/, build/ を消す
clean:
	rm -rf $(DIST) build
