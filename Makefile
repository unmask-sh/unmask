# unmask top-level build.
#
# targets:
#   make build              admin (host arch)
#   make build-admin        admin (follows GOARCH)
#   make build-module       unmask nginx module (.so) for current GOARCH
#   make build-all          admin + module (release set)
#   make package            generate rpm + deb + apk via nfpm (requires nfpm)
#   make test               go test
#   make clean              remove dist/, build/
#
# Environment variables:
#   UNMASK_VERSION   (default: 0.1.5)  package version
#   GOOS             (default: linux)
#   GOARCH           (default: detected host arch.  amd64 / arm64 / 386 / etc.)
#   NGINX_VERSION    (default: 1.26.2) nginx source version (for module build)
#   NGINX_SRC        (default: build/nginx-$(NGINX_VERSION)) source extraction directory
#   NFPM             (default: nfpm) nfpm binary path
#   DOCKER_REGISTRY  (default: empty) registry prefix pushed by docker-buildx
#
# Required external tools:
#   - go              (admin binary build)
#   - gcc / make      (nginx module build)
#   - nfpm            (rpm/deb/apk: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest)
#   - envsubst        (env expansion for nfpm yml; bundled with coreutils / gettext-base)
#   - docker          (docker / docker-buildx target; optional)
#   - aarch64-linux-gnu-gcc (cross compile of arm64 nginx module; optional)
#

UNMASK_VERSION ?= 0.1.13
GOOS           ?= linux
# Default from `go env`; on hosts without Go (e.g. the arm64 qemu builder
# container running build-module-multi) fall back to uname -m, NOT a hardcoded
# amd64 — that silently pointed MULTI_DIR at the amd64 cache inside an aarch64
# container and turned the whole arm64 module build into a "cached" no-op.
GOARCH         ?= $(shell go env GOARCH 2>/dev/null || uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')

NGINX_VERSION  ?= 1.26.2
NGINX_SRC      ?= build/nginx-$(NGINX_VERSION)
NFPM           ?= nfpm

# apk signing key.  Default points at the key store kept beside the repo
# (../../keys/ relative to rpm/, where nfpm runs) -- private keys stay out of
# the git tree.  To sign with another key, pass NFPM_APK_KEY_FILE=... as a
# make argument / env.
# Empty -> nfpm skips signing -> unsigned apk (rejected by apk-tools v3).
NFPM_APK_KEY_FILE ?= ../../keys/oss@unmask.sh-260509.rsa
NFPM_APK_KEY_NAME ?= oss@unmask.sh-260509.rsa.pub
export NFPM_APK_KEY_FILE NFPM_APK_KEY_NAME

DIST            = dist
ADMIN_BIN       = $(DIST)/unmask-$(GOOS)-$(GOARCH)
MODULE_SO       = $(DIST)/ngx_http_unmask_module-$(GOOS)-$(GOARCH).so

# Reproducible-build flags:
#   -trimpath      strip $GOPATH / module cache paths from the binary
#   -buildvcs=false  drop the embedded git revision / dirty flag (= changes when
#                  uncommitted edits exist or different working trees produce the
#                  same commit)
#   -ldflags -s -w  strip debug + symbol tables (= shrinks binary, deterministic)
# Combined with SOURCE_DATE_EPOCH (honoured by Go since 1.20) and a pinned Go
# toolchain via go.mod (= GOTOOLCHAIN=local), two builds from the same commit
# produce byte-identical binaries.  Builds run under nfpm pick up SOURCE_DATE_EPOCH
# via env so the rpm / deb / apk content hashes are stable too.
GOFLAGS = -trimpath -buildvcs=false -ldflags="-s -w -X main.Version=$(UNMASK_VERSION)"

# SOURCE_DATE_EPOCH: pin file mtime + Go's "build info" timestamp.  Default to
# the commit timestamp so reproducible builds work without an explicit override.
# Override on the command line (= `make build SOURCE_DATE_EPOCH=1700000000`)
# when the operator wants a specific deterministic timestamp.
ifeq ($(origin SOURCE_DATE_EPOCH),undefined)
SOURCE_DATE_EPOCH := $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)
endif
export SOURCE_DATE_EPOCH

.PHONY: build build-all build-admin build-module build-module-multi build-module-multi-openssl11 build-module-multi-openssl10 build-module-multi-glibc212 build-module-multi-all build-demo package package-all package-rpm package-deb package-apk package-plugin-nginx package-plugin-nginx-rpm package-plugin-nginx-deb package-plugin-nginx-apk package-plugin-nginx-fat package-web-nginx package-web-apache release docker docker-buildx test e2e e2e-demo e2e-docker e2e-docker-down e2e-hv1 e2e-docker-socket e2e-docker-mariadb e2e-lifecycle distro-check vet fmt clean release-clean help repo repo-apk publish

help:
	@printf "unmask Makefile targets:\n\n"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'

## build         - admin binary (host arch)
build: build-admin

## build-all     - admin + nginx module (release set)
build-all: build-admin build-module

## build-admin   - Go static admin server
build-admin:
	mkdir -p $(DIST)
	cd admin && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build $(GOFLAGS) -o ../$(ADMIN_BIN) ./cmd/unmask

## update-iprange-embed - refresh embedded search-bot bypass-IP ranges from the hub (run + commit before release)
.PHONY: update-iprange-embed
update-iprange-embed:
	cd admin && GOTOOLCHAIN=auto go run ./cmd/unmask update-iprange -out assets/iprange
	@echo ">>> review the diff, then commit admin/assets/iprange/*.json before 'make release'"

## build-module  - nginx dynamic module .so (downloads nginx source as needed)
# Note: must build with the same nginx version + same openssl ABI as the
# target host nginx, or load_module will reject it.  Match NGINX_VERSION to
# the target.  Use `nginx -V 2>&1 | tr -- - '\n' | grep with-` to inspect
# the production build options.
#
# NGINX_WITH_COMPAT is ON by default.  Requires nginx 1.11.5+ (older nginx is
# not supported).  Build with NGINX_WITH_COMPAT=0 for things like RHEL 6 EPEL
# nginx 1.10.3 (loses strict ABI match but builds on older nginx).
NGINX_WITH_COMPAT ?= 1
ifeq ($(NGINX_WITH_COMPAT),1)
NGINX_COMPAT_FLAG = --with-compat
else
NGINX_COMPAT_FLAG =
endif

# arm64 build path switch.  Default is native build assuming QEMU emulation
# (run inside docker buildx --platform=linux/arm64).  The cross-compile path
# (EPEL's aarch64-linux-gnu-gcc + sysroot) is not adopted in v0.1 because of
# missing EPEL sysroot.  When the sysroot is ready, enable NGINX_CROSS_OPTS.
ifeq ($(GOARCH),arm64)
NGINX_BUILD_DIR  = objs-arm64
else
NGINX_BUILD_DIR  = objs
endif
NGINX_CROSS_OPTS =

build-module: $(NGINX_SRC)/configure
	cd $(NGINX_SRC) && \
		./configure --builddir=$(NGINX_BUILD_DIR) $(NGINX_COMPAT_FLAG) --with-http_ssl_module \
		            $(NGINX_CROSS_OPTS) \
		            --add-dynamic-module=$(CURDIR)/nginx-module && \
		$(MAKE) -f $(NGINX_BUILD_DIR)/Makefile modules
	mkdir -p $(DIST)
	cp $(NGINX_SRC)/$(NGINX_BUILD_DIR)/ngx_http_unmask_module.so $(MODULE_SO)
	@echo "built $(MODULE_SO) (nginx $(NGINX_VERSION), with-compat=$(NGINX_WITH_COMPAT), arch=$(GOARCH))"

## build-module-multi - build .so for multiple nginx versions in one go.
# Output: dist/multi-modules/<nginx-ver>/ngx_http_unmask_module.so
# package-plugin-nginx-fat bundles these into one rpm/deb/apk as a fat plugin.
#
# The default version set covers the standard nginx version on major distros:
#   1.10.3   RHEL/CentOS 6 EPEL final; older nginx official repo builds
#   1.12.2   RHEL 7 EPEL
#   1.14.2   Debian 10 / RHEL nginx official 2018
#   1.16.1   Ubuntu 18.04 / Debian backports
#   1.18.0   Debian 11 / Ubuntu 20.04 / 22.04 / Alpine 3.14
#   1.20.2   RHEL nginx official 2021 / Alpine 3.16
#   1.22.1   Debian 12 / RHEL nginx official 2022 / Alpine 3.17/3.18
#   1.24.0   RHEL nginx official 2023 / Alpine 3.19
#   1.26.2   current stable (Alpine 3.20 / RHEL official latest stable branch)
#
# 1.10/1.12 series do not support --with-compat, so build with NGINX_WITH_COMPAT=0.
# 1.14+ build with --with-compat (stronger ABI compat).
PLUGIN_NGINX_VERSIONS ?= 1.10.3 1.12.2 1.14.1 1.14.2 1.16.1 1.18.0 1.20.1 1.20.2 1.22.1 1.24.0 1.26.2 1.26.3 1.28.3 1.30.0

# multi-modules output dir.  amd64 keeps the existing dist/multi-modules/
# (compat); arm64 etc. coexist as dist/multi-modules-<arch>/.
# package-plugin-nginx-fat switches the scan target based on GOARCH.
ifeq ($(GOARCH),amd64)
MULTI_DIR = $(DIST)/multi-modules
else
MULTI_DIR = $(DIST)/multi-modules-$(GOARCH)
endif

build-module-multi:
	@echo ">>> building modules for: $(PLUGIN_NGINX_VERSIONS) (arch=$(GOARCH), OpenSSL 3 from host)"
	@mkdir -p $(MULTI_DIR)
	@for v in $(PLUGIN_NGINX_VERSIONS); do \
		echo ""; \
		echo "=== nginx $$v ==="; \
		out=$(MULTI_DIR)/$$v/ngx_http_unmask_module.so; \
		mkdir -p $$(dirname $$out); \
		if [ -f $$out ]; then \
			echo "  cached: $$out (rm to rebuild)"; \
			continue; \
		fi; \
		compat=1; \
		case "$$v" in 1.10.*|1.11.[0-4]) compat=0 ;; esac; \
		$(MAKE) build-module NGINX_VERSION=$$v NGINX_WITH_COMPAT=$$compat || { \
			echo "!!! build failed for nginx $$v (continuing)"; \
			continue; \
		}; \
		cp $(DIST)/ngx_http_unmask_module-linux-$(GOARCH).so $$out; \
		echo "  saved: $$out"; \
	done
	@echo ""
	@echo ">>> built modules:"
	@ls -la $(MULTI_DIR)/*/*.so 2>/dev/null || echo "  (none)"

# build-module-multi-openssl11: batch-build OpenSSL 1.1 ABI-linked plugin .so
# via an AlmaLinux 8 docker container (targets rhel6/7/8, Debian 11, Ubuntu
# 22.04 hosts).
# Output: dist/multi-modules-openssl11/<ver>/ngx_http_unmask_module.so.
# Prereqs: docker installed + unmask-builder-openssl11 image already built.
#   $ docker build -t unmask-builder-openssl11 build/docker-openssl11/
# Arch-suffixed like MULTI_DIR: amd64 keeps the legacy un-suffixed path; other
# arches get -$(GOARCH).  This also keeps package-plugin-nginx-fat honest for
# arm64 — the openssl11/10/glibc212 bundles exist only for amd64 today, so the
# arm64 package scan finds no files there instead of silently bundling x86 .so
# files the placer could then install on an aarch64 host.
ifeq ($(GOARCH),amd64)
MULTI_OPENSSL11_DIR = $(DIST)/multi-modules-openssl11
BUILDER_OPENSSL11   = unmask-builder-openssl11
else
MULTI_OPENSSL11_DIR = $(DIST)/multi-modules-openssl11-$(GOARCH)
BUILDER_OPENSSL11   = unmask-builder-openssl11-$(GOARCH)
endif
build-module-multi-openssl11:
	@if ! docker image inspect $(BUILDER_OPENSSL11) >/dev/null 2>&1; then \
		echo ">>> building $(BUILDER_OPENSSL11) image first (--platform=linux/$(GOARCH))"; \
		docker build --platform=linux/$(GOARCH) -t $(BUILDER_OPENSSL11) build-docker/openssl11/; \
	fi
	@echo ">>> building modules for: $(PLUGIN_NGINX_VERSIONS) (OpenSSL 1.1 via AlmaLinux 8, $(GOARCH))"
	@mkdir -p $(MULTI_OPENSSL11_DIR)
	@for v in $(PLUGIN_NGINX_VERSIONS); do \
		echo ""; \
		echo "=== nginx $$v (OpenSSL 1.1) ==="; \
		out=$(MULTI_OPENSSL11_DIR)/$$v/ngx_http_unmask_module.so; \
		if [ -f $$out ]; then \
			echo "  cached: $$out (rm to rebuild)"; \
			continue; \
		fi; \
		docker run --rm --platform=linux/$(GOARCH) -v "$$(pwd):/work" $(BUILDER_OPENSSL11) $$v || { \
			echo "!!! build failed for nginx $$v (continuing)"; \
			continue; \
		}; \
	done
	@# The builder runs as root, so the bind-mounted outputs land root-owned and
	@# a later `make clean` cannot delete them.  Hand them back to the invoking
	@# user from inside the same image (no sudo needed on the host).
	@docker run --rm --platform=linux/$(GOARCH) -v "$$(pwd):/work" --entrypoint chown $(BUILDER_OPENSSL11) -R "$$(id -u):$$(id -g)" /work/$(MULTI_OPENSSL11_DIR) 2>/dev/null || true
	@echo ""
	@echo ">>> built modules (OpenSSL 1.1):"
	@ls -la $(MULTI_OPENSSL11_DIR)/*/*.so 2>/dev/null || echo "  (none)"

# build-module-multi-openssl10: batch-build OpenSSL 1.0 ABI-linked plugin .so
# via a CentOS 7 docker container (targets CentOS 7 / RHEL 7 / Oracle Linux 7
# and other libcrypto.so.10 hosts).  CentOS 7 hit EOL on 2024-06-30, so repos
# are sourced from vault.
# Output: dist/multi-modules-openssl10/<ver>/ngx_http_unmask_module.so.
# Prereqs: docker installed + unmask-builder-openssl10 image already built.
#   $ docker build -t unmask-builder-openssl10 build/docker-openssl10/
ifeq ($(GOARCH),amd64)
MULTI_OPENSSL10_DIR = $(DIST)/multi-modules-openssl10
else
MULTI_OPENSSL10_DIR = $(DIST)/multi-modules-openssl10-$(GOARCH)
endif
.PHONY: build-module-multi-openssl10
build-module-multi-openssl10:
	@if ! docker image inspect unmask-builder-openssl10 >/dev/null 2>&1; then \
		echo ">>> building unmask-builder-openssl10 image first"; \
		docker build -t unmask-builder-openssl10 build/docker-openssl10/; \
	fi
	@echo ">>> building modules for: $(PLUGIN_NGINX_VERSIONS) (OpenSSL 1.0 via docker CentOS 7 vault)"
	@mkdir -p $(MULTI_OPENSSL10_DIR)
	@for v in $(PLUGIN_NGINX_VERSIONS); do \
		echo ""; \
		echo "=== nginx $$v (OpenSSL 1.0) ==="; \
		out=$(MULTI_OPENSSL10_DIR)/$$v/ngx_http_unmask_module.so; \
		if [ -f $$out ]; then \
			echo "  cached: $$out (rm to rebuild)"; \
			continue; \
		fi; \
		docker run --rm -v "$$(pwd):/work" unmask-builder-openssl10 $$v || { \
			echo "!!! build failed for nginx $$v (continuing)"; \
			continue; \
		}; \
	done
	@# Hand the root-owned bind-mount outputs back to the invoking user (see
	@# the openssl11 target).
	@docker run --rm -v "$$(pwd):/work" --entrypoint chown unmask-builder-openssl10 -R "$$(id -u):$$(id -g)" /work/dist/multi-modules-openssl10 2>/dev/null || true
	@echo ""
	@echo ">>> built modules (OpenSSL 1.0):"
	@ls -la $(MULTI_OPENSSL10_DIR)/*/*.so 2>/dev/null || echo "  (none)"

# build-module-multi-glibc212: batch-build glibc 2.12 + OpenSSL 1.0 ABI-linked
# plugin .so via a CentOS 6 docker container (targets CentOS 6 / RHEL 6 hosts).
# CentOS 6 hit EOL on 2020-11-30, so repos are pinned to the
# archive.kernel.org HTTP mirror.
# Output: dist/multi-modules-glibc212/<ver>/ngx_http_unmask_module.so.
# Prereqs: docker installed + unmask-builder-centos6 image already built.
#   $ docker build -t unmask-builder-centos6 build/docker-centos6/
ifeq ($(GOARCH),amd64)
MULTI_GLIBC212_DIR = $(DIST)/multi-modules-glibc212
else
MULTI_GLIBC212_DIR = $(DIST)/multi-modules-glibc212-$(GOARCH)
endif
.PHONY: build-module-multi-glibc212
build-module-multi-glibc212:
	@if ! docker image inspect unmask-builder-centos6 >/dev/null 2>&1; then \
		echo ">>> building unmask-builder-centos6 image first"; \
		docker build -t unmask-builder-centos6 build/docker-centos6/; \
	fi
	@echo ">>> building modules for: $(PLUGIN_NGINX_VERSIONS) (glibc 2.12 via docker CentOS 6)"
	@mkdir -p $(MULTI_GLIBC212_DIR)
	@for v in $(PLUGIN_NGINX_VERSIONS); do \
		echo ""; \
		echo "=== nginx $$v (glibc 2.12 / OpenSSL 1.0) ==="; \
		out=$(MULTI_GLIBC212_DIR)/$$v/ngx_http_unmask_module.so; \
		if [ -f $$out ]; then \
			echo "  cached: $$out (rm to rebuild)"; \
			continue; \
		fi; \
		docker run --rm -v "$$(pwd):/work" unmask-builder-centos6 $$v || { \
			echo "!!! build failed for nginx $$v (continuing)"; \
			continue; \
		}; \
	done
	@# Hand the root-owned bind-mount outputs back to the invoking user (see
	@# the openssl11 target).
	@docker run --rm -v "$$(pwd):/work" --entrypoint chown unmask-builder-centos6 -R "$$(id -u):$$(id -g)" /work/dist/multi-modules-glibc212 2>/dev/null || true
	@echo ""
	@echo ">>> built modules (glibc 2.12):"
	@ls -la $(MULTI_GLIBC212_DIR)/*/*.so 2>/dev/null || echo "  (none)"

# build-module-multi-all: build OpenSSL 3 + 1.1 + 1.0 + glibc 2.12 ABIs (for unmask-plugin-nginx-fat).
.PHONY: build-module-multi-all
ifeq ($(GOARCH),amd64)
build-module-multi-all: build-module-multi build-module-multi-openssl11 build-module-multi-openssl10 build-module-multi-glibc212
else
# Non-amd64 (= arm64): ship only OpenSSL 3 + OpenSSL 1.1.  The OpenSSL 1.0
# (CentOS 7 / RHEL 7) and glibc-2.12 (CentOS 6) ABIs target x86-only / EOL
# distros with no arm64 install base -- CentOS 6 never had aarch64 at all -- so
# the arm64 fat plugin bundles just the two modern ABIs.
build-module-multi-all: build-module-multi build-module-multi-openssl11
endif

## build-demo    - demo nginx binary + nginx module (same source tree).  For long-running dev environments.
# Unlike build-module, also generates the nginx binary (objs/nginx).  Not needed at distribution time.
# Start from demo/ with `<NGINX_SRC>/objs/nginx -p demo -c demo/nginx.conf`.
build-demo: $(NGINX_SRC)/configure
	cd $(NGINX_SRC) && \
		./configure --with-compat --with-http_ssl_module \
		            --add-dynamic-module=$(CURDIR)/nginx-module && \
		$(MAKE)
	@echo "built $(NGINX_SRC)/objs/nginx + nginx module"

$(NGINX_SRC)/configure:
	mkdir -p build
	curl -sSL "https://nginx.org/download/nginx-$(NGINX_VERSION).tar.gz" \
		-o build/nginx-$(NGINX_VERSION).tar.gz
	@expected=$$(awk '$$2 == "nginx-$(NGINX_VERSION).tar.gz" {print $$1}' nginx-module/nginx-sha256sums.txt); \
	 if [ -z "$$expected" ]; then \
		echo "ERROR: nginx $(NGINX_VERSION) has no pinned sha256 in nginx-module/nginx-sha256sums.txt -- add it before building" >&2; \
		rm -f build/nginx-$(NGINX_VERSION).tar.gz; exit 1; \
	 fi; \
	 actual=$$(sha256sum build/nginx-$(NGINX_VERSION).tar.gz | cut -d' ' -f1); \
	 if [ "$$expected" != "$$actual" ]; then \
		echo "ERROR: nginx $(NGINX_VERSION) source sha256 mismatch (supply-chain check failed):" >&2; \
		echo "  expected $$expected" >&2; echo "  actual   $$actual" >&2; \
		rm -f build/nginx-$(NGINX_VERSION).tar.gz; exit 1; \
	 fi; \
	 echo ">>> verified nginx-$(NGINX_VERSION).tar.gz sha256 ($$actual)"
	tar -xzf build/nginx-$(NGINX_VERSION).tar.gz -C build
	rm build/nginx-$(NGINX_VERSION).tar.gz
	touch $(NGINX_SRC)/configure

build:
	mkdir -p build

## package       - main unmask rpm/deb/apk (admin only, no nginx module).
# Works with auth_request mode by default.  If you need nginx native (JA4),
# build the plugin separately with package-plugin-nginx and use it alongside.
package: package-rpm package-deb package-apk

## package-release - generate unmask-release rpm/deb/apk.
# A tiny noarch package that drops in repo + GPG key.  Users install it once,
# e.g.:
#   dnf install -y https://unmask.sh/dl/rpm/unmask-release-latest.noarch.rpm
# then `dnf install unmask` pulls in the main body.  Same pattern as
# zabbix / docker / epel, avoiding "curl URL | sh".
#
# Before distribution, replace rpm/release/RPM-GPG-KEY-unmask and
# rpm/release/unmask.rsa.pub with real keys (currently placeholders).
package-release:
	# dearmor the deb keyring (apt's Signed-By: expects a binary keyring).
	# Leaving ASCII armor as-is makes apt-get update ignore the repo with NO_PUBKEY.
	mkdir -p build/release
	gpg --dearmor --yes -o build/release/unmask.gpg < rpm/release/RPM-GPG-KEY-unmask
	$(call _nfpm_yaml,release,unmask-release,all,unmask project,https://unmask.sh/,$(DIST)/.tmp-pkg/nfpm-release.yaml)
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-release.yaml --packager rpm --target ../$(DIST)
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-release.yaml --packager deb --target ../$(DIST)
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-release.yaml --packager apk --target ../$(DIST)
	rm -f $(DIST)/.tmp-pkg/nfpm-release.yaml

## repo - assemble a distribution layout including metadata into repo/ from
# the rpm/deb/apk under dist/ (tools/build-repo.sh). Output: ../unmask-dl-build/.
# Upload to unmask.sh/dl/ is a separate target.
# To sign, pass UNMASK_GPG_KEY_ID / UNMASK_RSA_PRIVKEY via environment.
# deb / apk metadata generation needs apt-ftparchive / apk (which AlmaLinux
# lacks by default; intended to run on Debian or inside docker).
repo:
	./tools/build-repo.sh

## repo-apk - regenerate the apk repo index (APKINDEX.tar.gz) inside an
# Alpine 3.20 container.  A non-Alpine build host (e.g. Rocky 9) lacks
# apk-tools / abuild, so the apk stage of `make repo` is otherwise skipped
# and the
# `../unmask-dl-build/apk/` tree goes stale.  This target:
#   1. Builds (or reuses) the unmask-alpine-builder image from tools/Dockerfile.alpine
#   2. Mounts the repo + the sibling keys/ and unmask-dl-build/ into /work,
#      /keys, /out respectively.
#   3. Runs `tools/build-repo.sh /out apk` (= apk stage only) inside the
#      container, leaving /rpm/ and /deb/ untouched.
#
# Inputs (override via env):
#   UNMASK_RSA_PRIVKEY  default: /keys/oss@unmask.sh-260509.rsa
#   UNMASK_RSA_PUBNAME  default: oss@unmask.sh-260509.rsa.pub
#                       (= the name written into APKINDEX's RSA signature
#                        filename; apk-tools looks for /etc/apk/keys/<pubname>
#                        on the client, shipped via unmask-release).
#   UNMASK_GPG_KEY_ID   accepted for parity with `make repo`; ignored by apk stage.
#
# Container runs as the host uid:gid so files under /out stay writable by the
# `apps` user (= no root-owned files in unmask-dl-build/).
repo-apk:
	@test -d $(DIST) || { echo 'ERR: $(DIST) absent; run `make package` first' >&2; exit 1; }
	@test -d ../keys || { echo 'ERR: ../keys missing — expected RSA private key at ../keys/oss@unmask.sh-260509.rsa' >&2; exit 1; }
	@test -d ../unmask-dl-build || { echo 'ERR: ../unmask-dl-build missing — run `make repo` once to seed the layout' >&2; exit 1; }
	docker build -t unmask-alpine-builder -f tools/Dockerfile.alpine tools/
	docker run --rm \
		--user $(shell id -u):$(shell id -g) \
		-v $(realpath .):/work \
		-v $(realpath ../keys):/keys:ro \
		-v $(realpath ../unmask-dl-build):/out \
		-e UNMASK_RSA_PRIVKEY=$${UNMASK_RSA_PRIVKEY:-/keys/oss@unmask.sh-260509.rsa} \
		-e UNMASK_RSA_PUBNAME=$${UNMASK_RSA_PUBNAME:-oss@unmask.sh-260509.rsa.pub} \
		unmask-alpine-builder \
		/work/tools/build-repo.sh /out apk
	@echo ""
	@echo ">>> apk repo regenerated at ../unmask-dl-build/apk/"
	@ls -la ../unmask-dl-build/apk/main/*/APKINDEX.tar.gz 2>/dev/null || true

## publish - rsync repo/ to unmask.sh/dl/ (a GCE VM) via tools/publish-repo.sh.
# UNMASK_DL_HOST / UNMASK_DL_USER / UNMASK_DL_PATH / UNMASK_SSH_KEY override
# the connection.  For --dry-run, run `make publish ARGS=--dry-run`.
publish:
	./tools/publish-repo.sh $(ARGS)

## sign-rpm - GPG-sign dist/*.rpm (rpm --addsign).
# Env: UNMASK_GPG_KEY_ID (required, e.g. C03DD45E28C4446FDDC48EFC34A320B544B28158).
# Optional:
#   UNMASK_GNUPGHOME       project-local keyring (default keys/gpg)
#   UNMASK_GPG_PASSPHRASE  for batch / CI; omit to be prompted via read -s
# Prereqs: rpm-sign (dnf install rpm-sign) + secret imported into UNMASK_GNUPGHOME.
# Reuses the passphrase-preset logic in tools/build-repo.sh by invoking a tiny
# shim that exports GNUPGHOME, presets the cached passphrase into the agent
# once, then runs rpm --addsign with the cache hit on every package.
sign-rpm:
	@[ -n "$(UNMASK_GPG_KEY_ID)" ] || { echo "ERR: UNMASK_GPG_KEY_ID not set (e.g. C03DD45E...44B28158)" >&2; exit 1; }
	@./tools/with-gpg-preset.sh rpm --addsign --define "_gpg_name $(UNMASK_GPG_KEY_ID)" $(DIST)/*.rpm

## sign-verify - verify GPG signatures on dist/*.rpm.
sign-verify:
	@for f in $(DIST)/*.rpm; do echo "--- $$f ---"; rpm -K "$$f"; done

# nfpm yaml is built up from rpm/templates/* via envsubst.  Three fragments:
#   common.yaml.in     — name / arch / version / vendor / homepage / license
#   signing.yaml.in    — rpm / deb / apk signing blocks (= product packages only,
#                        not for unmask-release which is the chain-of-trust root)
#   <kind>-body.yaml.in — description / depends / contents / scripts / overrides
# concatenated into $(DIST)/.tmp-pkg/nfpm-<kind>.<arch>.yaml and fed to nfpm.
#
# nfpm itself does not expand env vars in contents.src, so each fragment is
# expanded with envsubst at concat time.
NFPM_TPL = rpm/templates

# _nfpm_yaml — assemble one yml from the templates.
#   $(1) kind            (= main / plugin-nginx / plugin-nginx-fat / release /
#                          web-nginx / web-apache)
#   $(2) PACKAGE_NAME    (= unmask / unmask-plugin-nginx / unmask-release / ...)
#   $(3) PACKAGE_ARCH    (= $(GOARCH) for binaries, "all" for unmask-release)
#   $(4) PACKAGE_VENDOR  (= "unmask" for product packages, "unmask project" for release)
#   $(5) PACKAGE_HOMEPAGE
#   $(6) output yaml path
#
# Note: unmask-release intentionally OMITS signing.yaml.in (= the release
# package IS the chain-of-trust root; signing it with the same key would be
# circular).  apk signing for release is inlined into release-body.yaml.in
# because alpine refuses unsigned packages outright.
define _nfpm_yaml
	mkdir -p $$(dirname $(6))
	PACKAGE_NAME='$(2)' PACKAGE_ARCH='$(3)' PACKAGE_VENDOR='$(4)' PACKAGE_HOMEPAGE='$(5)' UNMASK_VERSION='$(UNMASK_VERSION)' \
		envsubst '$$PACKAGE_NAME $$PACKAGE_ARCH $$PACKAGE_VENDOR $$PACKAGE_HOMEPAGE $$UNMASK_VERSION' \
		< $(NFPM_TPL)/common.yaml.in > $(6)
	if [ "$(1)" != "release" ]; then \
		PACKAGE_HOMEPAGE='$(5)' \
			envsubst '$$PACKAGE_HOMEPAGE $$NFPM_RPM_KEY_FILE $$NFPM_APK_KEY_FILE $$NFPM_APK_KEY_NAME' \
			< $(NFPM_TPL)/signing.yaml.in >> $(6) ; \
	fi
	UNMASK_VERSION='$(UNMASK_VERSION)' UNMASK_ARCH='$(GOARCH)' \
		envsubst '$$UNMASK_ARCH $$UNMASK_VERSION $$NFPM_APK_KEY_FILE $$NFPM_APK_KEY_NAME' \
		< $(NFPM_TPL)/$(1)-body.yaml.in >> $(6)
endef

# Concatenated yaml for the main `unmask` package goes through nfpm for a given packager ($1).
# `cd rpm` is required because contents.src paths in main-body.yaml.in are
# relative to rpm/ (= same convention every nfpm target shares).
define _nfpm_main
	$(call _nfpm_yaml,main,unmask,$(GOARCH),unmask,https://github.com/unmask-sh/unmask,$(DIST)/.tmp-pkg/nfpm-main.$(GOARCH).yaml)
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-main.$(GOARCH).yaml --packager $(1) --target ../$(DIST)
	rm -f $(DIST)/.tmp-pkg/nfpm-main.$(GOARCH).yaml
endef

# The main package only needs the admin binary (no nginx module required).
package-rpm: build-admin
	$(call _nfpm_main,rpm)
package-deb: build-admin
	$(call _nfpm_main,deb)
package-apk: build-admin
	$(call _nfpm_main,apk)

## package-plugin-nginx-fat - bundle .so for multiple nginx versions into one plugin.
# Prereq: build-module-multi has generated .so for all versions (dist/multi-modules/<ver>/...).
# postinstall picks the best match based on host nginx version.
# One rpm/deb/apk handles any host whose nginx is one of PLUGIN_NGINX_VERSIONS.
# Output filenames (nginx version is not embedded):
#   dist/unmask-plugin-nginx-<unmask_ver>-1.<arch>.rpm
#   dist/unmask-plugin-nginx_<unmask_ver>_<arch>.deb
#   dist/unmask-plugin-nginx_<unmask_ver>_<arch>.apk
# The auto-build prereq applies on amd64 only: the .so for other arches can
# only be produced under qemu (see PRE-RELEASE step 0) — letting the host
# toolchain "fill in" missing versions would drop x86 .so files into the
# arm64 cache and poison the aarch64 package.  Non-amd64 packaging instead
# hard-requires the pre-built cache below.
ifeq ($(GOARCH),amd64)
package-plugin-nginx-fat: build-module-multi-all
endif
package-plugin-nginx-fat:
	@if [ "$(GOARCH)" != "amd64" ]; then \
		ls $(MULTI_DIR)/*/*.so >/dev/null 2>&1 || { \
			echo "!! $(MULTI_DIR) is missing/empty — build the $(GOARCH) .so cache under qemu first:"; \
			echo "   docker run --rm --platform=linux/$(GOARCH) -v \$$PWD:/work -w /work debian:12 \\"; \
			echo "     bash -c 'apt-get update -qq && apt-get install -y -qq build-essential make libpcre3-dev libpcre2-dev zlib1g-dev libssl-dev && make build-module-multi GOARCH=$(GOARCH)'"; \
			exit 1; }; \
	fi
	mkdir -p $(DIST)/.tmp-pkg
	# 1. Assemble the nfpm yml from rpm/templates/* (plugin-nginx-fat-body.yaml.in
	#    ends with `contents:` and an empty list, ready for append).
	$(call _nfpm_yaml,plugin-nginx-fat,unmask-plugin-nginx,$(GOARCH),unmask,https://github.com/unmask-sh/unmask,$(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml)
	# 2. Append the bundled .so list to contents.
	#    OpenSSL 3 build (dist/multi-modules/<v>/...) -> /usr/share/unmask/plugin/openssl3/
	#    OpenSSL 1.1 build (dist/multi-modules-openssl11/<v>/...) -> /usr/share/unmask/plugin/openssl11/
	#    postinstall checks the host's libssl version and cp's the right one to /usr/lib/nginx/modules/.
	@for d in $(MULTI_DIR)/*/; do \
		v=$$(basename "$$d"); \
		so="$$d/ngx_http_unmask_module.so"; \
		[ -f "$$so" ] || continue; \
		echo "  - src: ../$$so" >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "    dst: /usr/share/unmask/plugin/openssl3/ngx_http_unmask_module-$$v.so" >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "    file_info:"                                                            >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "      mode: 0644"                                                          >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "  -> bundling nginx $$v (OpenSSL 3)"; \
	done
	@for d in $(MULTI_OPENSSL11_DIR)/*/; do \
		v=$$(basename "$$d"); \
		so="$$d/ngx_http_unmask_module.so"; \
		[ -f "$$so" ] || continue; \
		echo "  - src: ../$$so" >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "    dst: /usr/share/unmask/plugin/openssl11/ngx_http_unmask_module-$$v.so" >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "    file_info:"                                                             >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "      mode: 0644"                                                           >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "  -> bundling nginx $$v (OpenSSL 1.1)"; \
	done
	@for d in $(MULTI_OPENSSL10_DIR)/*/; do \
		v=$$(basename "$$d"); \
		so="$$d/ngx_http_unmask_module.so"; \
		[ -f "$$so" ] || continue; \
		echo "  - src: ../$$so" >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "    dst: /usr/share/unmask/plugin/openssl10/ngx_http_unmask_module-$$v.so" >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "    file_info:"                                                             >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "      mode: 0644"                                                           >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "  -> bundling nginx $$v (OpenSSL 1.0)"; \
	done
	@for d in $(MULTI_GLIBC212_DIR)/*/; do \
		v=$$(basename "$$d"); \
		so="$$d/ngx_http_unmask_module.so"; \
		[ -f "$$so" ] || continue; \
		echo "  - src: ../$$so" >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "    dst: /usr/share/unmask/plugin/glibc212/ngx_http_unmask_module-$$v.so" >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "    file_info:"                                                            >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "      mode: 0644"                                                          >> $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml; \
		echo "  -> bundling nginx $$v (CentOS 6 / glibc 2.12)"; \
	done
	# 3. Build all 3 formats.
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml --packager rpm --target ../$(DIST)
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml --packager deb --target ../$(DIST)
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml --packager apk --target ../$(DIST)
	rm -f $(DIST)/.tmp-pkg/nfpm-plugin-nginx-fat.$(GOARCH).yaml
	rm -rf $(DIST)/.tmp-pkg
	@echo ""
	@echo ">>> fat plugin output:"
	@ls -lah $(DIST)/unmask-plugin-nginx-$(UNMASK_VERSION)-1.*.rpm \
	         $(DIST)/unmask-plugin-nginx_$(UNMASK_VERSION)_*.deb \
	         $(DIST)/unmask-plugin-nginx_$(UNMASK_VERSION)_*.apk 2>/dev/null

## package-plugin-nginx - optional plugin for the nginx native module (rpm/deb/apk set).
# Prereq: run `build-module NGINX_VERSION=<host nginx version>` once.
# Output (a distro-agnostic .so placed at a staging path; postinstall cp's it
# into nginx's --modules-path=, hence distro-agnostic):
#   dist/unmask-plugin-nginx-<unmask_ver>-nginx_<X.Y.Z>.<arch>.rpm
#   dist/unmask-plugin-nginx_<unmask_ver>-nginx_<X.Y.Z>_<arch>.deb
#   dist/unmask-plugin-nginx_<unmask_ver>-nginx_<X.Y.Z>_<arch>.apk
package-plugin-nginx: package-plugin-nginx-rpm package-plugin-nginx-deb package-plugin-nginx-apk

# Shared macro: assemble plugin-nginx (single variant) yml + a NGINX_VERSION-baked
# preinstall, then run nfpm.  The preinstall is templated separately because
# nfpm scripts: takes a file path, not inline content.
define _nfpm_plugin
	mkdir -p $(DIST)/.tmp-pkg
	sed "s|__NGINX_VERSION__|$(NGINX_VERSION)|g" rpm/scripts/preinstall-plugin-nginx.sh > $(DIST)/.tmp-pkg/preinstall-plugin-nginx.sh
	chmod +x $(DIST)/.tmp-pkg/preinstall-plugin-nginx.sh
	$(call _nfpm_yaml,plugin-nginx,unmask-plugin-nginx,$(GOARCH),unmask,https://github.com/unmask-sh/unmask,$(DIST)/.tmp-pkg/nfpm-plugin-nginx.$(GOARCH).yaml)
	sed -i "s|./scripts/preinstall-plugin-nginx.sh|../$(DIST)/.tmp-pkg/preinstall-plugin-nginx.sh|" $(DIST)/.tmp-pkg/nfpm-plugin-nginx.$(GOARCH).yaml
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-plugin-nginx.$(GOARCH).yaml --packager $(1) --target ../$(DIST)
	rm -f $(DIST)/.tmp-pkg/nfpm-plugin-nginx.$(GOARCH).yaml
	rm -rf $(DIST)/.tmp-pkg
endef

package-plugin-nginx-rpm: build-module
	$(call _nfpm_plugin,rpm)
	# rpm: original name unmask-plugin-nginx-X.Y.Z-1.<arch>.rpm
	#    -> new name unmask-plugin-nginx-X.Y.Z-nginx_A.B.C.<arch>.rpm
	@for f in $(DIST)/unmask-plugin-nginx-$(UNMASK_VERSION)-1.*.rpm; do \
		test -f "$$f" || continue; \
		new=$$(echo "$$f" | sed "s|-1\\.\\([^.]*\\)\\.rpm$$|-nginx_$(NGINX_VERSION).\\1.rpm|"); \
		mv "$$f" "$$new"; \
		echo ">>> plugin rpm: $$new"; \
	done

package-plugin-nginx-deb: build-module
	$(call _nfpm_plugin,deb)
	# deb: original name unmask-plugin-nginx_X.Y.Z_<arch>.deb
	#    -> new name unmask-plugin-nginx_X.Y.Z-nginx_A.B.C_<arch>.deb
	@for f in $(DIST)/unmask-plugin-nginx_$(UNMASK_VERSION)_*.deb; do \
		test -f "$$f" || continue; \
		new=$$(echo "$$f" | sed "s|_$(UNMASK_VERSION)_|_$(UNMASK_VERSION)-nginx_$(NGINX_VERSION)_|"); \
		mv "$$f" "$$new"; \
		echo ">>> plugin deb: $$new"; \
	done

package-plugin-nginx-apk: build-module
	$(call _nfpm_plugin,apk)
	# apk: original name unmask-plugin-nginx_X.Y.Z_<arch>.apk
	#    -> new name unmask-plugin-nginx_X.Y.Z-nginx_A.B.C_<arch>.apk
	@for f in $(DIST)/unmask-plugin-nginx_$(UNMASK_VERSION)_*.apk; do \
		test -f "$$f" || continue; \
		new=$$(echo "$$f" | sed "s|_$(UNMASK_VERSION)_|_$(UNMASK_VERSION)-nginx_$(NGINX_VERSION)_|"); \
		mv "$$f" "$$new"; \
		echo ">>> plugin apk: $$new"; \
	done

# ----------------------------------------------------------------
# unmask-web-<server> packages (drop a snippet into /etc/<httpd>/conf.d/).
# After install, `https://host/unmask/admin/` immediately renders the UI
# (zabbix pattern).  Distributed as separate rpm/deb/apk from the main
# unmask; pick the web server you want and install it.
# ----------------------------------------------------------------

# Shared macro: assemble web-<server> yml + run nfpm.
#   $(1) server name (nginx / apache)
#   $(2) packager    (rpm / deb / apk)
define _nfpm_web
	$(call _nfpm_yaml,web-$(1),unmask-web-$(1),$(GOARCH),unmask,https://github.com/unmask-sh/unmask,$(DIST)/.tmp-pkg/nfpm-web-$(1).$(GOARCH).yaml)
	cd rpm && $(NFPM) pkg --config ../$(DIST)/.tmp-pkg/nfpm-web-$(1).$(GOARCH).yaml --packager $(2) --target ../$(DIST)
	rm -f $(DIST)/.tmp-pkg/nfpm-web-$(1).$(GOARCH).yaml
endef

## package-web-nginx  - generate the nginx conf.d snippet as rpm/deb/apk
package-web-nginx:
	$(call _nfpm_web,nginx,rpm)
	$(call _nfpm_web,nginx,deb)
	$(call _nfpm_web,nginx,apk)

## package-web-apache - generate the Apache conf.d snippet as rpm/deb/apk
package-web-apache:
	$(call _nfpm_web,apache,rpm)
	$(call _nfpm_web,apache,deb)
	$(call _nfpm_web,apache,apk)

## package-all   - generate rpm/deb/apk for both amd64 and arm64 in one run
# Note: cross-compiling the nginx module (arm64 host != build host) requires
# a GCC cross toolchain (aarch64-linux-gnu-gcc).  Without it, only the admin
# binary is built for arm64.  If you build the .so on another host with
# `make build-module GOARCH=arm64` and drop it into dist/, this target picks it up.
package-all:
	$(MAKE) package GOARCH=amd64
	@if [ "$$(uname -m)" = "aarch64" ] || command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then \
		echo ">> arm64 toolchain found, building arm64 packages"; \
		$(MAKE) package GOARCH=arm64 CC=aarch64-linux-gnu-gcc; \
	elif [ -f $(DIST)/ngx_http_unmask_module-linux-arm64.so ] && [ -f $(DIST)/unmask-linux-arm64 ]; then \
		echo ">> arm64 artifacts already present, packaging only"; \
		$(MAKE) package-rpm GOARCH=arm64; \
		$(MAKE) package-deb GOARCH=arm64; \
		$(MAKE) package-apk GOARCH=arm64; \
	else \
		echo "!! arm64 cross toolchain not found and no prebuilt arm64 artifacts in $(DIST)/"; \
		echo "!! skipping arm64 package.  install gcc-aarch64-linux-gnu or build artifacts on arm64 host."; \
	fi

## docker        - unmask Docker image (host arch). tag: unmask/admin:$(UNMASK_VERSION)
docker:
	docker build -t unmask/admin:$(UNMASK_VERSION) -t unmask/admin:latest \
		--build-arg UNMASK_VERSION=$(UNMASK_VERSION) .

## docker-buildx - multi-arch image (amd64 + arm64).  To push to a registry,
# pass DOCKER_REGISTRY=docker.io/youruser/.  Unset = local image only.
DOCKER_REGISTRY ?=
docker-buildx:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg UNMASK_VERSION=$(UNMASK_VERSION) \
		-t $(DOCKER_REGISTRY)unmask/admin:$(UNMASK_VERSION) \
		-t $(DOCKER_REGISTRY)unmask/admin:latest \
		$(if $(DOCKER_REGISTRY),--push,--load) \
		.

## release       - batch-build main unmask + per-nginx-version plugin -> checksums.
# Main package (admin only): amd64 + arm64 (if cross toolchain is available).
# Plugin (nginx native module): one per version in NGINX_VERSIONS.
# Default is latest stable + the highly-compatible 1.18 / 1.20.  To extend, pass via env.
NGINX_VERSIONS ?= 1.20.2 1.18.0
release: release-clean
	@echo ">>> building release v$(UNMASK_VERSION)"
	# Main package (admin only / no nginx-module)
	$(MAKE) build-admin GOARCH=amd64
	$(MAKE) package-rpm GOARCH=amd64
	$(MAKE) package-deb GOARCH=amd64
	$(MAKE) package-apk GOARCH=amd64
	# arm64 (no cross toolchain needed = pure-Go)
	$(MAKE) build-admin GOARCH=arm64
	$(MAKE) package-rpm GOARCH=arm64
	$(MAKE) package-deb GOARCH=arm64
	$(MAKE) package-apk GOARCH=arm64
	# Fat plugin (one package bundling .so for multiple nginx versions).
	# postinstall picks the best match for host nginx, so one file ships everywhere.
	$(MAKE) package-plugin-nginx-fat UNMASK_VERSION=$(UNMASK_VERSION) GOARCH=amd64 || \
		echo "!!! fat plugin build failed (continuing)"
	# arm64 fat plugin: packaged from the PRE-BUILT .so cache
	# (dist/multi-modules-arm64/, produced once under qemu:
	#   docker run --platform=linux/arm64 ... make build-module-multi).
	# Building under qemu inside `make release` would add an hour+, so the
	# cache is a hard prereq here; the per-arch completeness gate below fails
	# the release if the arm64 plugin (or the cache) is missing.
	$(MAKE) package-plugin-nginx-fat UNMASK_VERSION=$(UNMASK_VERSION) GOARCH=arm64 || \
		echo "!!! arm64 fat plugin build failed (continuing; gate will catch a missing artifact)"
	# Web-server integration packages + the unmask-release repo bootstrap --
	# the rest of the advertised install set.  Without these, build-repo.sh
	# (which globs dist/*) would silently republish whatever stale
	# unmask-web-* / unmask-release files were left over from an earlier build.
	# Built per-arch (the contents are identical text, but rpm/deb/apk
	# resolvers only install arch-matching packages).
	$(MAKE) package-web-nginx UNMASK_VERSION=$(UNMASK_VERSION) GOARCH=amd64
	$(MAKE) package-web-apache UNMASK_VERSION=$(UNMASK_VERSION) GOARCH=amd64
	$(MAKE) package-web-nginx UNMASK_VERSION=$(UNMASK_VERSION) GOARCH=arm64
	$(MAKE) package-web-apache UNMASK_VERSION=$(UNMASK_VERSION) GOARCH=arm64
	$(MAKE) package-release UNMASK_VERSION=$(UNMASK_VERSION)
	# Completeness gate: refuse to call a partial set a release.  Every
	# package family the docs / repo advertise must exist in dist/ -- and the
	# main package must exist at THIS version in all three formats -- before
	# checksums are emitted.
	@echo ">>> asserting the full artifact set in $(DIST)/ (family x format x arch)"
	@cd $(DIST) && fail=0; \
	for fam in unmask-plugin-nginx unmask-web-nginx unmask-web-apache; do \
		for spec in x86_64.rpm aarch64.rpm amd64.deb arm64.deb x86_64.apk aarch64.apk; do \
			ls $$fam*$(UNMASK_VERSION)*$$spec >/dev/null 2>&1 || { echo "!! release set incomplete: no $$fam ($$spec) at $(UNMASK_VERSION) in dist/"; fail=1; }; \
		done; \
	done; \
	for ext in rpm deb apk; do \
		ls unmask-release*$(UNMASK_VERSION)*.$$ext >/dev/null 2>&1 || { echo "!! unmask-release .$$ext at $(UNMASK_VERSION) missing in dist/"; fail=1; }; \
	done; \
	for spec in x86_64.rpm aarch64.rpm amd64.deb arm64.deb x86_64.apk aarch64.apk; do \
		ls unmask?$(UNMASK_VERSION)*$$spec >/dev/null 2>&1 || { echo "!! main package ($$spec) at $(UNMASK_VERSION) missing in dist/"; fail=1; }; \
	done; \
	[ $$fail -eq 0 ] || { echo "!!! aborting: incomplete release set (see above)"; exit 1; }
	@echo ">>> generating checksums.txt"
	cd $(DIST) && sha256sum unmask-linux-* ngx_http_unmask_module-linux-* unmask*.rpm unmask*.deb unmask*.apk unmask-plugin-nginx*.deb unmask-plugin-nginx*.apk 2>/dev/null | awk '!seen[$$0]++' > checksums.txt || true
	# GPG-sign checksums.txt so a direct download (= GitHub release asset, not the
	# GPG-verified apt/dnf/apk repo) is verifiable: `gpg --verify checksums.txt.asc
	# checksums.txt`.  Gated on UNMASK_GPG_KEY_ID (= same key as sign-rpm); skipped
	# with a note when unset, so an unsigned dev build still completes.
	@if [ -n "$(UNMASK_GPG_KEY_ID)" ]; then \
		echo ">>> GPG-signing checksums.txt (detached, armored)"; \
		./tools/with-gpg-preset.sh gpg --batch --yes --armor --local-user "$(UNMASK_GPG_KEY_ID)" --detach-sign "$(DIST)/checksums.txt" \
			&& echo "    wrote $(DIST)/checksums.txt.asc"; \
	else \
		echo ">>> UNMASK_GPG_KEY_ID not set -- skipping checksums.txt signature"; \
		echo "    (set UNMASK_GPG_KEY_ID=<fingerprint> to emit checksums.txt.asc for direct-download verification)"; \
	fi
	@echo ">>> release artifacts in $(DIST)/:"
	@ls -la $(DIST)/

## release-github - create a DRAFT GitHub Release for v$(UNMASK_VERSION) and
##                  attach the dist/ rpm/deb/apk + checksums.txt.
##                  Release pipeline: `make release` (build) -> publish to the
##                  test /dl/ -> `make distro-check` (e2e + 8-distro install
##                  matrix) -> `make release-github`.  This target REFUSES to
##                  run unless distro-check passed for the current build.
##                  The release is left as a draft — review the assets, then
##                  publish it on GitHub.  Primary distribution stays the
##                  unmask.sh apt/dnf/apk repo; these assets are an immutable
##                  per-version archive / mirror.
.PHONY: release-github
release-github:
	@command -v gh >/dev/null 2>&1 || { echo "!!! gh CLI not found — see https://cli.github.com/"; exit 1; }
	@ls $(DIST)/unmask*.rpm $(DIST)/unmask*.deb $(DIST)/unmask*.apk >/dev/null 2>&1 || { \
		echo "!!! no packages in $(DIST)/ — run 'make release' first"; exit 1; }
	@test -f $(DIST)/.release-gate-ok || { \
		echo "!!! release gate not passed — run 'make distro-check' (e2e + 8-distro install matrix) first"; exit 1; }
	@if find $(DIST) \( -name 'unmask*.rpm' -o -name 'unmask*.deb' -o -name 'unmask*.apk' \) \
		-newer $(DIST)/.release-gate-ok -print -quit | grep -q .; then \
		echo "!!! packages were rebuilt after 'make distro-check' — re-run 'make distro-check'"; exit 1; fi
	@echo ">>> release gate OK (distro-check passed for this build)"
	@echo ">>> creating draft GitHub release v$(UNMASK_VERSION) with $(DIST)/ artifacts"
	gh release create v$(UNMASK_VERSION) \
		--repo unmask-sh/unmask \
		--draft \
		--title "unmask v$(UNMASK_VERSION)" \
		--notes 'rpm / deb / apk packages for this release. Recommended install is the unmask.sh apt/dnf/apk repository (https://unmask.sh/install/) — it configures GPG-verified automatic updates. The packages attached here are an immutable per-version archive; a directly-installed package does not configure the repository and will not auto-update. Verify downloads against checksums.txt (GPG: gpg --verify checksums.txt.asc checksums.txt).' \
		$(DIST)/unmask*.rpm $(DIST)/unmask*.deb $(DIST)/unmask*.apk $(DIST)/checksums.txt*
	@echo ">>> draft release created — review the assets, then publish at:"
	@echo "    https://github.com/unmask-sh/unmask/releases"

## test          - go test (admin app) + plugin parser unit test
test: test-plugin-parser
	cd admin && go test ./...

## test-plugin-parser - run the stand-alone C tests (ja4_parser_test.c + ja4_build_test.c)
.PHONY: test-plugin-parser
test-plugin-parser:
	mkdir -p $(DIST)
	gcc -std=gnu99 -Wall -Wextra \
		nginx-module/src/ja4_parser.c \
		nginx-module/src/ja4_parser_test.c \
		-o $(DIST)/ja4_parser_test
	$(DIST)/ja4_parser_test
	gcc -std=gnu99 -Wall -Wextra \
		nginx-module/src/ja4_build.c \
		nginx-module/src/ja4_build_test.c \
		-lcrypto -o $(DIST)/ja4_build_test
	$(DIST)/ja4_build_test

## fuzz-plugin  - ASan/UBSan fuzz of the ClientHello parser, JA4 builder + _bv cookie parser.
## Both handle fully untrusted input (raw TLS bytes / a client-set cookie).
## clang bundles the sanitizer runtime; override FUZZ_CC=gcc (+ dnf install libasan).
FUZZ_CC    ?= clang
FUZZ_FLAGS ?= -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1
FUZZ_ITERS ?= 1000000
.PHONY: fuzz-plugin
fuzz-plugin:
	mkdir -p $(DIST)
	$(FUZZ_CC) $(FUZZ_FLAGS) nginx-module/src/ja4_parser.c nginx-module/src/ja4_parser_fuzz.c -o $(DIST)/ja4_parser_fuzz
	$(DIST)/ja4_parser_fuzz $(FUZZ_ITERS)
	$(FUZZ_CC) $(FUZZ_FLAGS) nginx-module/src/bv_parser.c nginx-module/src/bv_parser_fuzz.c -o $(DIST)/bv_parser_fuzz
	$(DIST)/bv_parser_fuzz $(FUZZ_ITERS)
	$(FUZZ_CC) $(FUZZ_FLAGS) nginx-module/src/ja4_parser.c nginx-module/src/ja4_build.c nginx-module/src/ja4_build_fuzz.c -lcrypto -o $(DIST)/ja4_build_fuzz
	$(DIST)/ja4_build_fuzz $(FUZZ_ITERS)

## test-mariadb  - docker-gated MariaDB smoke (idempotent migrate + UTC + dialect aggregate)
.PHONY: test-mariadb
test-mariadb:
	@command -v docker >/dev/null 2>&1 || { echo "test-mariadb: docker absent, skipping"; exit 0; }
	@docker rm -f unmask-test-mariadb >/dev/null 2>&1 || true
	docker run -d --name unmask-test-mariadb -e MARIADB_ROOT_PASSWORD=rootpw -e MARIADB_DATABASE=unmask_test -e MARIADB_USER=unmask -e MARIADB_PASSWORD=unmask -p 3307:3306 mariadb:11 >/dev/null
	@echo "waiting for mariadb..."; for i in $$(seq 1 45); do docker exec unmask-test-mariadb mariadb -uunmask -punmask unmask_test -e "SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
	@cd admin && UNMASK_TEST_MARIADB_HOST=127.0.0.1 UNMASK_TEST_MARIADB_PORT=3307 UNMASK_TEST_MARIADB_USER=unmask UNMASK_TEST_MARIADB_PASSWORD=unmask UNMASK_TEST_MARIADB_DATABASE=unmask_test go test ./internal/db/ -run TestMariaDB -v -count=1; ret=$$?; docker rm -f unmask-test-mariadb >/dev/null 2>&1; exit $$ret

## e2e           - bare-metal e2e (run 4 scenarios via curl).  BASE_URL switches the target.
# Examples:
#   make e2e BASE_URL=https://localhost:8443
#   make e2e BASE_URL=https://demo.example.com:8443
e2e:
	./e2e/run.sh

## e2e-docker    - bring nginx + admin up via docker-compose and run run.sh (for CI / other hosts).
# Details in e2e/docker/README.md.  docker (or podman-compose) required.
e2e-docker:
	docker compose -f e2e/docker/docker-compose.yml up -d --build --wait
	@trap 'docker compose -f e2e/docker/docker-compose.yml down -v' EXIT; \
	    BASE_URL=https://localhost:8443 ./e2e/run.sh

e2e-docker-down:
	docker compose -f e2e/docker/docker-compose.yml down -v

## e2e-hv1       - run the docker e2e suite on the hv1 self-hosted runner (VM 9200)
# instead of locally.  Ships a CLEAN `git archive` of a committed tree (no
# shared-tree WIP, the false-failure source) over the o-hv1 VPN to a dedicated
# Debian 13 + docker-on-NVMe runner and runs there -- isolated + non-contending.
# Self-contained: no GitHub / SaaS CI.  Usage:
#   make e2e-hv1                 # HEAD, full suite
#   make e2e-hv1 COMMIT=a93efce  # a specific commit
#   make e2e-hv1 SCN="42 45"     # only the named scenarios
e2e-hv1:
	@tools/e2e-on-hv1.sh $(or $(COMMIT),HEAD) $(if $(strip $(SCN)),-- $(SCN))

## e2e-docker-socket - same as e2e-docker but admin listens on a UNIX SOCKET
# (0666 so the separate nginx container's worker can connect); nginx reaches it
# via the rendered `server unix:...;` upstream.  Skips the 9 scenarios that need
# admin TCP-direct (05/10/12/13/16) or the Apache forward-auth path (14/20/22/29).
e2e-docker-socket:
	docker compose -f e2e/docker/docker-compose.yml -f e2e/docker/docker-compose.socket.yml up -d --build --wait
	@trap 'docker compose -f e2e/docker/docker-compose.yml -f e2e/docker/docker-compose.socket.yml down -v' EXIT; \
	    UNMASK_E2E_SOCKET=1 BASE_URL=https://localhost:8443 ./e2e/run.sh

## e2e-docker-mariadb - same as e2e-docker but the admin daemon is backed by
# MariaDB instead of SQLite, so the full suite runs end-to-end against the
# MariaDB driver (migrations / UTC pin / dialect aggregates / the whole
# request->event->aggregate path).  All scenarios run; the backend is
# transparent to nginx / Apache / the challenge flow.
e2e-docker-mariadb:
	docker compose -f e2e/docker/docker-compose.yml -f e2e/docker/docker-compose.mariadb.yml up -d --build --wait
	@trap 'docker compose -f e2e/docker/docker-compose.yml -f e2e/docker/docker-compose.mariadb.yml down -v' EXIT; \
	    BASE_URL=https://localhost:8443 ./e2e/run.sh

## e2e-lifecycle - package-lifecycle scenarios on CentOS 6 in docker:
# install / upgrade (v0.1.0->v0.1.1) / removal / render-fail-safe -- the
# install-edge surfaces the fresh-install matrix masks (= 2026-06-08 GA audit
# core gap).  Builds both versions so the upgrade scenario has a FROM, then runs
# e2e/lifecycle/run.sh.  systemd-service lifecycle / SELinux enforcing / MariaDB
# / setup-wizard need a real VM or browser -> distro-check, not docker.
e2e-lifecycle:
	$(MAKE) package-rpm package-plugin-nginx-fat package-web-nginx UNMASK_VERSION=0.1.0
	$(MAKE) package-rpm package-plugin-nginx-fat package-web-nginx UNMASK_VERSION=0.1.1
	./e2e/lifecycle/run.sh

## distro-check  - release-gate: e2e (docker) + install matrix on a VM lab.
# Maintainer-only target.  e2e covers admin / plugin behavior in isolation;
# install-test-official.sh exercises the distribution path on real distros
# via a private sibling directory (../distro-verify/e2e/) which spins up KVM
# guests.  Both must pass before publishing.  Outside contributors run
# `make e2e-docker` instead; the install matrix run is reserved for the
# release maintainer.
.PHONY: distro-check
distro-check:
	@echo '=== gate 1/4: MariaDB backend smoke (docker) ==='
	$(MAKE) test-mariadb
	@echo '=== gate 2/4: e2e — SQLite backend (docker compose) ==='
	$(MAKE) e2e-docker
	@echo '=== gate 3/4: e2e — MariaDB backend (docker compose) ==='
	$(MAKE) e2e-docker-mariadb
	@echo '=== gate 4/4: install matrix (10 distros, verdict-gated) ==='
	cd ../distro-verify/e2e && ./install-test-official.sh
	@mkdir -p $(DIST) && touch $(DIST)/.release-gate-ok
	@echo '=== release gate PASSED — e2e (SQLite + MariaDB) + 10-distro install matrix green ==='
	@echo '    (recorded in $(DIST)/.release-gate-ok — consumed by release-github)'

## vet           - go vet
vet:
	cd admin && go vet ./...

## lint          - golangci-lint, exactly as CI runs it
#
# GOTOOLCHAIN pins the Go used for package loading to the version in
# .github/workflows/ci.yml.  golangci-lint embeds its own go/types, built
# against the Go it was released with, and cannot type-check standard-library
# sources from a NEWER Go -- on a box whose system Go is ahead of CI's it dies
# with "file requires newer Go version go1.NN (application built with go1.NN-1)"
# and a stack trace, which reads like a broken linter rather than a version
# mismatch.  Pinning here means `make lint` reproduces CI on any dev box.
#
# LINT_GO must track the go-version in ci.yml; LINT_VERSION the action's.
LINT_GO      ?= 1.25.10
LINT_VERSION ?= v2.12.2
lint:
	@# `go install` drops the binary in GOBIN/GOPATH/bin, which is commonly not
	@# on PATH; look there too rather than telling the user to install what they
	@# already have.
	@LINT=$$(command -v golangci-lint 2>/dev/null || echo "$$(go env GOPATH)/bin/golangci-lint"); \
	if [ ! -x "$$LINT" ]; then \
		echo 'golangci-lint not found. Install $(LINT_VERSION):'; \
		echo '  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(LINT_VERSION)'; \
		exit 1; \
	fi; \
	echo "=== golangci-lint (Go $(LINT_GO), as CI) ==="; \
	cd admin && GOTOOLCHAIN=go$(LINT_GO) "$$LINT" run --timeout=5m ./...

.PHONY: lint

## fmt           - gofmt -l (list of unformatted files)
fmt:
	cd admin && gofmt -l . | tee /dev/stderr | (! read x)

## clean         - remove dist/, build/
clean:
	rm -rf $(DIST) build

## release-clean  - clean for a release, but KEEP the arm64 qemu module caches
# The arm64 fat plugin is packaged straight from the pre-built .so cache
# (dist/multi-modules*-arm64/), which takes ~2h to regenerate under qemu, so a
# release must not wipe the very cache it then requires.  Everything else in
# dist/ is rebuilt, and a plain `make clean` still does a full wipe.
release-clean:
	rm -rf build
	@if [ -d $(DIST) ]; then \
		find $(DIST) -mindepth 1 -maxdepth 1 ! -name 'multi-modules*-arm64' -exec rm -rf {} +; \
	fi
