# Copyright (c) 2026 Ant Group Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Go command to use for build
GO ?= go
DOCKER ?= docker

# Extra flags passed to go commands. Leave empty by default because this
# repository does not vendor dependencies.
GOFLAGS ?=

# Root directory of the project (absolute path).
ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

PACKAGE_VERSION=$(shell sed -n '1p' version/VERSION)

RELEASE_GOOS=linux
RELEASE_GOARCH=amd64

RELEASE=sandboxd-$(PACKAGE_VERSION:v%=%)-$(RELEASE_GOOS)-$(RELEASE_GOARCH)

GO_BUILDTAGS ?=
GO_BUILDTAGS += urfave_cli_no_docs
GO_TAGS=$(if $(GO_BUILDTAGS),-tags "$(strip $(GO_BUILDTAGS))",)
PACKAGES=$(shell $(GO) list ${GO_TAGS} ./... | grep -v /integration)

# See Golang issue re: '-trimpath': https://github.com/golang/go/issues/13809
GOPATHS=$(shell go env GOPATH | tr ":" "\n" | tr ";" "\n")
GO_GCFLAGS=$(shell set -- ${GOPATHS}; echo "-gcflags=-trimpath=$${1}/src")

GOTEST ?= $(GO) test
TESTFLAGS ?= $(EXTRA_TESTFLAGS)

PROTOC_VERSION ?= 3.21.12
PROTOC_GEN_GO_VERSION ?= v1.36.11
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.2
GO_FIX_ACRONYM_VERSION ?= v0.3.0
PROTOBUF_BUILD_IMAGE ?= golang:1.25.5-bookworm
PROTOBUF_TOOL_IMAGE ?= sandboxd-protobuf:$(PROTOC_VERSION)-go-$(PROTOC_GEN_GO_VERSION)-grpc-$(PROTOC_GEN_GO_GRPC_VERSION)
PROTOBUF_BUILD_ARGS ?=
BPF2GO_VERSION ?= v0.9.1
BPF_CLANG_VERSION ?= 14.0.6
BPF_CLANG_PACKAGE_VERSION ?= 1:14.0.6-12
BPF_CLANG_FORMAT_PACKAGE_VERSION ?= $(BPF_CLANG_PACKAGE_VERSION)
BPF_LIBBPF_PACKAGE_VERSION ?= 1:1.1.2-0+deb12u1
BPF_LINUX_UAPI_PACKAGE_VERSION ?= 6.1.180-1
BPF_BUILD_IMAGE ?= golang:1.25.5-bookworm@sha256:d9132cce84391efab786495288756d60e1da215b1f94e87860aeefc3d4c45b6d
BPF_TOOL_IMAGE ?= sandboxd-bpf:clang-$(BPF_CLANG_VERSION)-bpf2go-$(BPF2GO_VERSION)
BPF_TEST_IMAGE ?= sandboxd-bpfnat-test:clang-$(BPF_CLANG_VERSION)-bpf2go-$(BPF2GO_VERSION)
BPF_BUILD_ARGS ?=
BPF_TEST_BUILD_ARGS ?=
BPF_SOURCE_DIRS := bpf/bpfnat bpf/networkacl
BPF_C_SOURCES := $(shell find $(BPF_SOURCE_DIRS) -type f \( -name '*.c' -o -name '*.h' \) | sort)

.PHONY: all clean test storage-test e2e release release-binary release-cli runc-shim sandbox-logger firecracker-agent protobuf-image protos protos-local check-protos bpf-image bpf bpf-local bpf-format bpf-format-local check-bpf-format check-bpf-format-local check-bpf-generated check-bpf bpfnat-test-image bpfnat-test bpfnat-test-local networkacl-test networkacl-test-local tidy vendor fmt check-fmt vet help
.DEFAULT_GOAL := all

all: release ## build binaries

release: release-binary release-cli runc-shim sandbox-logger firecracker-agent
	@echo "Built $(RELEASE)."

release-binary:
	@echo "Building output/sandboxd"
	@CGO_ENABLED=1 GOOS=$(RELEASE_GOOS) GOARCH=$(RELEASE_GOARCH) $(GO) build -o output/sandboxd -tags "seccomp apparmor" ./cmd/sandboxd

release-cli:
	@echo "Building output/sbox"
	@CGO_ENABLED=1 GOOS=$(RELEASE_GOOS) GOARCH=$(RELEASE_GOARCH) $(GO) build -o output/sbox ./cmd/sbox

runc-shim:
	@echo "Building output/runc-shim"
	@CGO_ENABLED=0 GOOS=$(RELEASE_GOOS) GOARCH=$(RELEASE_GOARCH) $(GO) build -o output/runc-shim ./cmd/runc-shim

sandbox-logger:
	@echo "Building output/sandbox-logger"
	@CGO_ENABLED=0 GOOS=$(RELEASE_GOOS) GOARCH=$(RELEASE_GOARCH) $(GO) build -o output/sandbox-logger ./cmd/sandbox-logger

firecracker-agent:
	@echo "Building output/firecracker-agent"
	@CGO_ENABLED=0 GOOS=$(RELEASE_GOOS) GOARCH=$(RELEASE_GOARCH) $(GO) build -o output/firecracker-agent ./cmd/firecracker-agent

test: ## run tests
	@$(GO) clean -testcache
	@$(GOTEST) ${TESTFLAGS} ${PACKAGES}

storage-test: ## run privileged loop-backed filesystem integration tests
	@set -eu; \
	tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$${tmpdir}"' EXIT; \
	$(GO) test ${GO_TAGS} -c -o "$${tmpdir}/volumemanager.test" ./pkg/volumemanager; \
	$(GO) test ${GO_TAGS} -c -o "$${tmpdir}/runtime.test" ./pkg/runtime; \
	sudo env SANDBOXD_RUN_STORAGE_INTEGRATION=1 \
		"$${tmpdir}/volumemanager.test" \
		-test.v -test.run '^TestLoopBackedFilestoreIntegration$$'; \
	sudo env SANDBOXD_RUN_STORAGE_INTEGRATION=1 \
		"$${tmpdir}/runtime.test" \
		-test.v -test.run '^TestEROFSLoopDeviceDirIntegration$$'

e2e: ## run unit tests and the selected privileged runtime e2e flows
	@bash test/e2e/run.sh

FORCE:

.PHONY: gen-protoc-v1
gen-protoc-v1:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/runtime/v1/*.proto

protobuf-image:
	$(DOCKER) build $(PROTOBUF_BUILD_ARGS) \
		--build-arg GO_BUILD_IMAGE=$(PROTOBUF_BUILD_IMAGE) \
		--build-arg PROTOC_VERSION=$(PROTOC_VERSION) \
		--build-arg PROTOC_GEN_GO_VERSION=$(PROTOC_GEN_GO_VERSION) \
		--build-arg PROTOC_GEN_GO_GRPC_VERSION=$(PROTOC_GEN_GO_GRPC_VERSION) \
		--build-arg GO_FIX_ACRONYM_VERSION=$(GO_FIX_ACRONYM_VERSION) \
		-f tools/protobuf.Dockerfile \
		-t $(PROTOBUF_TOOL_IMAGE) .

protos: protobuf-image ## regenerate protobuf code with the pinned toolchain
	$(DOCKER) run --rm \
		--user "$(shell id -u):$(shell id -g)" \
		-v "$(ROOTDIR):/workspace" \
		$(PROTOBUF_TOOL_IMAGE)

protos-local: gen-protoc-v1
	go-fix-acronym -w -a '(Id|Io|Uuid|Os)$$' $(shell find api -name '*.pb.go')

check-protos: protos ## verify generated protobuf code is up to date
	@git diff --exit-code -- api
	@test -z "$$(git ls-files --others --exclude-standard -- api | tee /dev/stderr)"

bpf-image:
	$(DOCKER) build $(BPF_BUILD_ARGS) \
		--build-arg GO_BUILD_IMAGE=$(BPF_BUILD_IMAGE) \
		--build-arg BPF2GO_VERSION=$(BPF2GO_VERSION) \
		--build-arg BPF_CLANG_VERSION=$(BPF_CLANG_VERSION) \
		--build-arg BPF_CLANG_PACKAGE_VERSION=$(BPF_CLANG_PACKAGE_VERSION) \
		--build-arg BPF_CLANG_FORMAT_PACKAGE_VERSION=$(BPF_CLANG_FORMAT_PACKAGE_VERSION) \
		--build-arg BPF_LIBBPF_PACKAGE_VERSION=$(BPF_LIBBPF_PACKAGE_VERSION) \
		--build-arg BPF_LINUX_UAPI_PACKAGE_VERSION=$(BPF_LINUX_UAPI_PACKAGE_VERSION) \
		-f tools/bpf.Dockerfile \
		-t $(BPF_TOOL_IMAGE) .

bpf: bpf-image ## regenerate embedded BPF objects with the pinned toolchain
	$(DOCKER) run --rm \
		--user "$(shell id -u):$(shell id -g)" \
		-v "$(ROOTDIR):/workspace" \
		$(BPF_TOOL_IMAGE)

bpf-local: ## regenerate BPF objects with matching local bpf2go and Clang 14 tools
	go generate ./pkg/networkmanager/bpfnat ./pkg/networkmanager/networkacl

bpf-format: bpf-image ## format BPF C sources with the pinned toolchain
	$(DOCKER) run --rm \
		--user "$(shell id -u):$(shell id -g)" \
		-v "$(ROOTDIR):/workspace" \
		$(BPF_TOOL_IMAGE) bpf-format-local

bpf-format-local:
	clang-format-14 -i $(BPF_C_SOURCES)

check-bpf-format: bpf-image ## verify BPF C sources use the pinned format
	$(DOCKER) run --rm \
		--user "$(shell id -u):$(shell id -g)" \
		-v "$(ROOTDIR):/workspace" \
		$(BPF_TOOL_IMAGE) check-bpf-format-local

check-bpf-format-local:
	clang-format-14 --dry-run --Werror $(BPF_C_SOURCES)

check-bpf-generated: bpf ## verify generated BPF bindings and objects are up to date
	@git diff --exit-code -- pkg/networkmanager/bpfnat pkg/networkmanager/networkacl
	@test -z "$$(git ls-files --others --exclude-standard -- pkg/networkmanager/bpfnat pkg/networkmanager/networkacl | tee /dev/stderr)"

check-bpf: check-bpf-format check-bpf-generated ## verify BPF C formatting and generated artifacts

bpfnat-test-image: bpf-image
	$(DOCKER) build $(BPF_TEST_BUILD_ARGS) \
		--build-arg BPF_TOOL_IMAGE=$(BPF_TOOL_IMAGE) \
		-f tools/bpfnat-test.Dockerfile \
		-t $(BPF_TEST_IMAGE) .

bpfnat-test: bpfnat-test-image ## run privileged bpfnat dataplane and lifecycle tests
	$(DOCKER) run --rm \
		--privileged \
		--network none \
		--tmpfs /sys/fs/bpf:rw,nosuid,nodev,noexec,mode=700 \
		--sysctl net.ipv4.ip_forward=1 \
		--sysctl net.ipv4.conf.all.rp_filter=0 \
		-v "$(ROOTDIR):/workspace:ro" \
		$(BPF_TEST_IMAGE)

bpfnat-test-local:
	$(GO) test -count=1 -v -tags bpfnat_integration ./pkg/networkmanager/bpfnat

networkacl-test: bpfnat-test-image ## run privileged network ACL dataplane tests
	$(DOCKER) run --rm \
		--privileged \
		--network none \
		--tmpfs /sys/fs/bpf:rw,nosuid,nodev,noexec,mode=700 \
		--sysctl net.ipv4.ip_forward=1 \
		--sysctl net.ipv4.conf.all.rp_filter=0 \
		--sysctl net.ipv4.conf.default.rp_filter=0 \
		-v "$(ROOTDIR):/workspace:ro" \
		$(BPF_TEST_IMAGE) networkacl-test-local

networkacl-test-local:
	$(GO) test -count=1 -v -tags networkacl_integration ./pkg/networkmanager/networkacl

tidy: ## ensure go.mod/go.sum are up-to-date
	@GOFLAGS= $(GO) mod tidy

vendor: ## sync vendor/ from go.mod (requires network)
	@GOFLAGS= $(GO) mod vendor

fmt: ## format Go code
	go fmt ./...

check-fmt: ## verify Go code is gofmt-clean
	@files="$$(gofmt -l .)" || exit $$?; \
	test -z "$$files" || { printf '%s\n' "$$files" >&2; exit 1; }

vet: ## run go vet
	go vet ./...

clean: ## clean up build artifacts
	@rm -rf output/
	@rm -rf bin/
	@$(GO) clean -testcache

help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "%-30s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort
