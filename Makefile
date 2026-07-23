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

GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)

RELEASE=sandboxd-$(PACKAGE_VERSION:v%=%)-${GOOS}-${GOARCH}

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

.PHONY: all clean test e2e e2e-v2 release release-binary release-cli protobuf-image protos protos-local check-protos tidy vendor fmt vet help
.DEFAULT_GOAL := all

all: release ## build binaries

release: release-binary release-cli
	@echo "Built $(RELEASE)."

release-binary:
	@echo "Building output/sandboxd"
ifeq ($(GOOS),linux)
	@$(GO) build -o output/sandboxd -tags "seccomp apparmor" ./cmd/sandboxd
else
	@echo "cross-platform build binary at $(GOOS)"
	@CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GO) build -o output/sandboxd -tags "seccomp apparmor" ./cmd/sandboxd
endif

release-cli:
	@echo "Building output/sbox"
ifeq ($(GOOS),linux)
	@$(GO) build -o output/sbox ./cmd/sbox
else
	@echo "cross-platform build client at $(GOOS)"
	@CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GO) build -o output/sbox ./cmd/sbox
endif

test: ## run tests
	@$(GO) clean -testcache
	@$(GOTEST) ${TESTFLAGS} ${PACKAGES}

e2e: ## run unit tests and the privileged runsc e2e flow
	@bash test/e2e/run.sh

e2e-v2: ## run the self-contained privileged cgroup v2 Docker E2E flow
	@bash test/e2e/run-v2.sh

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

tidy: ## ensure go.mod/go.sum are up-to-date
	@GOFLAGS= $(GO) mod tidy

vendor: ## sync vendor/ from go.mod (requires network)
	@GOFLAGS= $(GO) mod vendor

fmt: ## format Go code
	go fmt ./...

vet: ## run go vet
	go vet ./...

clean: ## clean up build artifacts
	@rm -rf output/
	@rm -rf bin/
	@$(GO) clean -testcache

help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "%-30s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort
