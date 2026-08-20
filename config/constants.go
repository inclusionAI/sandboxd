// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// Runtime names supported by sandboxd.
const (
	RuntimeNameRunsc = "runsc"
	RuntimeNameKata  = "kata"
	RuntimeNameRunc  = "runc"

	GVisorCheckpointDirName          = "gvisor-checkpoints"
	GVisorCheckpointPathAnnotation   = "dev.gvisor.internal.checkpoint.path"
	GVisorCheckpointEnableAnnotation = "dev.gvisor.internal.checkpoint.enable"
)

// Sandbox service related constants.
const (
	UnknownVersion = "unknown"

	SandboxServiceName = "sandbox"
)

const (
	SandboxPrefix     = "sbox"
	SandboxIDPrefix   = SandboxPrefix + "-"
	SandboxSpecFile   = "config.json"
	SandboxMetaFile   = "meta.pb"
	SandboxStatusFile = "status"
)

// IsValidSandboxID reports whether id follows the namespace used by generated
// sandbox IDs and by the sbox lifecycle commands.
func IsValidSandboxID(id string) bool {
	if !strings.HasPrefix(id, SandboxIDPrefix) || len(id) <= len(SandboxIDPrefix) {
		return false
	}
	if filepath.Base(id) != id || filepath.Clean(id) != id || strings.ContainsRune(id, '\\') {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Resource pool identifiers and OCI annotation key prefix.
// Cgroup and network resource managers use these as map keys when reporting
// the allocations they own back through sandbox.OccupiedResource and as the
// suffix of OCI annotations persisted in the sandbox's config.json.
const (
	ResourceNameCgroup    = "cgroup"
	ResourceNameInterface = "interface"

	ResourceAnnotationKeyPrefix = "sandbox.akernel.dev/resource-"
	CgroupPathPrefix            = "/sandbox/"
)

// RuntimeResources maps runtime handler name → resource pool names that
// sandbox.Manager.Occupy must allocate before handing the request to that
// runtime. Server.go consults this when translating a Start RPC into per-pool
// allocations.
var RuntimeResources = map[string][]string{
	RuntimeNameRunsc: {ResourceNameCgroup, ResourceNameInterface},
	RuntimeNameKata:  {ResourceNameCgroup, ResourceNameInterface},
	RuntimeNameRunc:  {ResourceNameCgroup, ResourceNameInterface},
}

const (
	RecycleBin = "_recycle"
)

const (
	// HouseKeepingMaxCostTime is the max cost time of housekeeping.
	// If the cost time is larger than this value,
	// a warning log will be printed and the server will set self to unhealthy.
	HouseKeepingMaxCostTime = time.Second * 5

	// LifeCycleAliveValidInterval is the valid interval of alive check before terrible.
	LifeCycleAliveValidInterval = time.Second * 5
)

// Bucket key store bucket
const (
	// CgroupBucket Bucket key store bucket
	CgroupBucket = "cgroup"
	// BridgeIpBucket Bucket key store bucket
	BridgeIpBucket = "bridgeIp"
	// SandboxFSStateBucket stores sandbox-to-filesystem source mappings for
	// rebuilding mount references after an in-pod sandboxd restart.
	SandboxFSStateBucket = "sandboxFSState"
)

// Network related constants.
const (
	HostVethPrefix = "hv."
	PeerVethPrefix = "pv."

	NatBackendIptables = "iptables"
	NatBackendBpfnat   = "bpfnat"
)

const (
	SandboxEnvLabelKey     = "sandbox.akernel.dev/env-id"
	SandboxEnvKey          = "RUNTIME_ENV_ID"
	SandboxFunctionNameKey = "RUNTIME_FUNCTION_NAME"

	// Label key strings retain the legacy "io.sandbox.container.overlayfs.*" form
	// for on-the-wire compatibility with existing OCI spec annotations.
	SandboxOverlayfsLowerDirLabel  = "io.sandbox.container.overlayfs.lowerDir"
	SandboxOverlayfsTargetDirLabel = "io.sandbox.container.overlayfs.targetDir"

	OverlayUpperDirName = "overlay-upper"
	OverlayWorkDirName  = "overlay-work"

	// LabelRuntimeID is the OCI annotation key carrying the function runtime
	// id associated with a sandbox.
	LabelRuntimeID = "runtime-id"
)
