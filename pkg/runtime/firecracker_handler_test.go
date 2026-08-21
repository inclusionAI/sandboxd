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

package runtime

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

func TestFirecrackerMachineSize(t *testing.T) {
	handler := &FirecrackerHandler{defaultVCPUs: 1, defaultMem: 512}
	tests := []struct {
		name      string
		resources *runtimeapi.LinuxSandboxResources
		wantCPU   uint32
		wantMem   uint32
		wantError bool
	}{
		{name: "defaults", wantCPU: 1, wantMem: 512},
		{
			name: "quota and rounded memory",
			resources: &runtimeapi.LinuxSandboxResources{
				CpuQuota:           150000,
				CpuPeriod:          100000,
				MemoryLimitInBytes: 129*1024*1024 + 1,
			},
			wantCPU: 2,
			wantMem: 130,
		},
		{
			name: "shares",
			resources: &runtimeapi.LinuxSandboxResources{
				CpuShares:          1536,
				MemoryLimitInBytes: 256 * 1024 * 1024,
			},
			wantCPU: 2,
			wantMem: 256,
		},
		{
			name: "too little memory",
			resources: &runtimeapi.LinuxSandboxResources{
				MemoryLimitInBytes: 127 * 1024 * 1024,
			},
			wantError: true,
		},
		{
			name: "too many CPUs",
			resources: &runtimeapi.LinuxSandboxResources{
				CpuQuota:  math.MaxInt64,
				CpuPeriod: 1,
			},
			wantError: true,
		},
		{
			name: "too much memory",
			resources: &runtimeapi.LinuxSandboxResources{
				MemoryLimitInBytes: math.MaxInt64,
			},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cpu, memory, err := handler.machineSize(test.resources)
			if test.wantError {
				if err == nil {
					t.Fatalf("machineSize = %d, %d, want error", cpu, memory)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cpu != test.wantCPU || memory != test.wantMem {
				t.Fatalf(
					"machineSize = %d, %d, want %d, %d",
					cpu, memory, test.wantCPU, test.wantMem,
				)
			}
		})
	}
}

func TestFirecrackerValidateStartRequestRejectsOCIImages(t *testing.T) {
	handler := &FirecrackerHandler{}
	tests := []struct {
		name    string
		request *runtimeapi.StartRequest
		message string
	}{
		{
			name: "rootfs",
			request: &runtimeapi.StartRequest{Rootfs: &runtimeapi.RootfsConfig{
				Type: runtimeapi.RootfsSrcType_IMAGE,
				Source: &runtimeapi.RootfsConfig_ImageUrl{
					ImageUrl: "example.invalid/rootfs:latest",
				},
			}},
			message: "does not support OCI image rootfs",
		},
		{
			name: "mount",
			request: &runtimeapi.StartRequest{
				Rootfs: &runtimeapi.RootfsConfig{
					Type: runtimeapi.RootfsSrcType_LOCAL,
					Source: &runtimeapi.RootfsConfig_Path{
						Path: "/rootfs.erofs",
					},
				},
				Mounts: []*runtimeapi.Mount{{
					Target: "/mnt/image",
					Source: &runtimeapi.Mount_ImageUrl{
						ImageUrl: "example.invalid/data:latest",
					},
				}},
			},
			message: "does not support OCI image mount at /mnt/image",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := handler.ValidateStartRequest(test.request)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("ValidateStartRequest() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestFirecrackerRuntimeDirectoryIsStableAndBounded(t *testing.T) {
	handler := &FirecrackerHandler{runtimeRoot: "/run/sandboxd/firecracker"}
	sandboxID := "sbox-" + strings.Repeat("a", 120)
	first := handler.runtimeDirectory(sandboxID)
	second := handler.runtimeDirectory(sandboxID)
	if first != second {
		t.Fatalf("runtime directory changed: %q != %q", first, second)
	}
	if filepath.Dir(first) != handler.runtimeRoot {
		t.Fatalf("runtime directory %q is outside %q", first, handler.runtimeRoot)
	}
	for _, socket := range []string{
		filepath.Join(first, firecrackerAPISocket),
		filepath.Join(first, firecrackerVsock),
	} {
		if len(socket) >= 100 {
			t.Fatalf("socket path is too long: %d bytes: %s", len(socket), socket)
		}
	}
	if first == handler.runtimeDirectory(sandboxID+"different") {
		t.Fatal("different sandbox IDs share a runtime directory")
	}
}

func TestValidateFirecrackerPersistedState(t *testing.T) {
	root := t.TempDir()
	handler := &FirecrackerHandler{
		sandboxRoot: filepath.Join(root, "containers"),
		storageRoot: filepath.Join(root, "filestore"),
		runtimeRoot: filepath.Join(root, "runtime"),
	}
	sandboxID := "sbox-state"
	bundlePath := filepath.Join(handler.sandboxRoot, sandboxID)
	storagePath := filepath.Join(handler.storageRoot, sandboxID)
	runtimePath := handler.runtimeDirectory(sandboxID)
	for _, path := range []string{bundlePath, storagePath, runtimePath} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	valid := firecrackerPersistedState{
		ID:          sandboxID,
		BundlePath:  bundlePath,
		APIPath:     filepath.Join(runtimePath, firecrackerAPISocket),
		VsockPath:   filepath.Join(runtimePath, firecrackerVsock),
		OverlayPath: filepath.Join(storagePath, "overlay.ext4"),
	}
	if err := handler.validatePersistedState(sandboxID, bundlePath, valid); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*firecrackerPersistedState)
	}{
		{
			name: "ID",
			mutate: func(state *firecrackerPersistedState) {
				state.ID = "sbox-other"
			},
		},
		{
			name: "bundle",
			mutate: func(state *firecrackerPersistedState) {
				state.BundlePath = t.TempDir()
			},
		},
		{
			name: "API socket",
			mutate: func(state *firecrackerPersistedState) {
				state.APIPath = filepath.Join(t.TempDir(), firecrackerAPISocket)
			},
		},
		{
			name: "vsock",
			mutate: func(state *firecrackerPersistedState) {
				state.VsockPath = filepath.Join(t.TempDir(), firecrackerVsock)
			},
		},
		{
			name: "overlay",
			mutate: func(state *firecrackerPersistedState) {
				state.OverlayPath = filepath.Join(t.TempDir(), "overlay.ext4")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := valid
			test.mutate(&state)
			if err := handler.validatePersistedState(sandboxID, bundlePath, state); err == nil {
				t.Fatalf("accepted inconsistent %s state: %+v", test.name, state)
			}
		})
	}
}
