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

package firecracker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDecodeKvmMSRIndices(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want []uint32
	}{
		{
			name: "empty list",
			buf:  []byte{0, 0, 0, 0},
			want: []uint32{},
		},
		{
			name: "single MSR (PVM vcpu struct)",
			buf: func() []byte {
				buf := make([]byte, 8)
				binary.LittleEndian.PutUint32(buf[0:], 1)
				binary.LittleEndian.PutUint32(buf[4:], msrPVMVCPUStruct)
				return buf
			}(),
			want: []uint32{msrPVMVCPUStruct},
		},
		{
			name: "multiple MSRs including PVM",
			buf: func() []byte {
				buf := make([]byte, 4+3*4)
				binary.LittleEndian.PutUint32(buf[0:], 3)
				binary.LittleEndian.PutUint32(buf[4:], 0x10)
				binary.LittleEndian.PutUint32(buf[8:], msrPVMVCPUStruct)
				binary.LittleEndian.PutUint32(buf[12:], 0x11)
				return buf
			}(),
			want: []uint32{0x10, msrPVMVCPUStruct, 0x11},
		},
		{
			name: "truncated buffer",
			buf:  []byte{2, 0, 0, 0, 0x10, 0, 0, 0},
			want: []uint32{0x10},
		},
		{
			name: "header too short",
			buf:  []byte{1, 2},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeKvmMSRIndices(tc.buf)
			if len(got) != len(tc.want) {
				t.Fatalf("decode = %v (len %d), want %v (len %d)",
					got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("decode[%d] = %#x, want %#x", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestProbeKvmBackendOnLiveDevice runs the actual ABI probe against the
// host's /dev/kvm. It is optional in the unprivileged unit suite: the device
// must exist and be accessible to the user before the ABI itself is tested.
func TestProbeKvmBackendOnLiveDevice(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("MSR backend identification uses the x86-64 KVM ABI")
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			t.Skipf("live KVM probe unavailable to this user: %v", err)
		}
		t.Fatalf("check /dev/kvm access: %v", err)
	}
	if err := kvm.Close(); err != nil {
		t.Fatalf("close KVM access check: %v", err)
	}
	backend, err := probeKvmBackend("/dev/kvm")
	if err != nil {
		t.Fatalf("probeKvmBackend: %v", err)
	}
	if backend != KvmBackendPVM && backend != KvmBackendHardware {
		t.Fatalf("probeKvmBackend returned unknown identity %q", backend)
	}
	t.Logf("live backend probe: %s", backend)
}

// TestVerifyCheckpointCompatFull exercises the complete verifyCheckpointCompat
// path — including the backend and TSC gates that now run even for artifacts
// without a manifest or compat tuple — using realistic sealed v2 directories.
// It does not test digest mismatches (covered by the pre-existing
// TestVerifyCheckpointCompat in compat_test.go).
func TestVerifyCheckpointCompatFull(t *testing.T) {
	// stackFixtureFiles creates the stack files a handler digests. The
	// handler's buildCheckpointCompat runs during verification, so the
	// binary/kernel/initrd must exist.
	stackFixtureFiles := func(t *testing.T) *Handler {
		t.Helper()
		dir := t.TempDir()
		for path, content := range map[string]string{
			filepath.Join(dir, "firecracker"): "vmm-binary",
			filepath.Join(dir, "vmlinux"):     "guest-kernel",
			filepath.Join(dir, "initrd.img"):  "guest-initrd",
		} {
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
		}
		return &Handler{
			binary:     filepath.Join(dir, "firecracker"),
			kernelPath: filepath.Join(dir, "vmlinux"),
			initrdPath: filepath.Join(dir, "initrd.img"),
			kernelArgs: "console=ttyS0",
		}
	}

	// sealV2 creates a sealed v2 checkpoint directory with the given compat.
	sealV2 := func(t *testing.T, compat *firecrackerCheckpointCompat) *firecrackerCheckpointArtifact {
		t.Helper()
		dir := t.TempDir()
		files, err := prepareFirecrackerCheckpointV2(dir, "", 1<<20)
		if err != nil {
			t.Fatalf("prepare v2 checkpoint: %v", err)
		}
		writeArtifactComponent(t, files.State, 8<<10)
		writeArtifactComponent(t, files.Memory, 1<<20)
		writeArtifactComponent(t, files.Overlay, 32<<10)
		manifest := &firecrackerCheckpointManifest{
			SnapshotType: firecrackerSnapshotTypeFull,
			MemorySize:   1 << 20,
			Compat:       compat,
		}
		if err := finalizeFirecrackerCheckpointV2ForTest(files, manifest); err != nil {
			t.Fatalf("finalize v2 checkpoint: %v", err)
		}
		artifact, err := openFirecrackerCheckpoint(dir)
		if err != nil {
			t.Fatalf("open sealed checkpoint: %v", err)
		}
		return artifact
	}

	// legacyArtifact returns an artifact with no manifest (v1 layout).
	legacyArtifact := func(t *testing.T) *firecrackerCheckpointArtifact {
		return &firecrackerCheckpointArtifact{
			Layout: firecrackerCheckpointLayoutV1Archive,
			Files:  firecrackerCheckpointFiles{State: filepath.Join(t.TempDir(), "checkpoint.img")},
		}
	}

	cases := []struct {
		name     string
		handler  func(t *testing.T) *Handler
		artifact func(t *testing.T) *firecrackerCheckpointArtifact
		wantErr  string // "" for allow
	}{
		{
			name: "nil manifest on kvm handler allows (legacy compat)",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendHardware
				h.tscFrequencyKHz = 2500000
				h.tscScalingSupported = true
				return h
			},
			artifact: legacyArtifact,
			wantErr:  "",
		},
		{
			name: "nil manifest on pvm handler rejects (unknown provenance)",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendPVM
				h.tscFrequencyKHz = 2500000
				return h
			},
			artifact: legacyArtifact,
			wantErr:  "no recorded backend (legacy artifact)",
		},
		{
			name: "nil compat on kvm handler allows",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendHardware
				h.tscFrequencyKHz = 2500000
				h.tscScalingSupported = true
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, nil)
			},
			wantErr: "",
		},
		{
			name: "nil compat on pvm handler rejects",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendPVM
				h.tscFrequencyKHz = 2500000
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, nil)
			},
			wantErr: "no recorded backend (legacy artifact)",
		},
		{
			name: "matching pvm full tuple allows",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendPVM
				h.tscFrequencyKHz = 2500000
				h.tscScalingSupported = false
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, &firecrackerCheckpointCompat{
					Backend: KvmBackendPVM, TSCFrequencyKHz: 2500000,
				})
			},
			wantErr: "",
		},
		{
			name: "matching kvm full tuple allows",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendHardware
				h.tscFrequencyKHz = 2500000
				h.tscScalingSupported = true
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, &firecrackerCheckpointCompat{
					Backend: KvmBackendHardware, TSCFrequencyKHz: 2500000,
				})
			},
			wantErr: "",
		},
		{
			name: "pvm artifact on kvm handler rejects",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendHardware
				h.tscFrequencyKHz = 2500000
				h.tscScalingSupported = true
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, &firecrackerCheckpointCompat{
					Backend: KvmBackendPVM, TSCFrequencyKHz: 2500000,
				})
			},
			wantErr: `produced on backend "pvm" but this node runs backend "kvm"`,
		},
		{
			name: "kvm artifact on pvm handler rejects",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendPVM
				h.tscFrequencyKHz = 2500000
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, &firecrackerCheckpointCompat{
					Backend: KvmBackendHardware, TSCFrequencyKHz: 2500000,
				})
			},
			wantErr: `produced on backend "kvm" but this node runs backend "pvm"`,
		},
		{
			name: "pvm artifact without tsc on pvm handler rejects",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendPVM
				h.tscFrequencyKHz = 2500000
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, &firecrackerCheckpointCompat{
					Backend: KvmBackendPVM, TSCFrequencyKHz: 0,
				})
			},
			wantErr: "no recorded TSC frequency",
		},
		{
			name: "pvm artifact with different tsc on pvm handler rejects",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendPVM
				h.tscFrequencyKHz = 2500000
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, &firecrackerCheckpointCompat{
					Backend: KvmBackendPVM, TSCFrequencyKHz: 2400000,
				})
			},
			wantErr: "TSC",
		},
		{
			name: "kvm artifact without tsc on kvm handler allows (legacy)",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendHardware
				h.tscFrequencyKHz = 2500000
				h.tscScalingSupported = true
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, &firecrackerCheckpointCompat{
					Backend: KvmBackendHardware, TSCFrequencyKHz: 0,
				})
			},
			wantErr: "",
		},
		{
			name: "pvm handler without local tsc rejects all",
			handler: func(t *testing.T) *Handler {
				h := stackFixtureFiles(t)
				h.kvmBackend = KvmBackendPVM
				h.tscFrequencyKHz = 0 // simulate probe failure in tests
				return h
			},
			artifact: func(t *testing.T) *firecrackerCheckpointArtifact {
				return sealV2(t, &firecrackerCheckpointCompat{
					Backend: KvmBackendPVM, TSCFrequencyKHz: 2500000,
				})
			},
			wantErr: "local TSC frequency is unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := tc.handler(t)
			artifact := tc.artifact(t)
			err := handler.verifyCheckpointCompat(artifact)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected allow, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got allow", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestCheckpointManifestBackendRoundTrip verifies the Backend and
// TSCFrequencyKHz fields survive a manifest write/read cycle.
func TestCheckpointManifestBackendRoundTrip(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, firecrackerCheckpointManifestName)
	manifest := &firecrackerCheckpointManifest{
		Version:      firecrackerCheckpointVersion2,
		SnapshotType: firecrackerSnapshotTypeFull,
		MemorySize:   256 << 20,
		Compat: &firecrackerCheckpointCompat{
			Arch:            "amd64",
			Backend:         "pvm",
			TSCFrequencyKHz: 2500000,
		},
		Digests: map[string]string{},
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, encoded, 0600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	read, err := readFirecrackerCheckpointManifest(dir)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if read.Compat == nil {
		t.Fatal("read manifest has no compat tuple")
	}
	if read.Compat.Backend != "pvm" {
		t.Fatalf("backend round-trip = %q, want %q", read.Compat.Backend, "pvm")
	}
	if read.Compat.TSCFrequencyKHz != 2500000 {
		t.Fatalf("tsc round-trip = %d, want %d", read.Compat.TSCFrequencyKHz, 2500000)
	}
}

// finalizeFirecrackerCheckpointV2ForTest seals a v2 checkpoint with digests
// computed from the written components.
func finalizeFirecrackerCheckpointV2ForTest(
	files firecrackerCheckpointFiles,
	manifest *firecrackerCheckpointManifest,
) error {
	manifest.Version = firecrackerCheckpointVersion2
	return finalizeFirecrackerCheckpointV2(context.Background(), files, manifest)
}
