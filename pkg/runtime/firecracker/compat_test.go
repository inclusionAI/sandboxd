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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stackFixture lays out the three stack files a handler digests and returns
// the handler wired to them.
func stackFixture(t *testing.T) *Handler {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "firecracker")
	kernel := filepath.Join(dir, "vmlinux")
	initrd := filepath.Join(dir, "initrd.img")
	virtiofsd := filepath.Join(dir, "virtiofsd")
	for path, content := range map[string]string{
		binary:    "vmm-binary",
		kernel:    "guest-kernel",
		initrd:    "guest-initrd",
		virtiofsd: "virtiofsd-binary",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write stack file %s: %v", path, err)
		}
	}
	return &Handler{
		binary:        binary,
		kernelPath:    kernel,
		initrdPath:    initrd,
		virtiofsdPath: virtiofsd,
		kernelArgs:    "console=ttyS0",
	}
}

func TestBuildCheckpointCompatDigestsAndCaches(t *testing.T) {
	handler := stackFixture(t)

	first, err := handler.buildCheckpointCompat(2, false)
	if err != nil {
		t.Fatalf("build compat: %v", err)
	}
	if first.Arch == "" || len(first.Firecracker) != 64 || len(first.Kernel) != 64 ||
		len(first.Initrd) != 64 || first.Vcpus != 2 || first.KernelArgs != "console=ttyS0" {
		t.Fatalf("compat tuple incomplete: %+v", first)
	}
	// The digests are cached: mutating a stack file after the first build
	// must not change the tuple.
	if err := os.WriteFile(handler.kernelPath, []byte("mutated"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := handler.buildCheckpointCompat(4, true)
	if err != nil {
		t.Fatalf("rebuild compat: %v", err)
	}
	if second.Kernel != first.Kernel {
		t.Fatal("compat digests were recomputed instead of cached")
	}
	if second.Vcpus != 4 {
		t.Fatalf("vcpu count %d not carried per checkpoint", second.Vcpus)
	}
	if len(second.VirtioFSD) != 64 {
		t.Fatalf("virtiofsd digest missing: %+v", second)
	}
	third, err := handler.buildCheckpointCompat(1, false)
	if err != nil {
		t.Fatalf("rebuild non-virtio-fs compat: %v", err)
	}
	if third.VirtioFSD != "" {
		t.Fatalf("virtiofsd digest leaked into non-virtio-fs tuple: %+v", third)
	}
}

func TestVerifyCheckpointCompat(t *testing.T) {
	handler := stackFixture(t)
	seal := func(t *testing.T, compat *firecrackerCheckpointCompat) *firecrackerCheckpointArtifact {
		t.Helper()
		dir := t.TempDir()
		files, err := prepareFirecrackerCheckpointV2(dir, "", 1<<20)
		if err != nil {
			t.Fatalf("prepare v2 checkpoint: %v", err)
		}
		writeArtifactComponent(t, files.State, 8<<10)
		writeArtifactComponent(t, files.Memory, 1<<20)
		writeArtifactComponent(t, files.Overlay, 32<<10)
		if err := finalizeFirecrackerCheckpointV2(context.Background(), files, &firecrackerCheckpointManifest{
			SnapshotType: firecrackerSnapshotTypeSoftDirty,
			MemorySize:   1 << 20,
			Compat:       compat,
		}); err != nil {
			t.Fatalf("finalize v2 checkpoint: %v", err)
		}
		artifact, err := openFirecrackerCheckpoint(dir)
		if err != nil {
			t.Fatalf("open sealed checkpoint: %v", err)
		}
		return artifact
	}

	// No tuple at all (a pre-M3 artifact) restores without verification.
	if err := handler.verifyCheckpointCompat(seal(t, nil)); err != nil {
		t.Fatalf("tuple-less artifact rejected: %v", err)
	}

	matching, err := handler.buildCheckpointCompat(1, false)
	if err != nil {
		t.Fatalf("build compat: %v", err)
	}
	if err := handler.verifyCheckpointCompat(seal(t, matching)); err != nil {
		t.Fatalf("matching stack rejected: %v", err)
	}

	// A foreign kernel digest must be rejected by name.
	foreign := *matching
	foreign.Kernel = strings.Repeat("0", 64)
	err = handler.verifyCheckpointCompat(seal(t, &foreign))
	if err == nil || !strings.Contains(err.Error(), "kernel") {
		t.Fatalf("foreign kernel accepted: %v", err)
	}

	// Unrecorded fields are skipped: an artifact that pinned only the
	// binary still restores after a kernel swap.
	onlyBinary := &firecrackerCheckpointCompat{Firecracker: matching.Firecracker}
	if err := handler.verifyCheckpointCompat(seal(t, onlyBinary)); err != nil {
		t.Fatalf("partial tuple rejected: %v", err)
	}
}

func TestManifestRejectsMalformedCompatDigest(t *testing.T) {
	dir := t.TempDir()
	files, err := prepareFirecrackerCheckpointV2(dir, "", 1<<20)
	if err != nil {
		t.Fatalf("prepare v2 checkpoint: %v", err)
	}
	writeArtifactComponent(t, files.State, 8<<10)
	writeArtifactComponent(t, files.Memory, 1<<20)
	writeArtifactComponent(t, files.Overlay, 32<<10)
	if err := finalizeFirecrackerCheckpointV2(context.Background(), files, &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeSoftDirty,
		MemorySize:   1 << 20,
		Compat:       &firecrackerCheckpointCompat{Kernel: "not-a-digest"},
	}); err != nil {
		t.Fatalf("finalize v2 checkpoint: %v", err)
	}
	if _, err := openFirecrackerCheckpoint(dir); err == nil ||
		!strings.Contains(err.Error(), "compat kernel digest") {
		t.Fatalf("malformed compat digest accepted: %v", err)
	}
}
