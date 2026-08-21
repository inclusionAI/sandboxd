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
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	tasktypes "github.com/containerd/containerd/api/types/task"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	cmap "github.com/orcaman/concurrent-map/v2"
	"google.golang.org/protobuf/proto"
)

func TestValidateKataHost(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "containerd-shim-kata-v2")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	loggerBinary := filepath.Join(directory, "sandbox-logger")
	if err := os.WriteFile(loggerBinary, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "configuration.toml")
	if err := os.WriteFile(configPath, []byte("[runtime]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateKataHost(binary, config.KataConfig{
		ConfigPath:   configPath,
		KVMDevice:    "/dev/null",
		LoggerBinary: loggerBinary,
	}); err != nil {
		t.Fatalf("validateKataHost() error = %v", err)
	}
	if err := validateKataHost(binary, config.KataConfig{
		ConfigPath:   configPath,
		KVMDevice:    filepath.Join(directory, "missing-kvm"),
		LoggerBinary: loggerBinary,
	}); err == nil {
		t.Fatal("validateKataHost() succeeded without a KVM device")
	}
}

func TestSandboxLoggerURI(t *testing.T) {
	uri, err := sandboxLoggerURI(
		"/usr/local/bin/sandbox-logger",
		"/tmp/std out.log",
		"/tmp/stderr.log",
	)
	if err != nil {
		t.Fatal(err)
	}
	const want = "binary:///usr/local/bin/sandbox-logger?stderr=%2Ftmp%2Fstderr.log&stdout=%2Ftmp%2Fstd+out.log"
	if uri != want {
		t.Fatalf("sandboxLoggerURI() = %q, want %q", uri, want)
	}
	if _, err := sandboxLoggerURI("sandbox-logger", os.DevNull, os.DevNull); err == nil {
		t.Fatal("sandboxLoggerURI() accepted a relative binary path")
	}
}

func TestKataRuntimeOptions(t *testing.T) {
	options, err := kataRuntimeOptions("/opt/kata/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if options == nil || options.TypeUrl != kataRuntimeOptionsTypeURL {
		t.Fatalf("kataRuntimeOptions() = %+v", options)
	}
	decoded := &runtimeoptions.Options{}
	if err := proto.Unmarshal(options.Value, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ConfigPath != "/opt/kata/config.toml" {
		t.Fatalf("config path = %q", decoded.ConfigPath)
	}
}

func TestKataBundlePathRejectsTraversal(t *testing.T) {
	handler := &KataHandler{sandboxRoot: t.TempDir()}
	if _, err := handler.bundlePath("../../outside"); err == nil {
		t.Fatal("bundlePath() accepted a path outside the sandbox root")
	}
}

func TestKataSandboxStatus(t *testing.T) {
	tests := []struct {
		name string
		in   tasktypes.Status
		want SandboxStatus
	}{
		{name: "created", in: tasktypes.Status_CREATED, want: SandboxStatusCreated},
		{name: "running", in: tasktypes.Status_RUNNING, want: SandboxStatusRunning},
		{name: "stopped", in: tasktypes.Status_STOPPED, want: SandboxStatusExited},
		{name: "paused", in: tasktypes.Status_PAUSED, want: SandboxStatusUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := kataSandboxStatus(test.in); got != test.want {
				t.Fatalf("kataSandboxStatus(%s) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestKataProcessStatAlive(t *testing.T) {
	tests := []struct {
		name string
		stat string
		want bool
	}{
		{
			name: "running",
			stat: "123 (containerd-shim-kata-v2) S 1 2 3",
			want: true,
		},
		{
			name: "zombie",
			stat: "123 (containerd-shim-kata-v2) Z 1 2 3",
			want: false,
		},
		{
			name: "closing parenthesis in command",
			stat: "123 (containerd) shim) Z 1 2 3",
			want: false,
		},
		{
			name: "malformed",
			stat: "123",
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := kataProcessStatAlive([]byte(test.stat)); got != test.want {
				t.Fatalf("kataProcessStatAlive() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPrepareKataEROFSRootfs(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "bundle")
	rootfsImage := filepath.Join(t.TempDir(), "rootfs.img")
	if err := os.WriteFile(rootfsImage, []byte("erofs"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bundlePath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(bundlePath, "config.json"),
		[]byte(`{"root":{"path":"unused"}}`),
		0644,
	); err != nil {
		t.Fatal(err)
	}

	originalImageMount := mountKataEROFSImage
	originalOverlayMount := mountKataOverlay
	originalUnmount := unmountKataPath
	t.Cleanup(func() {
		mountKataEROFSImage = originalImageMount
		mountKataOverlay = originalOverlayMount
		unmountKataPath = originalUnmount
	})

	var imageSource string
	var imageTarget string
	mountKataEROFSImage = func(source, target string) error {
		imageSource = source
		imageTarget = target
		return nil
	}
	var overlayLower string
	var overlayTarget string
	mountKataOverlay = func(lowerDir, _, _, target string) error {
		overlayLower = lowerDir
		overlayTarget = target
		return nil
	}
	var unmounted []string
	unmountKataPath = func(target string) error {
		unmounted = append(unmounted, target)
		return syscall.EINVAL
	}

	plan, err := prepareKataRootfs(bundlePath, rootfsImage, kataRootfsEROFS, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	lowerDir := filepath.Join(bundlePath, kataRootfsLowerDir)
	rootfsDir := filepath.Join(bundlePath, kataRootfsDir)
	if imageSource != rootfsImage || imageTarget != lowerDir {
		t.Fatalf("mounted EROFS image %q at %q", imageSource, imageTarget)
	}
	if overlayLower != lowerDir || overlayTarget != rootfsDir {
		t.Fatalf("mounted overlay with lower %q at %q", overlayLower, overlayTarget)
	}
	if len(plan.mounts) != 1 {
		t.Fatalf("rootfs mount count = %d, want 1", len(plan.mounts))
	}
	if plan.mounts[0].Type != "bind" ||
		plan.mounts[0].Source != rootfsDir ||
		plan.mounts[0].Target != "/" ||
		!slices.Equal(plan.mounts[0].Options, []string{"rbind", "ro"}) {
		t.Fatalf("unexpected rootfs mounts: %+v", plan.mounts)
	}
	data, err := os.ReadFile(filepath.Join(bundlePath, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Root == nil || spec.Root.Path != kataRootfsDir || !spec.Root.Readonly {
		t.Fatalf("root = %+v", spec.Root)
	}

	unmounted = nil
	plan.cleanup()
	if len(unmounted) != 2 ||
		unmounted[0] != rootfsDir ||
		unmounted[1] != lowerDir {
		t.Fatalf("unmounted paths = %v", unmounted)
	}
	if _, err := os.Stat(lowerDir); !os.IsNotExist(err) {
		t.Fatalf("EROFS lower directory still exists: %v", err)
	}
}

func TestClassifyKataRootfs(t *testing.T) {
	directory := t.TempDir()
	if kind, err := classifyKataRootfs(directory); err != nil || kind != kataRootfsDirectory {
		t.Fatalf("classify directory = %v, %v", kind, err)
	}

	image := filepath.Join(t.TempDir(), "rootfs.erofs")
	if err := os.WriteFile(image, []byte("erofs"), 0644); err != nil {
		t.Fatal(err)
	}
	if kind, err := classifyKataRootfs(image); err != nil || kind != kataRootfsEROFS {
		t.Fatalf("classify EROFS image = %v, %v", kind, err)
	}
}

func TestPrepareKataMountsExposesEROFSFilesThroughVirtiofs(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "bundle")
	originalMount := mountKataEROFSImage
	originalUnmount := unmountKataPath
	var mountedSource string
	var mountedTarget string
	mountKataEROFSImage = func(source, target string) error {
		mountedSource = source
		mountedTarget = target
		return nil
	}
	var unmountedTargets []string
	unmountKataPath = func(target string) error {
		unmountedTargets = append(unmountedTargets, target)
		return nil
	}
	t.Cleanup(func() {
		mountKataEROFSImage = originalMount
		unmountKataPath = originalUnmount
	})

	image := filepath.Join(t.TempDir(), "runtime.erofs")
	if err := os.WriteFile(image, []byte("erofs"), 0644); err != nil {
		t.Fatal(err)
	}
	original := StartConfig{
		Rootfs: t.TempDir(),
		Mounts: []*runtime.Mount{{
			Type:    "erofs",
			Target:  "/runtime",
			Options: []string{"ro", "loop"},
			Source:  &runtime.Mount_HostPath{HostPath: image},
		}},
	}
	kataConfig := cloneKataStartConfig(original)
	cleanup, err := prepareKataMounts(bundlePath, &kataConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if kataConfig.Mounts[0].GetType() != "bind" {
		t.Fatalf("mount type = %q", kataConfig.Mounts[0].GetType())
	}
	if original.Mounts[0].GetType() != "erofs" {
		t.Fatal("preparing Kata mounts mutated the caller's request")
	}
	mountDir := filepath.Join(bundlePath, kataEROFSMountDir, "0")
	lowerDir := filepath.Join(mountDir, kataEROFSLowerDir)
	if kataConfig.Mounts[0].GetHostPath() != lowerDir {
		t.Fatalf("mount source = %q, want %q", kataConfig.Mounts[0].GetHostPath(), lowerDir)
	}
	if mountedSource != image || mountedTarget != lowerDir {
		t.Fatalf("mounted EROFS image %q at %q", mountedSource, mountedTarget)
	}
	if got := kataConfig.Mounts[0].GetOptions(); len(got) != 2 ||
		got[0] != "ro" ||
		got[1] != "rbind" {
		t.Fatalf("mount options = %v, want [ro rbind]", got)
	}
	cleanup()
	if len(unmountedTargets) != 1 ||
		unmountedTargets[0] != lowerDir {
		t.Fatalf(
			"unmounted targets = %v, want [%q]",
			unmountedTargets,
			lowerDir,
		)
	}
	if _, err := os.Stat(filepath.Join(bundlePath, kataEROFSMountDir)); !os.IsNotExist(err) {
		t.Fatalf("EROFS mount directory still exists: %v", err)
	}
}

func TestPrepareKataMountsKeepsDirectoriesOnVirtiofs(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "bundle")
	directory := t.TempDir()
	originalMount := mountKataEROFSImage
	mountKataEROFSImage = func(_, _ string) error {
		t.Fatal("directory-backed mount used an EROFS loop mount")
		return nil
	}
	t.Cleanup(func() {
		mountKataEROFSImage = originalMount
	})
	kataConfig := StartConfig{
		Mounts: []*runtime.Mount{{
			Type:    "erofs",
			Target:  "/runtime",
			Options: []string{"ro", "loop"},
			Source:  &runtime.Mount_HostPath{HostPath: directory},
		}},
	}
	cleanup, err := prepareKataMounts(bundlePath, &kataConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	mount := kataConfig.Mounts[0]
	if mount.GetType() != "bind" || mount.GetHostPath() != directory {
		t.Fatalf("directory mount = %+v", mount)
	}
	if len(mount.GetOptions()) != 2 ||
		mount.GetOptions()[0] != "ro" ||
		mount.GetOptions()[1] != "rbind" {
		t.Fatalf("directory mount options = %v", mount.GetOptions())
	}
}

func TestPrepareKataMountsReusesEROFSFileWithinSandbox(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "bundle")
	image := filepath.Join(t.TempDir(), "runtime.erofs")
	if err := os.WriteFile(image, []byte("erofs"), 0644); err != nil {
		t.Fatal(err)
	}

	originalMount := mountKataEROFSImage
	originalUnmount := unmountKataPath
	mountCalls := 0
	mountKataEROFSImage = func(_, _ string) error {
		mountCalls++
		return nil
	}
	unmountKataPath = func(string) error {
		return syscall.EINVAL
	}
	t.Cleanup(func() {
		mountKataEROFSImage = originalMount
		unmountKataPath = originalUnmount
	})

	kataConfig := StartConfig{
		Mounts: []*runtime.Mount{
			{
				Type:   kataEROFSMountType,
				Target: "/runtime-a",
				Source: &runtime.Mount_HostPath{HostPath: image},
			},
			{
				Type:   kataEROFSMountType,
				Target: "/runtime-b",
				Source: &runtime.Mount_HostPath{HostPath: image},
			},
		},
	}
	cleanup, err := prepareKataMounts(bundlePath, &kataConfig)
	if err != nil {
		t.Fatal(err)
	}
	if mountCalls != 1 {
		t.Fatalf("EROFS mount calls = %d, want 1", mountCalls)
	}
	if kataConfig.Mounts[0].GetHostPath() != kataConfig.Mounts[1].GetHostPath() {
		t.Fatalf(
			"shared EROFS sources differ: %q and %q",
			kataConfig.Mounts[0].GetHostPath(),
			kataConfig.Mounts[1].GetHostPath(),
		)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupKataRootfsPreservesPathsAfterUnmountFailure(t *testing.T) {
	bundlePath := t.TempDir()
	rootfsPath := filepath.Join(bundlePath, kataRootfsDir)
	if err := os.MkdirAll(rootfsPath, 0755); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(rootfsPath, "keep")
	if err := os.WriteFile(markerPath, []byte("mounted"), 0644); err != nil {
		t.Fatal(err)
	}

	originalUnmount := unmountKataPath
	unmountKataPath = func(target string) error {
		if target == rootfsPath {
			return syscall.EPERM
		}
		return syscall.EINVAL
	}
	t.Cleanup(func() {
		unmountKataPath = originalUnmount
	})

	err := cleanupKataRootfs(bundlePath)
	if err == nil || !strings.Contains(err.Error(), "unmount Kata rootfs") {
		t.Fatalf("cleanupKataRootfs() error = %v", err)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("rootfs path removed after failed unmount: %v", err)
	}
}

func TestCleanupKataMountsPreservesPathsAfterUnmountFailure(t *testing.T) {
	bundlePath := t.TempDir()
	lowerPath := filepath.Join(
		bundlePath,
		kataEROFSMountDir,
		"0",
		kataEROFSLowerDir,
	)
	if err := os.MkdirAll(lowerPath, 0755); err != nil {
		t.Fatal(err)
	}

	originalUnmount := unmountKataPath
	unmountKataPath = func(target string) error {
		if target == lowerPath {
			return syscall.EPERM
		}
		return syscall.EINVAL
	}
	t.Cleanup(func() {
		unmountKataPath = originalUnmount
	})

	err := cleanupKataMounts(bundlePath)
	if err == nil || !strings.Contains(err.Error(), "unmount Kata EROFS input") {
		t.Fatalf("cleanupKataMounts() error = %v", err)
	}
	if _, err := os.Stat(lowerPath); err != nil {
		t.Fatalf("EROFS mount path removed after failed unmount: %v", err)
	}
}

func TestDeleteKataSandboxReturnsCleanupFailure(t *testing.T) {
	sandboxRoot := t.TempDir()
	sandboxID := "sandbox-kata-cleanup"
	bundlePath := filepath.Join(sandboxRoot, sandboxID)
	if err := os.MkdirAll(filepath.Join(bundlePath, kataRootfsDir), 0755); err != nil {
		t.Fatal(err)
	}

	originalUnmount := unmountKataPath
	unmountKataPath = func(target string) error {
		if target == filepath.Join(bundlePath, kataRootfsDir) {
			return syscall.EPERM
		}
		return syscall.EINVAL
	}
	t.Cleanup(func() {
		unmountKataPath = originalUnmount
	})

	handler := &KataHandler{
		binary:      "/bin/true",
		sandboxRoot: sandboxRoot,
		shims:       cmap.New[*kataShimInstance](),
	}
	err := handler.Delete(context.Background(), sandboxID)
	if err == nil || !strings.Contains(err.Error(), "unmount Kata rootfs") {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestDeleteKataSandboxRemovesSharedPath(t *testing.T) {
	sandboxRoot := t.TempDir()
	sharedRoot := t.TempDir()
	sandboxID := "sandbox-kata-shared"
	if err := os.MkdirAll(filepath.Join(sandboxRoot, sandboxID), 0755); err != nil {
		t.Fatal(err)
	}
	sharedPath := filepath.Join(sharedRoot, sandboxID, "rw", "passthrough")
	if err := os.MkdirAll(sharedPath, 0755); err != nil {
		t.Fatal(err)
	}

	originalUnmount := unmountKataPath
	unmountKataPath = func(string) error {
		return syscall.EINVAL
	}
	t.Cleanup(func() {
		unmountKataPath = originalUnmount
	})

	handler := &KataHandler{
		binary:      "/bin/true",
		sandboxRoot: sandboxRoot,
		sharedRoot:  sharedRoot,
		shims:       cmap.New[*kataShimInstance](),
	}
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sharedRoot, sandboxID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Kata shared path remains: %v", err)
	}
}

func TestDeleteKataSandboxPreservesSharedPathWhenShimStopFails(t *testing.T) {
	sandboxRoot := t.TempDir()
	sharedRoot := t.TempDir()
	sandboxID := "sandbox-kata-running"
	sharedPath := filepath.Join(sharedRoot, sandboxID)
	if err := os.MkdirAll(sharedPath, 0755); err != nil {
		t.Fatal(err)
	}

	originalUnmount := unmountKataPath
	unmountKataPath = func(string) error {
		return syscall.EINVAL
	}
	t.Cleanup(func() {
		unmountKataPath = originalUnmount
	})

	handler := &KataHandler{
		binary:      "/bin/false",
		sandboxRoot: sandboxRoot,
		sharedRoot:  sharedRoot,
		shims:       cmap.New[*kataShimInstance](),
	}
	if err := handler.Delete(context.Background(), sandboxID); err == nil {
		t.Fatal("Delete() succeeded when the Kata shim stop failed")
	}
	if _, err := os.Stat(sharedPath); err != nil {
		t.Fatalf("Kata shared path was removed after shim stop failure: %v", err)
	}
}

func TestRecoverShimsCleansDeadKataBundle(t *testing.T) {
	sandboxRoot := t.TempDir()
	sharedRoot := t.TempDir()
	sandboxID := "sandbox-kata-orphan"
	bundlePath := filepath.Join(sandboxRoot, sandboxID)
	for _, path := range []string{
		filepath.Join(bundlePath, kataRootfsDir),
		filepath.Join(bundlePath, kataRootfsLowerDir),
		filepath.Join(bundlePath, kataEROFSMountDir, "0", kataEROFSLowerDir),
	} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "shim.pid"), []byte("invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "address"), []byte("unix://stale"), 0644); err != nil {
		t.Fatal(err)
	}
	sharedPath := filepath.Join(sharedRoot, sandboxID, "rw", "passthrough")
	if err := os.MkdirAll(sharedPath, 0755); err != nil {
		t.Fatal(err)
	}

	originalUnmount := unmountKataPath
	unmountKataPath = func(string) error {
		return syscall.EINVAL
	}
	t.Cleanup(func() {
		unmountKataPath = originalUnmount
	})

	handler := &KataHandler{
		binary:      "/bin/true",
		sandboxRoot: sandboxRoot,
		sharedRoot:  sharedRoot,
		shims:       cmap.New[*kataShimInstance](),
	}
	handler.recoverShims()

	for _, path := range []string{
		filepath.Join(bundlePath, "shim.pid"),
		filepath.Join(bundlePath, "address"),
		filepath.Join(bundlePath, kataRootfsDir),
		filepath.Join(bundlePath, kataRootfsLowerDir),
		filepath.Join(bundlePath, kataEROFSMountDir),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphaned Kata path %s remains: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(sharedRoot, sandboxID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned Kata shared path remains: %v", err)
	}
}

func TestPrepareKataResourceSpec(t *testing.T) {
	bundlePath := t.TempDir()
	shares := uint64(1536)
	memory := int64(2 * 1024 * 1024 * 1024)
	resource := &runtime.LinuxSandboxResources{
		CpuShares:          shares,
		MemoryLimitInBytes: memory,
	}
	spec := defaultSandboxSpec()
	setSpecResource(spec, resource)
	if err := writeKataSpec(filepath.Join(bundlePath, "config.json"), spec); err != nil {
		t.Fatal(err)
	}
	restore, err := prepareKataResourceSpec(bundlePath, resource)
	if err != nil {
		t.Fatal(err)
	}
	shimSpec := loadKataTestSpec(t, bundlePath)
	if got := shimSpec.Annotations[kataDefaultVCPUsAnnotation]; got != "2" {
		t.Fatalf("vCPU annotation = %q", got)
	}
	if got := shimSpec.Annotations[kataDefaultMemoryAnnotation]; got != "2048" {
		t.Fatalf("memory annotation = %q", got)
	}
	if shimSpec.Linux.Resources.CPU.Quota != nil || shimSpec.Linux.Resources.CPU.Period != nil {
		t.Fatal("shim-facing spec retained CPU quota")
	}
	if shimSpec.Linux.Resources.CPU.Shares == nil || *shimSpec.Linux.Resources.CPU.Shares != shares {
		t.Fatal("shim-facing spec did not retain CPU shares")
	}
	if shimSpec.Linux.Resources.Memory != nil {
		t.Fatal("shim-facing spec retained memory sizing")
	}

	if err := restore(); err != nil {
		t.Fatal(err)
	}
	restored := loadKataTestSpec(t, bundlePath)
	if restored.Linux.Resources.Memory == nil ||
		restored.Linux.Resources.Memory.Limit == nil ||
		*restored.Linux.Resources.Memory.Limit != memory {
		t.Fatal("restored spec did not retain the sandbox memory limit")
	}
}

func TestPrepareKataResourceSpecUsesQuotaForVCPUs(t *testing.T) {
	bundlePath := t.TempDir()
	resource := &runtime.LinuxSandboxResources{
		CpuQuota:  150000,
		CpuPeriod: 100000,
	}
	spec := defaultSandboxSpec()
	setSpecResource(spec, resource)
	if err := writeKataSpec(filepath.Join(bundlePath, "config.json"), spec); err != nil {
		t.Fatal(err)
	}
	restore, err := prepareKataResourceSpec(bundlePath, resource)
	if err != nil {
		t.Fatal(err)
	}
	shimSpec := loadKataTestSpec(t, bundlePath)
	if got := shimSpec.Annotations[kataDefaultVCPUsAnnotation]; got != "2" {
		t.Fatalf("vCPU annotation = %q, want 2", got)
	}
	if shimSpec.Linux.Resources.CPU.Quota != nil || shimSpec.Linux.Resources.CPU.Period != nil {
		t.Fatal("shim-facing spec retained CPU quota")
	}

	if err := restore(); err != nil {
		t.Fatal(err)
	}
	restored := loadKataTestSpec(t, bundlePath)
	if restored.Linux.Resources.CPU.Quota == nil ||
		*restored.Linux.Resources.CPU.Quota != resource.CpuQuota ||
		restored.Linux.Resources.CPU.Period == nil ||
		*restored.Linux.Resources.CPU.Period != resource.CpuPeriod {
		t.Fatal("restored spec did not retain CPU quota")
	}
}
func TestWriteKataDANConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox.json")
	resource := &networkmanager.NetResource{
		SchemaVersion: networkmanager.NetResourceSchemaVersion,
		EndpointType:  networkmanager.EndpointTypeTap,
		GuestMAC:      net.HardwareAddr{0x02, 0xfc, 0x0a, 0x58, 0x00, 0x02},
		Interface: &net.Interface{
			Name:         "tap.0a580002",
			MTU:          1500,
			HardwareAddr: net.HardwareAddr{0x02, 0xfd, 0x0a, 0x58, 0x00, 0x02},
		},
		Ip:      net.ParseIP("10.88.0.2"),
		Mask:    net.CIDRMask(16, 32),
		Gateway: net.ParseIP("10.88.0.1"),
	}
	if err := writeKataDANConfig(path, resource.Interface.Name, resource); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config kataDANConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.NetNS != nil || len(config.Devices) != 1 {
		t.Fatalf("DAN config = %+v", config)
	}
	device := config.Devices[0]
	if device.Device.QueueNum != 1 || device.Device.TapName != "tap.0a580002" {
		t.Fatalf("DAN device = %+v", device.Device)
	}
	if device.GuestMAC != "02:fc:0a:58:00:02" {
		t.Fatalf("DAN guest MAC = %q", device.GuestMAC)
	}
}

func TestRemoveKataNetworkNamespace(t *testing.T) {
	bundlePath := t.TempDir()
	spec := defaultSandboxSpec()
	spec.Linux.Namespaces = append(spec.Linux.Namespaces, LinuxNamespace{Type: NetworkNamespace})
	if err := writeKataSpec(filepath.Join(bundlePath, "config.json"), spec); err != nil {
		t.Fatal(err)
	}
	if err := removeKataNetworkNamespace(bundlePath); err != nil {
		t.Fatal(err)
	}
	updated := loadKataTestSpec(t, bundlePath)
	for _, namespace := range updated.Linux.Namespaces {
		if namespace.Type == NetworkNamespace {
			t.Fatal("network namespace was not removed")
		}
	}
}

func TestKataHostResourcesRetainsCPUControls(t *testing.T) {
	original := &runtime.LinuxSandboxResources{
		CpuShares:          1536,
		CpuQuota:           100000,
		CpuPeriod:          100000,
		MemoryLimitInBytes: 2 * 1024 * 1024 * 1024,
	}
	host := kataHostResources(original)
	if host.CpuShares != original.CpuShares ||
		host.CpuQuota != original.CpuQuota ||
		host.CpuPeriod != original.CpuPeriod ||
		host.MemoryLimitInBytes != original.MemoryLimitInBytes {
		t.Fatalf("host resources = %+v", host)
	}
	if host == original {
		t.Fatal("kataHostResources returned the caller's resource object")
	}
	host.CpuQuota = 0
	if original.CpuQuota == 0 {
		t.Fatal("kataHostResources mutated the caller")
	}
}

func loadKataTestSpec(t *testing.T, bundlePath string) *Spec {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundlePath, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	return &spec
}
