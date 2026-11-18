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

package runc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/runcshim"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuncCgroupPathUsesRuntimeOwnedChild(t *testing.T) {
	assert.Equal(t, "/sandbox/sbox-test/runc", runcCgroupPath("/sandbox/sbox-test"))
	assert.Empty(t, runcCgroupPath(""))
}

func TestAbortShimStopsTheInFlightRuncLauncher(t *testing.T) {
	bundle := t.TempDir()
	shim := filepath.Join(bundle, "fake-shim")
	require.NoError(t, os.WriteFile(shim, []byte(`#!/bin/sh
sleep 30 &
printf '%s' "$!" > "$0.child"
wait
`), 0700))
	handler := &Handler{shimBinary: shim}
	abort, err := handler.launchShim(bundle, runtimecore.StartConfig{ID: "sbox-shim-abort"})
	require.NoError(t, err)
	t.Cleanup(abort)
	var child string
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(shim + ".child")
		child = strings.TrimSpace(string(data))
		return err == nil && child != ""
	}, time.Second, 10*time.Millisecond)
	abort()
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(filepath.Join("/proc", child, "stat"))
		return errors.Is(err, os.ErrNotExist) || strings.Contains(string(data), ") Z ")
	}, time.Second, 10*time.Millisecond, "runc launcher survived the shim abort")
}

type cancellingOciLoader struct {
	cancel context.CancelFunc
	called bool
}

func (l *cancellingOciLoader) GenerateOci(runtimecore.OciLoadOptions) (string, *runtimecore.Spec, error) {
	l.called = true
	l.cancel()
	return "", &runtimecore.Spec{}, nil
}

func TestRuncStartAlreadyCancelledAllocatesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := t.TempDir()
	loader := &cancellingOciLoader{cancel: cancel}
	handler := &Handler{sandboxRoot: root, ociLoader: loader}

	err := handler.Start(ctx, runtimecore.StartConfig{ID: "expired"})

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, loader.called)
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestRuncStartStopsAfterPreparationCancelsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loader := &cancellingOciLoader{cancel: cancel}
	handler := &Handler{sandboxRoot: t.TempDir(), ociLoader: loader}
	config := runtimecore.StartConfig{
		ID: "expired", CgroupPath: "/private-cgroup",
		Network: &networkmanager.NetResource{
			Interface: &net.Interface{Name: "pv.test"},
			NetNSPath: "/var/run/netns/runc-sbox-expired",
			Lifecycle: networkmanager.InterfaceLifecycleEphemeral,
		},
	}

	err := handler.Start(ctx, config)

	require.True(t, loader.called)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRuncWaitStartedRejectsCancelledReadyMarker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bundle := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bundle, runcshim.InitPIDFile), []byte("42"), 0600))
	require.ErrorIs(t, (&Handler{}).waitStarted(ctx, bundle), context.Canceled)
}

func TestValidateExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runc")
	require.NoError(t, os.WriteFile(path, []byte("binary"), 0644))
	assert.ErrorContains(t, validateExecutable(path, "runc binary"), "executable")

	require.NoError(t, os.Chmod(path, 0755))
	assert.NoError(t, validateExecutable(path, "runc binary"))
	assert.Error(t, validateExecutable(path+"-missing", "runc binary"))
}

func TestConfigureRuncKVM(t *testing.T) {
	spec := &runtimecore.Spec{Linux: &runtimecore.Linux{Resources: &runtimecore.LinuxResources{}}}
	require.NoError(t, configureRuncKVM(spec, os.DevNull))
	require.Len(t, spec.Mounts, 1)
	assert.Equal(t, "/dev/kvm", spec.Mounts[0].Destination)
	assert.Equal(t, os.DevNull, spec.Mounts[0].Source)
	require.Len(t, spec.Linux.Resources.Devices, 1)
	assert.True(t, spec.Linux.Resources.Devices[0].Allow)
	assert.Equal(t, "c", spec.Linux.Resources.Devices[0].Type)

	err := configureRuncKVM(spec, os.DevNull)
	assert.ErrorContains(t, err, "already configured")
}

func TestConfigureRuncKVMRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-device")
	require.NoError(t, os.WriteFile(path, nil, 0644))
	assert.ErrorContains(t, configureRuncKVM(&runtimecore.Spec{}, path), "not a character device")
}

func TestRequireHostFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filesystems")
	require.NoError(t, os.WriteFile(path, []byte("nodev\toverlay\n\terofs\n"), 0644))
	assert.NoError(t, requireHostFilesystem(path, "overlay"))
	assert.NoError(t, requireHostFilesystem(path, "erofs"))
	assert.ErrorContains(t, requireHostFilesystem(path, "xfs"), "not registered")
}

func TestRuncHandlerListFiltersRuntimeMarker(t *testing.T) {
	root := t.TempDir()
	runcBundle := filepath.Join(root, "sbox-runc")
	otherBundle := filepath.Join(root, "sbox-other")
	require.NoError(t, os.MkdirAll(runcBundle, 0755))
	require.NoError(t, os.MkdirAll(otherBundle, 0755))
	require.NoError(t, runtimecommon.WriteSandboxRuntimeMarker(runcBundle, config.RuntimeNameRunc))
	require.NoError(t, runtimecommon.WriteSandboxRuntimeMarker(otherBundle, config.RuntimeNameRunsc))
	handler := &Handler{client: &fakeRuncClient{states: []State{
		{ID: "sbox-runc", PID: 10, Status: "running", Bundle: runcBundle},
		{ID: "sbox-other", PID: 11, Status: "running", Bundle: otherBundle},
	}}}
	states, err := handler.List(context.Background())
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, "sbox-runc", states[0].ID)
	assert.Equal(t, runtimecore.SandboxStatusRunning, states[0].Status)
}

func TestRuncHandlerWaitReadsDurableExit(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "sbox-wait")
	require.NoError(t, os.MkdirAll(bundle, 0755))
	exitedAt := time.Now().UTC().Round(0)
	require.NoError(t, runcshim.WriteExit(filepath.Join(bundle, runcshim.ExitFile), runcshim.ExitRecord{
		Started:  true,
		ExitCode: 31,
		ExitedAt: exitedAt,
	}))
	handler := &Handler{sandboxRoot: root}
	exit, err := handler.Wait(context.Background(), "sbox-wait")
	require.NoError(t, err)
	assert.Equal(t, 31, exit.ExitCode)
	assert.Equal(t, exitedAt, exit.ExitedAt)
}

func TestRuncHandlerWaitReturnsStartupError(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "sbox-failed")
	require.NoError(t, os.MkdirAll(bundle, 0755))
	require.NoError(t, runcshim.WriteExit(filepath.Join(bundle, runcshim.ExitFile), runcshim.ExitRecord{
		ExitCode:     125,
		RuntimeError: "invalid OCI spec",
	}))
	handler := &Handler{sandboxRoot: root}
	_, err := handler.Wait(context.Background(), "sbox-failed")
	assert.EqualError(t, err, "invalid OCI spec")
}

type fakeRuncClient struct {
	states    []State
	state     State
	stateErr  error
	killErr   error
	deleteErr error
}

func (f *fakeRuncClient) List(context.Context) ([]State, error) {
	return f.states, nil
}

func (f *fakeRuncClient) State(context.Context, string) (State, error) {
	return f.state, f.stateErr
}

func (f *fakeRuncClient) Kill(context.Context, string, string, bool) error {
	return f.killErr
}

func (f *fakeRuncClient) Delete(context.Context, string, bool) error {
	return f.deleteErr
}

func TestRuncDeleteFailureRetainsRuntimeFiles(t *testing.T) {
	for _, failure := range []string{"missing-binary", "permission", "runtime-enoent", "cancelled", "deadline"} {
		t.Run(failure, func(t *testing.T) {
			const id = "sbox-retained"
			root, storage, stateRoot := t.TempDir(), t.TempDir(), t.TempDir()
			bundle := filepath.Join(root, id)
			markers := []string{filepath.Join(bundle, "rootfs", "data"), filepath.Join(bundle, "erofs", "content", "data"), filepath.Join(storage, id, "private-data"), filepath.Join(stateRoot, id, "state.json")}
			for _, name := range markers {
				require.NoError(t, os.MkdirAll(filepath.Dir(name), 0700))
				require.NoError(t, os.WriteFile(name, []byte("keep"), 0600))
			}
			binary := filepath.Join(t.TempDir(), "runc")
			if failure == "permission" {
				require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0644))
			}
			if failure == "runtime-enoent" {
				require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\necho 'open config.json: no such file or directory' >&2\nexit 1\n"), 0755))
			}
			var client runcClient = NewClient(binary, stateRoot)
			if failure == "cancelled" {
				client = &fakeRuncClient{killErr: context.Canceled, deleteErr: context.Canceled}
			}
			if failure == "deadline" {
				client = &fakeRuncClient{killErr: context.DeadlineExceeded, deleteErr: context.DeadlineExceeded}
			}
			oldUnmount := unmountRuncPath
			touched := false
			unmountRuncPath = func(string) error { touched = true; return nil }
			defer func() { unmountRuncPath = oldUnmount }()
			handler := &Handler{client: client, sandboxRoot: root, storageRoot: storage}
			err := handler.Delete(context.Background(), id)
			require.Error(t, err)
			assert.False(t, touched, "runtime deletion must succeed before filesystem cleanup")
			for _, name := range markers {
				data, e := os.ReadFile(name)
				require.NoError(t, e)
				assert.Equal(t, "keep", string(data))
			}
		})
	}
}

func TestRuncDeleteAmbiguousDiagnosticRetainsRuntimeFiles(t *testing.T) {
	for _, script := range []string{
		"#!/bin/sh\necho 'container does not exist' >&2\nkill -TERM $$\n",
		"#!/bin/sh\necho 'open /tmp/container does not exist/sbox/state.json: not a directory' >&2\nexit 1\n",
	} {
		t.Run(script, func(t *testing.T) {
			const id = "sbox-retained"
			root, storage, stateRoot := t.TempDir(), t.TempDir(), t.TempDir()
			bundle := filepath.Join(root, id)
			state := filepath.Join(stateRoot, id)
			require.NoError(t, os.Mkdir(state, 0700))
			markers := []string{filepath.Join(bundle, "rootfs", "data"), filepath.Join(storage, id, "private-data")}
			for _, name := range markers {
				require.NoError(t, os.MkdirAll(filepath.Dir(name), 0700))
				require.NoError(t, os.WriteFile(name, []byte("keep"), 0600))
			}
			binary := filepath.Join(t.TempDir(), "runc")
			require.NoError(t, os.WriteFile(binary, []byte(script), 0755))
			oldUnmount := unmountRuncPath
			touched := false
			unmountRuncPath = func(string) error { touched = true; return nil }
			defer func() { unmountRuncPath = oldUnmount }()
			handler := &Handler{client: NewClient(binary, stateRoot), sandboxRoot: root, storageRoot: storage}
			require.Error(t, handler.Delete(context.Background(), id))
			assert.False(t, touched)
			assert.DirExists(t, state)
			for _, name := range markers {
				data, err := os.ReadFile(name)
				require.NoError(t, err)
				assert.Equal(t, "keep", string(data))
			}
		})
	}
}

func TestRuncOrphanDeleteFailureRetainsPrivateStorage(t *testing.T) {
	const id = "sbox-orphan"
	root, storage := t.TempDir(), t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, id), 0700))
	require.NoError(t, runtimecommon.WriteSandboxRuntimeMarker(filepath.Join(root, id), config.RuntimeNameRunc))
	marker := filepath.Join(storage, id, "data")
	require.NoError(t, os.MkdirAll(filepath.Dir(marker), 0700))
	require.NoError(t, os.WriteFile(marker, []byte("keep"), 0600))
	handler := &Handler{client: NewClient(filepath.Join(t.TempDir(), "missing-runc"), t.TempDir()), sandboxRoot: root, storageRoot: storage}
	oldUnmount := unmountRuncPath
	unmountRuncPath = func(string) error { return nil }
	defer func() { unmountRuncPath = oldUnmount }()
	require.Error(t, handler.reconcileOrphans())
	assert.FileExists(t, marker)
}

func TestRuncDeleteFilesystemFailureCanBeRetried(t *testing.T) {
	const id = "sbox-retry"
	root, storage := t.TempDir(), t.TempDir()
	marker := filepath.Join(storage, id, "data")
	require.NoError(t, os.MkdirAll(filepath.Dir(marker), 0700))
	require.NoError(t, os.WriteFile(marker, []byte("keep"), 0600))
	handler := &Handler{client: &fakeRuncClient{killErr: assert.AnError}, sandboxRoot: root, storageRoot: storage}
	oldUnmount := unmountRuncPath
	defer func() { unmountRuncPath = oldUnmount }()
	unmountRuncPath = func(string) error { return errors.New("unmount failed") }
	require.Error(t, handler.Delete(context.Background(), id))
	assert.FileExists(t, marker, "filesystem cleanup failure must not discard private storage")
	unmountRuncPath = func(string) error { return nil }
	require.NoError(t, handler.Delete(context.Background(), id))
	assert.NoDirExists(t, filepath.Join(storage, id))
}

func TestInternalRuncStartTimeoutPreservesDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := (&Handler{}).waitStarted(ctx, t.TempDir())
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, ctx.Err())
	require.Contains(t, err.Error(), "runc container start")
}
