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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/runcshim"
	runcapi "github.com/inclusionAI/sandboxd/pkg/runtime/runc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuncCgroupPathUsesRuntimeOwnedChild(t *testing.T) {
	assert.Equal(t, "/sandbox/sbox-test/runc", runcCgroupPath("/sandbox/sbox-test"))
	assert.Empty(t, runcCgroupPath(""))
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
	spec := &Spec{Linux: &Linux{Resources: &LinuxResources{}}}
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
	assert.ErrorContains(t, configureRuncKVM(&Spec{}, path), "not a character device")
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
	require.NoError(t, writeSandboxRuntimeMarker(runcBundle, config.RuntimeNameRunc))
	require.NoError(t, writeSandboxRuntimeMarker(otherBundle, config.RuntimeNameRunsc))
	handler := &RuncHandler{client: &fakeRuncClient{states: []runcapi.State{
		{ID: "sbox-runc", PID: 10, Status: "running", Bundle: runcBundle},
		{ID: "sbox-other", PID: 11, Status: "running", Bundle: otherBundle},
	}}}
	states, err := handler.List(context.Background())
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, "sbox-runc", states[0].ID)
	assert.Equal(t, SandboxStatusRunning, states[0].Status)
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
	handler := &RuncHandler{sandboxRoot: root}
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
	handler := &RuncHandler{sandboxRoot: root}
	_, err := handler.Wait(context.Background(), "sbox-failed")
	assert.EqualError(t, err, "invalid OCI spec")
}

type fakeRuncClient struct {
	states    []runcapi.State
	state     runcapi.State
	stateErr  error
	killErr   error
	deleteErr error
}

func (f *fakeRuncClient) List(context.Context) ([]runcapi.State, error) {
	return f.states, nil
}

func (f *fakeRuncClient) State(context.Context, string) (runcapi.State, error) {
	return f.state, f.stateErr
}

func (f *fakeRuncClient) Kill(context.Context, string, string, bool) error {
	return f.killErr
}

func (f *fakeRuncClient) Delete(context.Context, string, bool) error {
	return f.deleteErr
}
