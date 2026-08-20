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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/physicalstate"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runscapi "github.com/inclusionAI/sandboxd/pkg/runtime/runsc"
	"github.com/stretchr/testify/assert"
)

func TestNewRunscHandlerUsesSharedLogFile(t *testing.T) {
	baseDir := t.TempDir()
	rootDir := filepath.Join(baseDir, "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(baseDir, "filestore")
	handler, err := NewRunscHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client, ok := handler.runsc.(*runscapi.Client)
	if !ok {
		t.Fatalf("runsc client has unexpected type %T", handler.runsc)
	}
	assert.Equal(t, filepath.Join(baseDir, "logs", config.RuntimeNameRunsc, "runsc.log"), client.Options.DebugLogPath)
}

func TestNewRunscHandlerPropagatesIgnoreCgroups(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.DisableCgroup = true
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(t.TempDir(), "filestore")
	handler, err := NewRunscHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client := handler.runsc.(*runscapi.Client)
	assert.True(t, client.Options.IgnoreCgroups)
}

func TestNewRunscHandlerRejectsMissingFilestore(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	_, err := NewRunscHandler(config.Config{RootDir: rootDir}, "/usr/local/bin/runsc", nil)
	assert.ErrorContains(t, err, "plugin.runtime.filestore_dir")
}

func TestRunscHandlerDoesNotPrepareNVProxyRootfsForGenericSpecUpdates(t *testing.T) {
	bundleRoot := t.TempDir()
	bundlePath := filepath.Join(bundleRoot, "sbox-generic-updates")
	assert.NoError(t, os.MkdirAll(bundlePath, 0755))

	originalMount := mountRunscNVProxyOverlay
	t.Cleanup(func() { mountRunscNVProxyOverlay = originalMount })
	mountRunscNVProxyOverlay = func(_, _, _, _ string) error {
		return errors.New("unexpected nvproxy overlay")
	}

	handler := &RunscHandler{
		runsc:                  successfulRunscClient{},
		ociLoader:              staticOciLoader{bundlePath: bundlePath, spec: &Spec{Root: &Root{Path: t.TempDir()}}},
		rootfsOverlayTmpfsSize: "10G",
		filestoreDir:           t.TempDir(),
		sandboxRoot:            bundleRoot,
		mountEROFS:             mountRunscNVProxyEROFSImage,
	}
	err := handler.Start(context.Background(), StartConfig{
		ID:          "sbox-generic-updates",
		Network:     &networkmanager.NetResource{},
		SpecUpdates: &SpecUpdates{Annotations: map[string]string{"example": "value"}},
	})
	assert.NoError(t, err)
}

func TestRunscHandlerMountsRootfsImageForNVProxy(t *testing.T) {
	bundleRoot := t.TempDir()
	rootfsImage := filepath.Join(t.TempDir(), "rootfs.img")
	assert.NoError(t, os.WriteFile(rootfsImage, []byte("erofs-placeholder"), 0644))

	loader, err := NewBundleLoader("", bundleRoot)
	assert.NoError(t, err)

	originalMount := mountRunscNVProxyOverlay
	originalImageMount := mountRunscNVProxyEROFSImage
	originalUnmount := unmountRunscNVProxyPath
	t.Cleanup(func() {
		mountRunscNVProxyOverlay = originalMount
		mountRunscNVProxyEROFSImage = originalImageMount
		unmountRunscNVProxyPath = originalUnmount
	})
	var lowerDir string
	mountRunscNVProxyOverlay = func(lower, _, _, _ string) error {
		lowerDir = lower
		return nil
	}
	var mountedImage, mountedImageTarget string
	mountRunscNVProxyEROFSImage = func(source, target string) error {
		mountedImage, mountedImageTarget = source, target
		return nil
	}
	unmountRunscNVProxyPath = func(string, int) error { return syscall.EINVAL }

	handler := &RunscHandler{
		runsc:                  successfulRunscClient{},
		ociLoader:              loader,
		rootfsOverlayTmpfsSize: "10G",
		filestoreDir:           t.TempDir(),
		sandboxRoot:            bundleRoot,
		mountEROFS:             mountRunscNVProxyEROFSImage,
	}
	err = handler.Start(context.Background(), StartConfig{
		ID:         "sbox-rootfs-image",
		Rootfs:     rootfsImage,
		CgroupPath: "/akernel/sbox-rootfs-image",
		Network:    &networkmanager.NetResource{},
		Resources:  &runtimeapi.LinuxSandboxResources{},
		SpecUpdates: &SpecUpdates{
			RequiresHostWritableRootfs: true,
		},
	})
	assert.NoError(t, err)
	expectedLower := filepath.Join(bundleRoot, "sbox-rootfs-image", runscNVProxyLowerDir)
	assert.Equal(t, rootfsImage, mountedImage)
	assert.Equal(t, expectedLower, mountedImageTarget)
	assert.Equal(t, expectedLower, lowerDir)
}

type staticOciLoader struct {
	bundlePath string
	spec       *Spec
	onGenerate func(OciLoadOptions)
}

func (l staticOciLoader) GenerateOci(options OciLoadOptions) (string, *Spec, error) {
	if l.onGenerate != nil {
		l.onGenerate(options)
	}
	return l.bundlePath, l.spec, nil
}

type successfulRunscClient struct{}

func (successfulRunscClient) Create(context.Context, runscapi.StartArgs) error { return nil }
func (successfulRunscClient) Start(context.Context, runscapi.StartArgs) error  { return nil }
func (successfulRunscClient) Checkpoint(context.Context, string, string, bool) error {
	return nil
}
func (successfulRunscClient) Restore(context.Context, runscapi.StartArgs, string) error {
	return nil
}
func (successfulRunscClient) Wait(context.Context, string) (int, error)  { return 0, nil }
func (successfulRunscClient) Delete(context.Context, string, bool) error { return nil }
func (successfulRunscClient) ListJSON(context.Context) ([]byte, error)   { return []byte("[]"), nil }

type listJSONRunscClient struct {
	successfulRunscClient
	states []State
}

func (c listJSONRunscClient) ListJSON(context.Context) ([]byte, error) {
	return json.Marshal(c.states)
}

func TestRunscHandlerListRejectsStaleRunningProcessFacts(t *testing.T) {
	handler := &RunscHandler{runsc: listJSONRunscClient{states: []State{
		{ID: "sbox-missing", InitProcessPid: 1 << 30, Status: SandboxStatusRunning},
		{ID: "sbox-wrong-process", InitProcessPid: os.Getpid(), Status: SandboxStatusRunning},
	}}}

	states, err := handler.List(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, SandboxStatusExited, states[0].Status)
	assert.Equal(t, SandboxStatusExited, states[1].Status)
}

func TestRunscHandlerListRetainsMatchingLiveSandboxProcess(t *testing.T) {
	process := exec.Command("/bin/sh")
	process.Args = []string{"runsc-sandbox", "-c", "sleep 30 & wait", "sbox-live"}
	assert.NoError(t, process.Start())
	t.Cleanup(func() {
		_ = process.Process.Kill()
		_, _ = process.Process.Wait()
	})
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(process.Process.Pid), "cmdline")
	assert.Eventually(t, func() bool {
		cmdline, err := os.ReadFile(cmdlinePath)
		return err == nil && strings.HasPrefix(string(cmdline), "runsc-sandbox\x00") &&
			strings.Contains(string(cmdline), "\x00sbox-live\x00")
	}, time.Second, time.Millisecond)

	handler := &RunscHandler{runsc: listJSONRunscClient{states: []State{{
		ID: "sbox-live", InitProcessPid: process.Process.Pid, Status: SandboxStatusRunning,
	}}}}
	states, err := handler.List(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, SandboxStatusRunning, states[0].Status)
}

func TestRunscHandlerListRejectsZombieSandboxProcess(t *testing.T) {
	process := exec.Command("/bin/sh")
	process.Args = []string{"runsc-sandbox", "-c", "exit 0", "sbox-zombie"}
	assert.NoError(t, process.Start())
	t.Cleanup(func() { _, _ = process.Process.Wait() })

	statPath := filepath.Join("/proc", strconv.Itoa(process.Process.Pid), "stat")
	assert.Eventually(t, func() bool {
		stat, err := os.ReadFile(statPath)
		return err == nil && strings.Contains(string(stat), ") Z ")
	}, time.Second, time.Millisecond)

	handler := &RunscHandler{runsc: listJSONRunscClient{states: []State{{
		ID: "sbox-zombie", InitProcessPid: process.Process.Pid, Status: SandboxStatusRunning,
	}}}}
	states, err := handler.List(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, SandboxStatusExited, states[0].Status)
}

type checkpointWritingRunscClient struct {
	successfulRunscClient
	checkpointDir *string
}

func (c checkpointWritingRunscClient) Restore(
	context.Context, runscapi.StartArgs, string,
) error {
	return os.WriteFile(filepath.Join(*c.checkpointDir, "checkpoint.img"), []byte("transient"), 0600)
}

type checkpointRemovalFailureRunscClient struct {
	successfulRunscClient
	checkpointDir *string
	deleteErrors  []error
	deleteCalls   int
}

func (c *checkpointRemovalFailureRunscClient) Restore(
	context.Context, runscapi.StartArgs, string,
) error {
	imagePath := filepath.Join(*c.checkpointDir, gvisorCheckpointImageName)
	if err := os.Mkdir(imagePath, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(imagePath, "entry"), []byte("busy"), 0600)
}

func (c *checkpointRemovalFailureRunscClient) Delete(context.Context, string, bool) error {
	index := c.deleteCalls
	c.deleteCalls++
	if index >= len(c.deleteErrors) {
		return nil
	}
	return c.deleteErrors[index]
}

func newRunscRestoreTestHandler(t *testing.T) (*RunscHandler, *string) {
	t.Helper()
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	bundleRoot := filepath.Join(rootDir, "containers")
	bundlePath := filepath.Join(bundleRoot, "sbox-restored")
	assert.NoError(t, os.MkdirAll(bundlePath, 0755))
	checkpointRoot := filepath.Join(rootDir, config.GVisorCheckpointDirName)
	assert.NoError(t, os.MkdirAll(checkpointRoot, 0700))

	var checkpointDir string
	handler := &RunscHandler{
		ociLoader: staticOciLoader{
			bundlePath: bundlePath,
			spec:       &Spec{Root: &Root{Path: t.TempDir()}},
			onGenerate: func(options OciLoadOptions) {
				checkpointDir = options.ManagedAnnotations[config.GVisorCheckpointPathAnnotation]
				spec := &Spec{
					Root:        &Root{Path: t.TempDir()},
					Annotations: options.ManagedAnnotations,
				}
				content, err := json.Marshal(spec)
				assert.NoError(t, err)
				assert.NoError(t, os.WriteFile(
					filepath.Join(bundlePath, config.SandboxSpecFile), content, 0600,
				))
			},
		},
		rootfsOverlayTmpfsSize: "10G",
		filestoreDir:           t.TempDir(),
		sandboxRoot:            bundleRoot,
		checkpointRoot:         checkpointRoot,
	}
	return handler, &checkpointDir
}

func TestRunscHandlerRestoreRemovesTransientCoordinationImage(t *testing.T) {
	handler, checkpointDir := newRunscRestoreTestHandler(t)
	handler.runsc = checkpointWritingRunscClient{checkpointDir: checkpointDir}

	err := handler.Restore(context.Background(), StartConfig{
		ID:      "sbox-restored",
		Network: &networkmanager.NetResource{},
	}, filepath.Join(t.TempDir(), "source-checkpoint.img"))

	assert.NoError(t, err)
	assert.DirExists(t, *checkpointDir, "future checkpoints still need the coordination directory")
	assert.NoFileExists(t, filepath.Join(*checkpointDir, "checkpoint.img"))
	assert.NoError(t, os.WriteFile(
		filepath.Join(*checkpointDir, "checkpoint.img"), []byte("next checkpoint"), 0600,
	))
	assert.FileExists(t, filepath.Join(*checkpointDir, "checkpoint.img"))
}

func TestRunscHandlerDeleteCleansPreparedStateWhenRuntimeIsAbsent(t *testing.T) {
	handler, checkpointDir := newRunscRestoreTestHandler(t)
	handler.runsc = checkpointWritingRunscClient{checkpointDir: checkpointDir}
	assert.NoError(t, handler.Restore(context.Background(), StartConfig{
		ID:      "sbox-restored",
		Network: &networkmanager.NetResource{},
	}, filepath.Join(t.TempDir(), "source-checkpoint.img")))
	assert.NoError(t, os.WriteFile(
		filepath.Join(*checkpointDir, gvisorCheckpointImageName), []byte("orphan"), 0600,
	))
	err := handler.Delete(context.Background(), "sbox-restored")

	assert.NoError(t, err)
	assert.NoDirExists(t, *checkpointDir)
}

func TestRunscHandlerRestoreCleanupRemovesPreparedStateAfterDelete(t *testing.T) {
	handler, checkpointDir := newRunscRestoreTestHandler(t)
	client := &checkpointRemovalFailureRunscClient{
		checkpointDir: checkpointDir,
		deleteErrors:  []error{nil},
	}
	handler.runsc = client

	err := handler.Restore(context.Background(), StartConfig{
		ID:      "sbox-restored",
		Network: &networkmanager.NetResource{},
	}, filepath.Join(t.TempDir(), "source-checkpoint.img"))

	assert.ErrorContains(t, err, "remove restored gVisor checkpoint image")
	assert.NotErrorIs(t, err, physicalstate.ErrRestoreCleanupIncomplete)
	assert.Equal(t, 1, client.deleteCalls)
	assert.NoDirExists(t, *checkpointDir)
}

func TestRunscHandlerRestoreCleanupRetriesBeforeRemovingPreparedState(t *testing.T) {
	handler, checkpointDir := newRunscRestoreTestHandler(t)
	client := &checkpointRemovalFailureRunscClient{
		checkpointDir: checkpointDir,
		deleteErrors:  []error{errors.New("delete temporarily unavailable"), nil},
	}
	handler.runsc = client

	err := handler.Restore(context.Background(), StartConfig{
		ID:      "sbox-restored",
		Network: &networkmanager.NetResource{},
	}, filepath.Join(t.TempDir(), "source-checkpoint.img"))

	assert.ErrorContains(t, err, "remove restored gVisor checkpoint image")
	assert.NotErrorIs(t, err, physicalstate.ErrRestoreCleanupIncomplete)
	assert.Equal(t, 2, client.deleteCalls)
	assert.NoDirExists(t, *checkpointDir)
}

func TestRunscHandlerRestoreCleanupPreservesPreparedStateWhenDeleteFails(t *testing.T) {
	handler, checkpointDir := newRunscRestoreTestHandler(t)
	deleteErr := errors.New("delete permanently unavailable")
	client := &checkpointRemovalFailureRunscClient{
		checkpointDir: checkpointDir,
		deleteErrors:  []error{deleteErr, deleteErr, deleteErr},
	}
	handler.runsc = client

	err := handler.Restore(context.Background(), StartConfig{
		ID:      "sbox-restored",
		Network: &networkmanager.NetResource{},
	}, filepath.Join(t.TempDir(), "source-checkpoint.img"))

	assert.ErrorContains(t, err, "remove restored gVisor checkpoint image")
	assert.ErrorContains(t, err, "delete permanently unavailable")
	assert.ErrorIs(t, err, physicalstate.ErrRestoreCleanupIncomplete)
	assert.Equal(t, runscFailureCleanupRetries, client.deleteCalls)
	assert.DirExists(t, *checkpointDir)
	assert.DirExists(t, filepath.Join(*checkpointDir, gvisorCheckpointImageName))
}

func TestRunscHandlerResolvesWritableLayerOverlay(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = "/home/akernel/xfs"
	cfg.RuntimeConfig.OverlayTmpfsSize = "10G"
	handler, err := NewRunscHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	overlay, size, err := handler.resolveRootOverlay(2 << 30)
	assert.NoError(t, err)
	assert.Equal(t, "root:dir=/home/akernel/xfs,size=2147483648", overlay)
	assert.Equal(t, "2147483648", size)

	overlay, size, err = handler.resolveRootOverlay(0)
	assert.NoError(t, err)
	assert.Equal(t, "root:dir=/home/akernel/xfs,size=10G", overlay)
	assert.Equal(t, "10G", size)
}
