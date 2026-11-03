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

package runsc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
)

func TestNewRunscHandlerUsesSharedLogFile(t *testing.T) {
	baseDir := t.TempDir()
	rootDir := filepath.Join(baseDir, "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(baseDir, "filestore")
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client, ok := handler.runsc.(*Client)
	if !ok {
		t.Fatalf("runsc client has unexpected type %T", handler.runsc)
	}
	assert.Equal(t, filepath.Join(baseDir, "logs", config.RuntimeNameRunsc, "runsc.log"), client.Options.DebugLogPath)
	assert.Equal(t, config.RunscPlatformSystrap, client.Options.Platform)
}

func TestNewRunscHandlerPropagatesCheckpointOptions(t *testing.T) {
	for _, mode := range []string{"full", "reflink"} {
		for _, background := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode=%s/background=%t", mode, background), func(t *testing.T) {
				base := t.TempDir()
				cfg := config.Config{RootDir: filepath.Join(base, "sandboxd", "root")}
				cfg.RuntimeConfig.FilestoreDir = filepath.Join(base, "filestore")
				cfg.RuntimeConfig.Runsc.CheckpointMode = mode
				cfg.RuntimeConfig.Runsc.BackgroundRestore = background
				handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
				if !assert.NoError(t, err) {
					return
				}
				client := handler.runsc.(*Client)
				assert.Equal(t, background, client.Options.BackgroundRestore)
				assert.Equal(t, mode == "reflink", client.Options.ReflinkFilestores)
			})
		}
	}
}

func TestNewRunscHandlerPropagatesIgnoreCgroups(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.DisableCgroup = true
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(t.TempDir(), "filestore")
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client := handler.runsc.(*Client)
	assert.True(t, client.Options.IgnoreCgroups)
}

func TestNewRunscHandlerPropagatesKVMPlatform(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(t.TempDir(), "filestore")
	cfg.RuntimeConfig.Runsc.Platform = config.RunscPlatformKVM
	cfg.RuntimeConfig.Runsc.ExtraArgs = []string{"--net-raw=true", "--allow-packet-socket-write=true"}
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client := handler.runsc.(*Client)
	assert.Equal(t, config.RunscPlatformKVM, client.Options.Platform)
	assert.Equal(t, cfg.RuntimeConfig.Runsc.ExtraArgs, client.Options.ExtraArgs)
}

func TestNewRunscHandlerRejectsInvalidPlatform(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(t.TempDir(), "filestore")
	cfg.RuntimeConfig.Runsc.Platform = "ptrace"
	_, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.ErrorContains(t, err, "runsc platform must be")
}

func TestNewRunscHandlerRejectsMissingFilestore(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	_, err := NewHandler(config.Config{RootDir: rootDir}, "/usr/local/bin/runsc", nil)
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

	handler := &Handler{
		runsc:                  successfulRunscClient{},
		ociLoader:              staticOciLoader{bundlePath: bundlePath, spec: &runtimecore.Spec{Root: &runtimecore.Root{Path: t.TempDir()}}},
		rootfsOverlayTmpfsSize: "10G",
		filestoreDir:           t.TempDir(),
		sandboxRoot:            bundleRoot,
		mountEROFS:             mountRunscNVProxyEROFSImage,
	}
	err := handler.Start(context.Background(), runtimecore.StartConfig{
		ID:          "sbox-generic-updates",
		Network:     &networkmanager.NetResource{},
		SpecUpdates: &runtimecore.SpecUpdates{Annotations: map[string]string{"example": "value"}},
	})
	assert.NoError(t, err)
}

func TestRunscHandlerMountsRootfsImageForNVProxy(t *testing.T) {
	bundleRoot := t.TempDir()
	rootfsImage := filepath.Join(t.TempDir(), "rootfs.img")
	assert.NoError(t, os.WriteFile(rootfsImage, []byte("erofs-placeholder"), 0644))

	loader, err := runtimecore.NewBundleLoader("", bundleRoot)
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

	handler := &Handler{
		runsc:                  successfulRunscClient{},
		ociLoader:              loader,
		rootfsOverlayTmpfsSize: "10G",
		filestoreDir:           t.TempDir(),
		sandboxRoot:            bundleRoot,
		mountEROFS:             mountRunscNVProxyEROFSImage,
	}
	err = handler.Start(context.Background(), runtimecore.StartConfig{
		ID:         "sbox-rootfs-image",
		Rootfs:     rootfsImage,
		CgroupPath: "/akernel/sbox-rootfs-image",
		Network:    &networkmanager.NetResource{},
		Resources:  &runtimeapi.LinuxSandboxResources{},
		SpecUpdates: &runtimecore.SpecUpdates{
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
	spec       *runtimecore.Spec
}

func (l staticOciLoader) GenerateOci(runtimecore.OciLoadOptions) (string, *runtimecore.Spec, error) {
	return l.bundlePath, l.spec, nil
}

type successfulRunscClient struct{}

func (successfulRunscClient) Create(context.Context, StartArgs) error { return nil }
func (successfulRunscClient) Start(context.Context, StartArgs) error  { return nil }
func (successfulRunscClient) Checkpoint(context.Context, string, string, bool, bool) error {
	return nil
}
func (successfulRunscClient) Restore(context.Context, StartArgs, string) error {
	return nil
}
func (successfulRunscClient) Wait(context.Context, string) (int, error)  { return 0, nil }
func (successfulRunscClient) Delete(context.Context, string, bool) error { return nil }
func (successfulRunscClient) ListJSON(context.Context) ([]byte, error)   { return []byte("[]"), nil }

func TestRunscHandlerResolvesWritableLayerOverlay(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = "/home/akernel/xfs"
	cfg.RuntimeConfig.OverlayTmpfsSize = "10G"
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
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

// Checkpoint dependencies must outlive the source bundle and remain reusable.
func TestManagedHostsCheckpointDependencies(t *testing.T) {
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	bundles, lower := t.TempDir(), t.TempDir()
	check(os.Mkdir(filepath.Join(lower, "etc"), 0755))
	fixture := func(id string) (*Handler, runtimecore.StartConfig, string) {
		t.Helper()
		bundle := filepath.Join(bundles, id)
		check(os.Mkdir(bundle, 0755))
		h := &Handler{
			runsc: successfulRunscClient{}, sandboxRoot: bundles, filestoreDir: t.TempDir(),
			ociLoader: staticOciLoader{bundlePath: bundle, spec: &runtimecore.Spec{Root: &runtimecore.Root{Path: lower}}},
		}
		start := runtimecore.StartConfig{
			ID: id, Network: &networkmanager.NetResource{},
			ManagedHosts: &runtimecore.ManagedHostsState{Version: runtimecore.ManagedHostsVersion, Runtime: "runsc", Layout: runtimecore.HostsLayoutPrivateRootfs},
			InitialFiles: []runtimecore.InitialFile{{Path: "/etc/hosts", Content: []byte("initial-host\n"), Mode: 0644}},
		}
		return h, start, bundle
	}
	h, start, bundle := fixture("source")
	check(h.Start(ctx, start))
	assert.Nil(t, start.ManagedHosts.Seed, "Start must not mutate caller state")
	original, err := runtimecore.ReadManagedHostsState(bundle)
	check(err)
	seed, err := readHostsSeed(bundle, original)
	check(err)
	checkpoint := filepath.Join(t.TempDir(), "first")
	// A replacement Handler must recover all initialization state from disk.
	restarted := &Handler{runsc: successfulRunscClient{}, sandboxRoot: bundles}
	check(restarted.Checkpoint(ctx, runtimecore.CheckpointConfig{ID: start.ID, Directory: checkpoint}))
	saved, err := runtimecore.ReadManagedHostsState(checkpoint)
	check(err)
	assert.Equal(t, original, saved)
	check(os.RemoveAll(bundle))

	target, restore, targetBundle := fixture("target")
	restore.InitialFiles, restore.ManagedHosts, restore.CheckpointDir = nil, nil, checkpoint
	check(target.Restore(ctx, restore))
	restored, err := runtimecore.ReadManagedHostsState(targetBundle)
	check(err)
	assert.Equal(t, saved, restored)
	restoredSeed, err := readHostsSeed(targetBundle, restored)
	check(err)
	assert.Equal(t, seed, restoredSeed, "Restore must copy the saved seed without initialization")
	second := filepath.Join(t.TempDir(), "second")
	check(restarted.Checkpoint(ctx, runtimecore.CheckpointConfig{ID: restore.ID, Directory: second}))
	repeated, err := runtimecore.ReadManagedHostsState(second)
	check(err)
	assert.Equal(t, saved, repeated)
	repeatedSeed, err := readHostsSeed(second, repeated)
	check(err)
	assert.Equal(t, seed, repeatedSeed)

	check(os.WriteFile(filepath.Join(checkpoint, runtimecore.RootfsSeedName), []byte("corrupted"), 0600))
	rejected, badRestore, rejectedBundle := fixture("rejected")
	badRestore.InitialFiles, badRestore.ManagedHosts, badRestore.CheckpointDir = nil, nil, checkpoint
	assert.ErrorContains(t, rejected.Restore(ctx, badRestore), "SHA-256 mismatch")
	_, err = os.Lstat(filepath.Join(rejectedBundle, runtimecore.RootfsSeedName))
	assert.ErrorIs(t, err, os.ErrNotExist, "failed restore must not leave seed artifacts")
}
