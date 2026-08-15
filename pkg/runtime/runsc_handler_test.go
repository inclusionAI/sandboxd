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
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
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
}

func (l staticOciLoader) GenerateOci(OciLoadOptions) (string, *Spec, error) {
	return l.bundlePath, l.spec, nil
}

type successfulRunscClient struct{}

func (successfulRunscClient) Create(context.Context, runscapi.StartArgs) error { return nil }
func (successfulRunscClient) Start(context.Context, runscapi.StartArgs) error  { return nil }
func (successfulRunscClient) Wait(context.Context, string) (int, error)        { return 0, nil }
func (successfulRunscClient) Delete(context.Context, string, bool) error       { return nil }
func (successfulRunscClient) ListJSON(context.Context) ([]byte, error)         { return []byte("[]"), nil }

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
