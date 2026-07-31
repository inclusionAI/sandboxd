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

package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/inclusionAI/sandboxd/config"
)

type panicUncompressedLayer struct {
	digest v1.Hash
}

func (l panicUncompressedLayer) Digest() (v1.Hash, error) {
	return l.digest, nil
}

func (l panicUncompressedLayer) DiffID() (v1.Hash, error) {
	return l.digest, nil
}

func (l panicUncompressedLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (l panicUncompressedLayer) Uncompressed() (io.ReadCloser, error) {
	return nil, fmt.Errorf("unexpected uncompressed call")
}

func (l panicUncompressedLayer) Size() (int64, error) {
	return 0, nil
}

func (l panicUncompressedLayer) MediaType() (types.MediaType, error) {
	return types.OCIUncompressedLayer, nil
}

type sleepLayer struct {
	digest v1.Hash
	delay  time.Duration
}

func (l sleepLayer) Digest() (v1.Hash, error) {
	return l.digest, nil
}

func (l sleepLayer) DiffID() (v1.Hash, error) {
	return l.digest, nil
}

func (l sleepLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (l sleepLayer) Uncompressed() (io.ReadCloser, error) {
	time.Sleep(l.delay)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("layer-data")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "etc/config",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len(content)),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func (l sleepLayer) Size() (int64, error) {
	return 0, nil
}

func (l sleepLayer) MediaType() (types.MediaType, error) {
	return types.OCIUncompressedLayer, nil
}

type observedSleepLayer struct {
	digest    v1.Hash
	delay     time.Duration
	inFlight  *int32
	maxFlight *int32
}

func (l observedSleepLayer) Digest() (v1.Hash, error) {
	return l.digest, nil
}

func (l observedSleepLayer) DiffID() (v1.Hash, error) {
	return l.digest, nil
}

func (l observedSleepLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (l observedSleepLayer) Uncompressed() (io.ReadCloser, error) {
	cur := atomic.AddInt32(l.inFlight, 1)
	for {
		prev := atomic.LoadInt32(l.maxFlight)
		if cur <= prev || atomic.CompareAndSwapInt32(l.maxFlight, prev, cur) {
			break
		}
	}
	defer atomic.AddInt32(l.inFlight, -1)

	time.Sleep(l.delay)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("layer-data")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "etc/config",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len(content)),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func (l observedSleepLayer) Size() (int64, error) {
	return 0, nil
}

func (l observedSleepLayer) MediaType() (types.MediaType, error) {
	return types.OCIUncompressedLayer, nil
}

type blockLayer struct {
	digest  v1.Hash
	started chan<- struct{}
	unblock <-chan struct{}
}

func (l blockLayer) Digest() (v1.Hash, error) {
	return l.digest, nil
}

func (l blockLayer) DiffID() (v1.Hash, error) {
	return l.digest, nil
}

func (l blockLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (l blockLayer) Uncompressed() (io.ReadCloser, error) {
	select {
	case l.started <- struct{}{}:
	default:
	}
	<-l.unblock

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("layer-data")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "etc/config",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len(content)),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func (l blockLayer) Size() (int64, error) {
	return 0, nil
}

func (l blockLayer) MediaType() (types.MediaType, error) {
	return types.OCIUncompressedLayer, nil
}

type errorLayer struct {
	digest v1.Hash
	err    error
}

func (l errorLayer) Digest() (v1.Hash, error) {
	return l.digest, nil
}

func (l errorLayer) DiffID() (v1.Hash, error) {
	return l.digest, nil
}

func (l errorLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (l errorLayer) Uncompressed() (io.ReadCloser, error) {
	if l.err != nil {
		return nil, l.err
	}
	return nil, fmt.Errorf("error layer")
}

func (l errorLayer) Size() (int64, error) {
	return 0, nil
}

func (l errorLayer) MediaType() (types.MediaType, error) {
	return types.OCIUncompressedLayer, nil
}

func TestExtractLayerTar_HandlesOCIWhiteouts(t *testing.T) {
	dst := t.TempDir()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	writeDir := func(name string) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
			t.Fatalf("write dir %s: %v", name, err)
		}
	}
	writeReg := func(name, content string) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(content))}); err != nil {
			t.Fatalf("write file header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write file body %s: %v", name, err)
		}
	}

	writeDir("etc")
	writeReg("etc/config", "v1")
	writeReg("etc/.wh.config", "")
	writeDir("var")
	writeReg("var/.wh..wh..opq", "")

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}

	if _, err := extractLayerTar(bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("extractLayerTar() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dst, "etc", ".wh.config")); !os.IsNotExist(err) {
		t.Fatalf(".wh.config should not exist as plain whiteout marker, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "etc", "config")); err != nil {
		t.Fatalf("whiteout target should exist after conversion, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "var", ".wh..wh..opq")); !os.IsNotExist(err) {
		t.Fatalf(".wh..wh..opq should not exist as plain file, err=%v", err)
	}
}

func TestExtractLayerTar_PreservesModeRegardlessOfUmask(t *testing.T) {
	dst := t.TempDir()

	oldUmask := syscall.Umask(0077)
	defer syscall.Umask(oldUmask)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := tw.WriteHeader(&tar.Header{
		Name:     "bin",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("write dir header: %v", err)
	}

	content := []byte("echo test\n")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "bin/run.sh",
		Typeflag: tar.TypeReg,
		Mode:     0777,
		Size:     int64(len(content)),
	}); err != nil {
		t.Fatalf("write file header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write file content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}

	if _, err := extractLayerTar(bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("extractLayerTar() error: %v", err)
	}

	dirInfo, err := os.Stat(filepath.Join(dst, "bin"))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got, want := dirInfo.Mode().Perm(), os.FileMode(0755); got != want {
		t.Fatalf("dir mode mismatch: got %04o want %04o", got, want)
	}

	fileInfo, err := os.Stat(filepath.Join(dst, "bin", "run.sh"))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got, want := fileInfo.Mode().Perm(), os.FileMode(0777); got != want {
		t.Fatalf("file mode mismatch: got %04o want %04o", got, want)
	}
}

func TestReconcileState_FixesMountAndLayerRefs(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	layer1Path := filepath.Join(mgr.layersDir, "sha256_a", "fs")
	layer2Path := filepath.Join(mgr.layersDir, "sha256_b", "fs")
	if err := os.MkdirAll(layer1Path, 0755); err != nil {
		t.Fatalf("mkdir layer1: %v", err)
	}
	if err := os.MkdirAll(layer2Path, 0755); err != nil {
		t.Fatalf("mkdir layer2: %v", err)
	}

	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:a", Path: layer1Path, RefCount: 0}); err != nil {
		t.Fatalf("put layer1: %v", err)
	}
	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:b", Path: layer2Path, RefCount: 99}); err != nil {
		t.Fatalf("put layer2: %v", err)
	}

	mountPath := filepath.Join(mgr.mountsDir, "mount-1", "merged")
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		t.Fatalf("mkdir mount path: %v", err)
	}
	if err := mgr.store.putMount(&OciMountRecord{
		ImageURL:     "docker.io/library/alpine:latest",
		MountID:      "mount-1",
		MountPath:    mountPath,
		LayerDigests: []string{"sha256:a", "sha256:b"},
	}); err != nil {
		t.Fatalf("put mount: %v", err)
	}

	mgr.readMnts = func() (map[string]struct{}, bool, error) {
		return map[string]struct{}{mountPath: {}}, true, nil
	}

	if err := mgr.reconcileState(); err != nil {
		t.Fatalf("reconcileState() error: %v", err)
	}

	mount, err := mgr.store.getMount("docker.io/library/alpine:latest")
	if err != nil {
		t.Fatalf("get mount: %v", err)
	}
	if mount == nil {
		t.Fatalf("mount should be kept after reconcile")
	}
	if _, ok := mgr.containers["docker.io/library/alpine:latest"]; !ok {
		t.Fatalf("in-memory containers should be restored from DB")
	}

	layer1, err := mgr.store.getLayer("sha256:a")
	if err != nil || layer1 == nil {
		t.Fatalf("get layer1 failed: err=%v", err)
	}
	layer2, err := mgr.store.getLayer("sha256:b")
	if err != nil || layer2 == nil {
		t.Fatalf("get layer2 failed: err=%v", err)
	}
	if layer1.RefCount != 1 || layer2.RefCount != 1 {
		t.Fatalf("layer refcounts not fixed, got %d and %d", layer1.RefCount, layer2.RefCount)
	}
}

func TestReconcileState_FixesChainRefsForRecoveredMount(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	layer1Path := filepath.Join(mgr.layersDir, "sha256_chain_a", "fs")
	layer2Path := filepath.Join(mgr.layersDir, "sha256_chain_b", "fs")
	chain1Path := filepath.Join(mgr.chainsDir, "c1", "fs")
	chain2Path := filepath.Join(mgr.chainsDir, "c2", "fs")
	for _, path := range []string{layer1Path, layer2Path, chain1Path, chain2Path} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}

	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:a", Path: layer1Path, RefCount: 0}); err != nil {
		t.Fatalf("put layer1: %v", err)
	}
	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:b", Path: layer2Path, RefCount: 99}); err != nil {
		t.Fatalf("put layer2: %v", err)
	}
	if err := mgr.store.putChain(&ChainRecord{ChainID: "sha256:c1", Path: chain1Path, RefCount: 0}); err != nil {
		t.Fatalf("put chain1: %v", err)
	}
	if err := mgr.store.putChain(&ChainRecord{ChainID: "sha256:c2", Path: chain2Path, RefCount: 99}); err != nil {
		t.Fatalf("put chain2: %v", err)
	}

	mountPath := filepath.Join(mgr.mountsDir, "mount-chain", "merged")
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		t.Fatalf("mkdir mount path: %v", err)
	}
	if err := mgr.store.putMount(&OciMountRecord{
		ImageURL:     "docker.io/library/alpine:chain",
		MountID:      "mount-chain",
		MountPath:    mountPath,
		LayerDigests: []string{"sha256:a", "sha256:b"},
		ChainIDs:     []string{"sha256:c1", "sha256:c2"},
		LowerDirs:    []string{chain2Path, chain1Path},
	}); err != nil {
		t.Fatalf("put mount: %v", err)
	}

	mgr.readMnts = func() (map[string]struct{}, bool, error) {
		return map[string]struct{}{mountPath: {}}, true, nil
	}

	if err := mgr.reconcileState(); err != nil {
		t.Fatalf("reconcileState() error: %v", err)
	}

	mount, err := mgr.store.getMount("docker.io/library/alpine:chain")
	if err != nil {
		t.Fatalf("get mount: %v", err)
	}
	if mount == nil {
		t.Fatalf("mount should be kept after reconcile")
	}
	if len(mount.ChainIDs) != 2 || mount.ChainIDs[0] != "sha256:c1" || mount.ChainIDs[1] != "sha256:c2" {
		t.Fatalf("mount chain ids not preserved, got %+v", mount.ChainIDs)
	}
	info, ok := mgr.containers["docker.io/library/alpine:chain"]
	if !ok {
		t.Fatalf("in-memory containers should be restored from DB")
	}
	if len(info.ChainIDs) != 2 || info.ChainIDs[0] != "sha256:c1" || info.ChainIDs[1] != "sha256:c2" {
		t.Fatalf("in-memory chain ids not restored, got %+v", info.ChainIDs)
	}

	chain1, err := mgr.store.getChain("sha256:c1")
	if err != nil || chain1 == nil {
		t.Fatalf("get chain1 failed: err=%v", err)
	}
	chain2, err := mgr.store.getChain("sha256:c2")
	if err != nil || chain2 == nil {
		t.Fatalf("get chain2 failed: err=%v", err)
	}
	if chain1.RefCount != 1 || chain2.RefCount != 1 {
		t.Fatalf("chain refcounts not fixed, got %d and %d", chain1.RefCount, chain2.RefCount)
	}
}

func TestReconcileState_DropsPersistedMountWhenMountMissing(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	layerPath := filepath.Join(mgr.layersDir, "sha256_stale_mount", "fs")
	if err := os.MkdirAll(layerPath, 0755); err != nil {
		t.Fatalf("mkdir layer path: %v", err)
	}
	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:stale-mount", Path: layerPath, RefCount: 0}); err != nil {
		t.Fatalf("put layer: %v", err)
	}

	mountPath := filepath.Join(mgr.mountsDir, "stale-mount", "merged")
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		t.Fatalf("mkdir mount path: %v", err)
	}
	if err := mgr.store.putMount(&OciMountRecord{
		ImageURL:     "docker.io/library/alpine:stale-mount",
		MountID:      "stale-mount",
		MountPath:    mountPath,
		LayerDigests: []string{"sha256:stale-mount"},
	}); err != nil {
		t.Fatalf("put mount: %v", err)
	}

	mgr.readMnts = func() (map[string]struct{}, bool, error) {
		return map[string]struct{}{}, true, nil
	}

	if err := mgr.reconcileState(); err != nil {
		t.Fatalf("reconcileState() error: %v", err)
	}

	mount, err := mgr.store.getMount("docker.io/library/alpine:stale-mount")
	if err != nil {
		t.Fatalf("get mount: %v", err)
	}
	if mount != nil {
		t.Fatalf("stale persisted mount should be removed when no live mount exists")
	}
	if _, ok := mgr.containers["docker.io/library/alpine:stale-mount"]; ok {
		t.Fatalf("stale persisted mount should not be restored in memory")
	}
}

func TestGCLayersByDiskPressure_RemovesUnreferencedLayers(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	layer0Path := filepath.Join(mgr.layersDir, "sha256_unused", "fs")
	layer1Path := filepath.Join(mgr.layersDir, "sha256_used", "fs")
	if err := os.MkdirAll(layer0Path, 0755); err != nil {
		t.Fatalf("mkdir layer0: %v", err)
	}
	if err := os.MkdirAll(layer1Path, 0755); err != nil {
		t.Fatalf("mkdir layer1: %v", err)
	}

	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:unused", Path: layer0Path, RefCount: 0, LastUsedUnix: 1}); err != nil {
		t.Fatalf("put layer0: %v", err)
	}
	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:used", Path: layer1Path, RefCount: 1, LastUsedUnix: 2}); err != nil {
		t.Fatalf("put layer1: %v", err)
	}

	calls := 0
	mgr.diskUsage = func(string) (float64, error) {
		calls++
		if calls == 1 {
			return 0.9, nil
		}
		return 0.7, nil
	}

	if err := mgr.gcLayersByDiskPressure(); err != nil {
		t.Fatalf("gcLayersByDiskPressure() error: %v", err)
	}

	unused, err := mgr.store.getLayer("sha256:unused")
	if err != nil {
		t.Fatalf("get unused layer: %v", err)
	}
	if unused != nil {
		t.Fatalf("unused layer should be deleted by gc")
	}
	used, err := mgr.store.getLayer("sha256:used")
	if err != nil {
		t.Fatalf("get used layer: %v", err)
	}
	if used == nil {
		t.Fatalf("used layer should remain")
	}
}

func TestGCChainsByDiskPressure_RemovesUnreferencedLowerdirs(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	chain0Path := filepath.Join(mgr.chainsDir, "c-unused", "fs")
	chain1Path := filepath.Join(mgr.chainsDir, "c-used", "fs")
	if err := os.MkdirAll(chain0Path, 0755); err != nil {
		t.Fatalf("mkdir chain0: %v", err)
	}
	if err := os.MkdirAll(chain1Path, 0755); err != nil {
		t.Fatalf("mkdir chain1: %v", err)
	}

	if err := mgr.store.putChain(&ChainRecord{ChainID: "sha256:unused-chain", Path: chain0Path, RefCount: 0, LastUsedUnix: 1}); err != nil {
		t.Fatalf("put chain0: %v", err)
	}
	if err := mgr.store.putChain(&ChainRecord{ChainID: "sha256:used-chain", Path: chain1Path, RefCount: 1, LastUsedUnix: 2}); err != nil {
		t.Fatalf("put chain1: %v", err)
	}

	calls := 0
	mgr.diskUsage = func(string) (float64, error) {
		calls++
		if calls == 1 {
			return 0.9, nil
		}
		return 0.7, nil
	}

	if err := mgr.gcChainsByDiskPressure(); err != nil {
		t.Fatalf("gcChainsByDiskPressure() error: %v", err)
	}

	unused, err := mgr.store.getChain("sha256:unused-chain")
	if err != nil {
		t.Fatalf("get unused chain: %v", err)
	}
	if unused != nil {
		t.Fatalf("unused chain should be deleted by gc")
	}
	used, err := mgr.store.getChain("sha256:used-chain")
	if err != nil {
		t.Fatalf("get used chain: %v", err)
	}
	if used == nil {
		t.Fatalf("used chain should remain")
	}
}

func TestReconcileState_RecoversMountFromTxn(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	layerPath := filepath.Join(mgr.layersDir, "sha256_txn", "fs")
	if err := os.MkdirAll(layerPath, 0755); err != nil {
		t.Fatalf("mkdir layer: %v", err)
	}
	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:txn", Path: layerPath, RefCount: 0}); err != nil {
		t.Fatalf("put layer: %v", err)
	}

	mountPath := filepath.Join(mgr.mountsDir, "txn-mount", "merged")
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		t.Fatalf("mkdir mount path: %v", err)
	}
	if err := mgr.store.putMountTxn(&OciMountTxnRecord{
		ImageURL:     "docker.io/library/busybox:latest",
		MountID:      "txn-mount",
		MountPath:    mountPath,
		LayerDigests: []string{"sha256:txn"},
	}); err != nil {
		t.Fatalf("put mount txn: %v", err)
	}

	mgr.readMnts = func() (map[string]struct{}, bool, error) {
		return map[string]struct{}{mountPath: {}}, true, nil
	}

	if err := mgr.reconcileState(); err != nil {
		t.Fatalf("reconcileState() error: %v", err)
	}

	mount, err := mgr.store.getMount("docker.io/library/busybox:latest")
	if err != nil {
		t.Fatalf("get mount: %v", err)
	}
	if mount == nil {
		t.Fatalf("mount record should be recovered from txn")
	}
	txn, err := mgr.store.getMountTxn("docker.io/library/busybox:latest")
	if err != nil {
		t.Fatalf("get mount txn: %v", err)
	}
	if txn != nil {
		t.Fatalf("mount txn should be removed after recovery")
	}
	layer, err := mgr.store.getLayer("sha256:txn")
	if err != nil || layer == nil {
		t.Fatalf("get layer: err=%v", err)
	}
	if layer.RefCount != 1 {
		t.Fatalf("recovered mount should set refcount to 1, got %d", layer.RefCount)
	}
}

func TestReconcileState_RecoversMountFromTxnWithChainIDs(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	layerPath := filepath.Join(mgr.layersDir, "sha256_txn_chain", "fs")
	chainPath := filepath.Join(mgr.chainsDir, "c1", "fs")
	for _, path := range []string{layerPath, chainPath} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := mgr.store.putLayer(&LayerRecord{Digest: "sha256:txn-chain", Path: layerPath, RefCount: 0}); err != nil {
		t.Fatalf("put layer: %v", err)
	}
	if err := mgr.store.putChain(&ChainRecord{ChainID: "sha256:chain-txn", Path: chainPath, RefCount: 0}); err != nil {
		t.Fatalf("put chain: %v", err)
	}

	mountPath := filepath.Join(mgr.mountsDir, "txn-chain-mount", "merged")
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		t.Fatalf("mkdir mount path: %v", err)
	}
	if err := mgr.store.putMountTxn(&OciMountTxnRecord{
		ImageURL:     "docker.io/library/busybox:chain",
		MountID:      "txn-chain-mount",
		MountPath:    mountPath,
		LayerDigests: []string{"sha256:txn-chain"},
		ChainIDs:     []string{"sha256:chain-txn"},
		LowerDirs:    []string{chainPath},
	}); err != nil {
		t.Fatalf("put mount txn: %v", err)
	}

	mgr.readMnts = func() (map[string]struct{}, bool, error) {
		return map[string]struct{}{mountPath: {}}, true, nil
	}

	if err := mgr.reconcileState(); err != nil {
		t.Fatalf("reconcileState() error: %v", err)
	}

	mount, err := mgr.store.getMount("docker.io/library/busybox:chain")
	if err != nil {
		t.Fatalf("get mount: %v", err)
	}
	if mount == nil {
		t.Fatalf("mount record should be recovered from txn")
	}
	if len(mount.ChainIDs) != 1 || mount.ChainIDs[0] != "sha256:chain-txn" {
		t.Fatalf("recovered mount chain ids mismatch, got %+v", mount.ChainIDs)
	}
	txn, err := mgr.store.getMountTxn("docker.io/library/busybox:chain")
	if err != nil {
		t.Fatalf("get mount txn: %v", err)
	}
	if txn != nil {
		t.Fatalf("mount txn should be removed after recovery")
	}
	layer, err := mgr.store.getLayer("sha256:txn-chain")
	if err != nil || layer == nil {
		t.Fatalf("get layer: err=%v", err)
	}
	if layer.RefCount != 1 {
		t.Fatalf("recovered mount should set layer refcount to 1, got %d", layer.RefCount)
	}
	chain, err := mgr.store.getChain("sha256:chain-txn")
	if err != nil || chain == nil {
		t.Fatalf("get chain: err=%v", err)
	}
	if chain.RefCount != 1 {
		t.Fatalf("recovered mount should set chain refcount to 1, got %d", chain.RefCount)
	}
}

func TestReconcileState_DropsTxnMountWhenLayersMissing(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	mountPath := filepath.Join(mgr.mountsDir, "txn-missing", "merged")
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		t.Fatalf("mkdir mount path: %v", err)
	}
	if err := mgr.store.putMountTxn(&OciMountTxnRecord{
		ImageURL:     "docker.io/library/missing:latest",
		MountID:      "txn-missing",
		MountPath:    mountPath,
		LayerDigests: []string{"sha256:missing"},
	}); err != nil {
		t.Fatalf("put mount txn: %v", err)
	}

	unmounted := false
	mgr.unmountFn = func(target string) error {
		if target == mountPath {
			unmounted = true
		}
		return nil
	}
	mgr.readMnts = func() (map[string]struct{}, bool, error) {
		return map[string]struct{}{mountPath: {}}, true, nil
	}

	if err := mgr.reconcileState(); err != nil {
		t.Fatalf("reconcileState() error: %v", err)
	}

	mount, err := mgr.store.getMount("docker.io/library/missing:latest")
	if err != nil {
		t.Fatalf("get mount: %v", err)
	}
	if mount != nil {
		t.Fatalf("mount record should not be recovered when layers are missing")
	}
	txn, err := mgr.store.getMountTxn("docker.io/library/missing:latest")
	if err != nil {
		t.Fatalf("get mount txn: %v", err)
	}
	if txn != nil {
		t.Fatalf("mount txn should be removed when layers are missing")
	}
	if !unmounted {
		t.Fatalf("orphan txn mount should be unmounted when layers are missing")
	}
}

func TestReconcileState_CleansOrphanOverlayMounts(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	orphanMountPath := filepath.Join(mgr.mountsDir, "orphan", "merged")
	if err := os.MkdirAll(orphanMountPath, 0755); err != nil {
		t.Fatalf("mkdir orphan mount: %v", err)
	}

	called := false
	mgr.unmountFn = func(target string) error {
		if target == orphanMountPath {
			called = true
		}
		return nil
	}
	mgr.readMnts = func() (map[string]struct{}, bool, error) {
		return map[string]struct{}{orphanMountPath: {}}, true, nil
	}

	if err := mgr.reconcileState(); err != nil {
		t.Fatalf("reconcileState() error: %v", err)
	}
	if !called {
		t.Fatalf("orphan overlay mount should be unmounted during reconcile")
	}
	if _, err := os.Stat(filepath.Dir(orphanMountPath)); !os.IsNotExist(err) {
		t.Fatalf("orphan mount directory should be removed, err=%v", err)
	}
}

func TestReconcileState_CleansStaleLayerTmpDirs(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	layerRoot := filepath.Join(mgr.layersDir, "sha256_stale")
	tmpPath := filepath.Join(layerRoot, "tmp-123")
	fsPath := filepath.Join(layerRoot, "fs")
	if err := os.MkdirAll(tmpPath, 0755); err != nil {
		t.Fatalf("mkdir tmp path: %v", err)
	}
	if err := os.MkdirAll(fsPath, 0755); err != nil {
		t.Fatalf("mkdir fs path: %v", err)
	}

	if err := mgr.reconcileState(); err != nil {
		t.Fatalf("reconcileState() error: %v", err)
	}

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("stale layer tmp dir should be removed, err=%v", err)
	}
	if _, err := os.Stat(fsPath); err != nil {
		t.Fatalf("layer fs dir should remain, err=%v", err)
	}
}

func TestImageLock_SameImageSerializes(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	assertSameKeySerializes(t, mgr.acquireImageLock, "docker.io/library/alpine:latest")
}

func TestImageLock_DifferentImagesCanRunConcurrently(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	assertDifferentKeysRunConcurrently(t, mgr.acquireImageLock, "docker.io/library/alpine:latest", "docker.io/library/busybox:latest")
}

func TestLayerLock_SameLayerSerializes(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	assertSameKeySerializes(t, mgr.acquireLayerLock, "sha256:same")
}

func TestLayerLock_DifferentLayersCanRunConcurrently(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	assertDifferentKeysRunConcurrently(t, mgr.acquireLayerLock, "sha256:a", "sha256:b")
}

func TestEnsureLayerExtracted_RecoversMetadataFromExistingPath(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	hash, err := v1.NewHash("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("new hash: %v", err)
	}

	layerDir, err := mgr.store.getOrCreateLayerDir(hash.String())
	if err != nil {
		t.Fatalf("getOrCreateLayerDir: %v", err)
	}
	layerPath := filepath.Join(mgr.layersDir, layerDir, "fs")
	if err := os.MkdirAll(filepath.Join(layerPath, "etc"), 0755); err != nil {
		t.Fatalf("mkdir layer path: %v", err)
	}
	content := []byte("hello")
	if err := os.WriteFile(filepath.Join(layerPath, "etc", "config"), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	rec, err := mgr.ensureLayerExtracted(panicUncompressedLayer{digest: hash})
	if err != nil {
		t.Fatalf("ensureLayerExtracted() error: %v", err)
	}
	if rec == nil {
		t.Fatalf("expected layer record")
	}
	if rec.Path != layerPath {
		t.Fatalf("unexpected recovered path: got %s want %s", rec.Path, layerPath)
	}
	if rec.SizeBytes <= 0 {
		t.Fatalf("expected recovered layer size > 0, got %d", rec.SizeBytes)
	}

	stored, err := mgr.store.getLayer(hash.String())
	if err != nil {
		t.Fatalf("get recovered layer: %v", err)
	}
	if stored == nil {
		t.Fatalf("expected recovered layer metadata in store")
	}
	if stored.RefCount != 1 {
		t.Fatalf("expected recovered layer refcount = 1, got %d", stored.RefCount)
	}
	if stored.RefZeroAtUnix != 0 {
		t.Fatalf("expected recovered layer ref-zero timestamp cleared, got %d", stored.RefZeroAtUnix)
	}
}

func TestEnsureLayerExtracted_KeepLegacyLayerPathNoMigration(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	hash, err := v1.NewHash("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatalf("new hash: %v", err)
	}

	legacyPath := filepath.Join(mgr.layersDir, "legacy-path", "fs")
	if err := os.MkdirAll(filepath.Join(legacyPath, "etc"), 0755); err != nil {
		t.Fatalf("mkdir legacy path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyPath, "etc", "config"), []byte("legacy"), 0644); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	layerDir, err := mgr.store.getOrCreateLayerDir(hash.String())
	if err != nil {
		t.Fatalf("getOrCreateLayerDir: %v", err)
	}
	mappedPath := filepath.Join(mgr.layersDir, layerDir, "fs")

	if err := mgr.store.putLayer(&LayerRecord{
		Digest:        hash.String(),
		Path:          legacyPath,
		RefCount:      0,
		RefZeroAtUnix: 0,
		LastUsedUnix:  0,
	}); err != nil {
		t.Fatalf("put legacy layer: %v", err)
	}

	rec, err := mgr.ensureLayerExtracted(panicUncompressedLayer{digest: hash})
	if err != nil {
		t.Fatalf("ensureLayerExtracted() error: %v", err)
	}
	if rec.Path != legacyPath {
		t.Fatalf("legacy layer path should be kept, got %s want %s", rec.Path, legacyPath)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy path should still exist, err=%v", err)
	}
	if _, err := os.Stat(mappedPath); !os.IsNotExist(err) {
		t.Fatalf("mapped path should not be created by online migration, err=%v", err)
	}
	if rec.RefCount != 1 {
		t.Fatalf("expected reserved layer refcount = 1, got %d", rec.RefCount)
	}
	if rec.RefZeroAtUnix != 0 {
		t.Fatalf("expected ref-zero timestamp to be cleared while reserved, got %d", rec.RefZeroAtUnix)
	}
}

func TestExtractLayersWithWorkers_RollsBackReservedRefsOnError(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()
	mgr.layerWorkers = 2

	goodHash, err := v1.NewHash("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err != nil {
		t.Fatalf("new good hash: %v", err)
	}
	badHash, err := v1.NewHash("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	if err != nil {
		t.Fatalf("new bad hash: %v", err)
	}

	_, _, err = mgr.extractLayersWithWorkers(context.Background(), []v1.Layer{
		sleepLayer{digest: goodHash},
		errorLayer{digest: badHash, err: fmt.Errorf("boom")},
	})
	if err == nil {
		t.Fatalf("extractLayersWithWorkers() error = nil, want non-nil")
	}

	layer, err := mgr.store.getLayer(goodHash.String())
	if err != nil {
		t.Fatalf("get good layer: %v", err)
	}
	if layer == nil {
		t.Fatalf("expected extracted good layer metadata to remain for cache reuse")
	}
	if layer.RefCount != 0 {
		t.Fatalf("expected reserved ref to be rolled back, got %d", layer.RefCount)
	}
	if layer.RefZeroAtUnix == 0 {
		t.Fatalf("expected rolled back layer to have ref-zero timestamp set")
	}
}

func TestExtractLayersWithWorkers_ConcurrentAndOrdered(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()
	mgr.layerWorkers = 2

	const layerCount = 4
	const delay = 200 * time.Millisecond

	layers := make([]v1.Layer, 0, layerCount)
	wantDigests := make([]string, 0, layerCount)
	for i := 0; i < layerCount; i++ {
		hash, err := v1.NewHash(fmt.Sprintf("sha256:%064x", i+1))
		if err != nil {
			t.Fatalf("new hash %d: %v", i, err)
		}
		layers = append(layers, sleepLayer{
			digest: hash,
			delay:  delay,
		})
		wantDigests = append(wantDigests, hash.String())
	}

	start := time.Now()
	gotDigests, gotPaths, err := mgr.extractLayersWithWorkers(context.Background(), layers)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("extractLayersWithWorkers() error: %v", err)
	}

	for i := 0; i < layerCount; i++ {
		if gotDigests[i] != wantDigests[i] {
			t.Fatalf("digest order mismatch at %d: got %s want %s", i, gotDigests[i], wantDigests[i])
		}
		if gotPaths[i] == "" {
			t.Fatalf("expected non-empty layer path at %d", i)
		}
		if _, err := os.Stat(gotPaths[i]); err != nil {
			t.Fatalf("layer path should exist at %d: %v", i, err)
		}
		layerDir := filepath.Base(filepath.Dir(gotPaths[i]))
		if len(layerDir) > 8 || layerDir == "" || layerDir[0] != 'l' {
			t.Fatalf("expected compact mapped layer dir, got %s", layerDir)
		}
	}

	// Serial execution would be roughly layerCount*delay (~800ms).
	// With 2 workers it should be around 2*delay (~400ms) plus overhead.
	if elapsed >= 700*time.Millisecond {
		t.Fatalf("expected concurrent extraction, elapsed=%v", elapsed)
	}
}

func TestExtractLayersWithWorkers_UseGlobalWorkerLimit(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()
	mgr.layerWorkers = 2

	var inFlight int32
	var maxFlight int32

	buildLayers := func(offset int) []v1.Layer {
		layers := make([]v1.Layer, 0, 3)
		for i := 0; i < 3; i++ {
			hash, err := v1.NewHash(fmt.Sprintf("sha256:%064x", offset+i+1))
			if err != nil {
				t.Fatalf("new hash: %v", err)
			}
			layers = append(layers, observedSleepLayer{
				digest:    hash,
				delay:     180 * time.Millisecond,
				inFlight:  &inFlight,
				maxFlight: &maxFlight,
			})
		}
		return layers
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	run := func(offset int) {
		defer wg.Done()
		_, _, err := mgr.extractLayersWithWorkers(context.Background(), buildLayers(offset))
		errCh <- err
	}

	wg.Add(2)
	go run(0)
	go run(100)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("extractLayersWithWorkers() error: %v", err)
		}
	}

	if got := atomic.LoadInt32(&maxFlight); got > int32(mgr.layerWorkers) {
		t.Fatalf("expected global max concurrency <= %d, got %d", mgr.layerWorkers, got)
	}
	if got := atomic.LoadInt32(&maxFlight); got < 2 {
		t.Fatalf("expected observed concurrency >= 2, got %d", got)
	}
}

func TestEnsureChainLowerDirs_CreatesDockerStyleLowerdirs(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	hash1, err := v1.NewHash(fmt.Sprintf("sha256:%064x", 1))
	if err != nil {
		t.Fatalf("new hash1: %v", err)
	}
	hash2, err := v1.NewHash(fmt.Sprintf("sha256:%064x", 2))
	if err != nil {
		t.Fatalf("new hash2: %v", err)
	}

	layers := []v1.Layer{
		sleepLayer{digest: hash1},
		sleepLayer{digest: hash2},
		sleepLayer{digest: hash2},
	}

	layerDigests, layerPaths, err := mgr.extractLayersWithWorkers(context.Background(), layers)
	if err != nil {
		t.Fatalf("extractLayersWithWorkers() error: %v", err)
	}
	if layerDigests[1] != layerDigests[2] {
		t.Fatalf("expected duplicate digests, got %s and %s", layerDigests[1], layerDigests[2])
	}
	if layerPaths[1] != layerPaths[2] {
		t.Fatalf("expected duplicate cache paths before materialization, got %s and %s", layerPaths[1], layerPaths[2])
	}

	diffIDs := []v1.Hash{hash1, hash2, hash2}
	chainIDs, err := buildChainIDs(diffIDs)
	if err != nil {
		t.Fatalf("buildChainIDs() error: %v", err)
	}
	if chainIDs[1] == chainIDs[2] {
		t.Fatalf("expected duplicate layer occurrence to produce distinct chainIDs, got %s", chainIDs[1])
	}

	gotPaths, err := mgr.ensureChainLowerDirs(chainIDs, layerPaths)
	if err != nil {
		t.Fatalf("ensureChainLowerDirs() error: %v", err)
	}
	gotPathsAgain, err := mgr.ensureChainLowerDirs(chainIDs, layerPaths)
	if err != nil {
		t.Fatalf("ensureChainLowerDirs() second call error: %v", err)
	}
	if gotPathsAgain[1] != gotPaths[1] || gotPathsAgain[2] != gotPaths[2] {
		t.Fatalf("expected stable chain lowerdir mapping, got %v then %v", gotPaths, gotPathsAgain)
	}

	if gotPaths[0] == layerPaths[0] {
		t.Fatalf("expected chain lowerdir path to differ from source layer path, got %s", gotPaths[0])
	}
	if gotPaths[1] == layerPaths[1] {
		t.Fatalf("expected chain lowerdir path to differ from source layer path, got %s", gotPaths[1])
	}
	if gotPaths[2] == layerPaths[2] {
		t.Fatalf("expected repeated occurrence to use chain lowerdir path, got %s", gotPaths[2])
	}
	if !strings.HasPrefix(gotPaths[2], mgr.chainsDir) {
		t.Fatalf("expected chain lowerdir path %s to live under %s", gotPaths[2], mgr.chainsDir)
	}
	if _, err := os.Stat(filepath.Join(gotPaths[2], "etc", "config")); err != nil {
		t.Fatalf("duplicate occurrence content missing: %v", err)
	}
	sourceInfo, err := os.Stat(filepath.Join(layerPaths[1], "etc", "config"))
	if err != nil {
		t.Fatalf("stat source config: %v", err)
	}
	targetInfo, err := os.Stat(filepath.Join(gotPaths[1], "etc", "config"))
	if err != nil {
		t.Fatalf("stat chain config: %v", err)
	}
	if !os.SameFile(sourceInfo, targetInfo) {
		t.Fatalf("expected chain lowerdir file to be hardlinked from source layer")
	}
}

func TestEnsureChainLowerDirs_RollsBackReservedRefsOnError(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	firstHash, err := v1.NewHash(fmt.Sprintf("sha256:%064x", 11))
	if err != nil {
		t.Fatalf("new hash1: %v", err)
	}
	secondHash, err := v1.NewHash(fmt.Sprintf("sha256:%064x", 12))
	if err != nil {
		t.Fatalf("new hash2: %v", err)
	}

	firstPath := filepath.Join(mgr.layersDir, "first", "fs")
	if err := os.MkdirAll(filepath.Join(firstPath, "etc"), 0755); err != nil {
		t.Fatalf("mkdir first path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(firstPath, "etc", "config"), []byte("first"), 0644); err != nil {
		t.Fatalf("write first config: %v", err)
	}

	chainIDs, err := buildChainIDs([]v1.Hash{firstHash, secondHash})
	if err != nil {
		t.Fatalf("buildChainIDs() error: %v", err)
	}

	if _, err := mgr.ensureChainLowerDirs(chainIDs, []string{firstPath, filepath.Join(mgr.layersDir, "missing", "fs")}); err == nil {
		t.Fatalf("ensureChainLowerDirs() error = nil, want non-nil")
	}

	firstChain, err := mgr.store.getChain(chainIDs[0])
	if err != nil {
		t.Fatalf("get first chain: %v", err)
	}
	if firstChain == nil {
		t.Fatalf("expected first chain metadata to exist")
	}
	if firstChain.RefCount != 0 {
		t.Fatalf("expected first chain ref rollback to restore refcount 0, got %d", firstChain.RefCount)
	}
	if firstChain.RefZeroAtUnix == 0 {
		t.Fatalf("expected first chain ref-zero timestamp to be set after rollback")
	}
}

func TestMaterializeChainLowerDir_UsesManagerClockForTempDir(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	fixedNow := time.Unix(1700000000, 123456789)
	mgr.now = func() time.Time { return fixedNow }

	sourcePath := filepath.Join(mgr.layersDir, "clock-source", "fs")
	targetPath := filepath.Join(mgr.chainsDir, "clock-target", "fs")
	if err := os.MkdirAll(filepath.Join(sourcePath, "etc"), 0755); err != nil {
		t.Fatalf("mkdir source path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "etc", "config"), []byte("clock"), 0644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	expectedTmpPath := filepath.Join(filepath.Dir(targetPath), fmt.Sprintf("tmp-%d", fixedNow.UnixNano()))
	if err := os.MkdirAll(expectedTmpPath, 0755); err != nil {
		t.Fatalf("mkdir stale tmp path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(expectedTmpPath, "stale"), []byte("old"), 0644); err != nil {
		t.Fatalf("write stale tmp file: %v", err)
	}

	if err := mgr.materializeChainLowerDir(sourcePath, targetPath); err != nil {
		t.Fatalf("materializeChainLowerDir() error: %v", err)
	}

	if _, err := os.Stat(expectedTmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected manager-clock temp path to be removed, err=%v", err)
	}
	content, err := os.ReadFile(filepath.Join(targetPath, "etc", "config"))
	if err != nil {
		t.Fatalf("read target file: %v", err)
	}
	if string(content) != "clock" {
		t.Fatalf("target file content = %q, want %q", string(content), "clock")
	}
}

func TestGCChainsByTTL_RemovesExpiredUnreferencedLowerdirs(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	now := time.Unix(1700000000, 0)
	mgr.now = func() time.Time { return now }
	mgr.layerTTL = 30 * time.Minute

	expiredPath := filepath.Join(mgr.chainsDir, "c1", "fs")
	freshPath := filepath.Join(mgr.chainsDir, "c2", "fs")
	for _, p := range []string{expiredPath, freshPath} {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(filepath.Join(p, "data"), []byte("x"), 0644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	if err := mgr.store.putChain(&ChainRecord{
		ChainID:       "sha256:expired",
		Path:          expiredPath,
		RefCount:      0,
		RefZeroAtUnix: now.Add(-31 * time.Minute).Unix(),
		LastUsedUnix:  now.Add(-31 * time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("put expired chain: %v", err)
	}
	if err := mgr.store.putChain(&ChainRecord{
		ChainID:       "sha256:fresh",
		Path:          freshPath,
		RefCount:      0,
		RefZeroAtUnix: now.Add(-10 * time.Minute).Unix(),
		LastUsedUnix:  now.Add(-10 * time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("put fresh chain: %v", err)
	}

	if err := mgr.gcChainsByTTL(); err != nil {
		t.Fatalf("gcChainsByTTL() error: %v", err)
	}

	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Fatalf("expired chain path should be removed, err=%v", err)
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Fatalf("fresh chain path should remain, err=%v", err)
	}
	rec, err := mgr.store.getChain("sha256:expired")
	if err != nil {
		t.Fatalf("get expired chain: %v", err)
	}
	if rec != nil {
		t.Fatalf("expired chain metadata should be removed, got %+v", rec)
	}
}

func TestGCLayersByTTL_RemovesExpiredUnreferencedLayers(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	now := time.Unix(1700000000, 0)
	mgr.now = func() time.Time { return now }
	mgr.layerTTL = 30 * time.Minute

	expiredPath := filepath.Join(mgr.layersDir, "sha256_expired", "fs")
	freshPath := filepath.Join(mgr.layersDir, "sha256_fresh", "fs")
	usedPath := filepath.Join(mgr.layersDir, "sha256_used", "fs")
	for _, p := range []string{expiredPath, freshPath, usedPath} {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(filepath.Join(p, "data"), []byte("x"), 0644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	if err := mgr.store.putLayer(&LayerRecord{
		Digest:        "sha256:expired",
		Path:          expiredPath,
		RefCount:      0,
		RefZeroAtUnix: now.Add(-31 * time.Minute).Unix(),
		LastUsedUnix:  now.Add(-31 * time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("put expired layer: %v", err)
	}
	if err := mgr.store.putLayer(&LayerRecord{
		Digest:        "sha256:fresh",
		Path:          freshPath,
		RefCount:      0,
		RefZeroAtUnix: now.Add(-10 * time.Minute).Unix(),
		LastUsedUnix:  now.Add(-10 * time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("put fresh layer: %v", err)
	}
	if err := mgr.store.putLayer(&LayerRecord{
		Digest:        "sha256:used",
		Path:          usedPath,
		RefCount:      1,
		RefZeroAtUnix: 0,
		LastUsedUnix:  now.Unix(),
	}); err != nil {
		t.Fatalf("put used layer: %v", err)
	}

	if err := mgr.gcLayers(); err != nil {
		t.Fatalf("gcLayers() error: %v", err)
	}

	expiredRec, err := mgr.store.getLayer("sha256:expired")
	if err != nil {
		t.Fatalf("get expired layer: %v", err)
	}
	if expiredRec != nil {
		t.Fatalf("expired layer should be deleted")
	}
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Fatalf("expired layer path should be removed, err=%v", err)
	}

	freshRec, err := mgr.store.getLayer("sha256:fresh")
	if err != nil {
		t.Fatalf("get fresh layer: %v", err)
	}
	if freshRec == nil {
		t.Fatalf("fresh layer should not be deleted by TTL")
	}

	usedRec, err := mgr.store.getLayer("sha256:used")
	if err != nil {
		t.Fatalf("get used layer: %v", err)
	}
	if usedRec == nil {
		t.Fatalf("referenced layer should not be deleted by TTL")
	}
}

func TestClose_WaitsForInFlightLayerWorker(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	hash, err := v1.NewHash("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("new hash: %v", err)
	}

	started := make(chan struct{}, 1)
	unblock := make(chan struct{})
	layer := blockLayer{
		digest:  hash,
		started: started,
		unblock: unblock,
	}

	extractDone := make(chan error, 1)
	go func() {
		_, _, err := mgr.extractLayersWithWorkers(context.Background(), []v1.Layer{layer})
		extractDone <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("worker did not start layer extraction in time")
	}

	closeDone := make(chan struct{})
	go func() {
		_ = mgr.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		t.Fatalf("Close() returned before in-flight worker finished")
	case <-time.After(120 * time.Millisecond):
	}

	close(unblock)

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("Close() did not finish after worker unblocked")
	}

	select {
	case <-extractDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("extract call did not finish")
	}
}

func TestListMountedImageURLs(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	if err := mgr.store.putMount(&OciMountRecord{
		ImageURL:     "docker.io/library/z:latest",
		MountID:      "m1",
		MountPath:    filepath.Join(mgr.mountsDir, "m1", "merged"),
		LayerDigests: []string{"sha256:a"},
	}); err != nil {
		t.Fatalf("put mount m1: %v", err)
	}
	if err := mgr.store.putMount(&OciMountRecord{
		ImageURL:     "docker.io/library/a:latest",
		MountID:      "m2",
		MountPath:    filepath.Join(mgr.mountsDir, "m2", "merged"),
		LayerDigests: []string{"sha256:b"},
	}); err != nil {
		t.Fatalf("put mount m2: %v", err)
	}

	got, err := mgr.ListMountedImageURLs()
	if err != nil {
		t.Fatalf("ListMountedImageURLs() error: %v", err)
	}

	want := []string{
		"docker.io/library/a:latest",
		"docker.io/library/z:latest",
	}
	if len(got) != len(want) {
		t.Fatalf("ListMountedImageURLs() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListMountedImageURLs()[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestListMountedDetails(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()

	if err := mgr.store.putMount(&OciMountRecord{
		ImageURL:      "docker.io/library/z:latest",
		MountID:       "m1",
		MountPath:     filepath.Join(mgr.mountsDir, "m1", "merged"),
		LayerDigests:  []string{"sha256:z1", "sha256:z2"},
		ChainIDs:      []string{"sha256:cz1", "sha256:cz2"},
		LowerDirs:     []string{"/layers/lz1", "/layers/lz2"},
		CreatedAtUnix: 100,
	}); err != nil {
		t.Fatalf("put mount m1: %v", err)
	}
	if err := mgr.store.putMount(&OciMountRecord{
		ImageURL:      "docker.io/library/a:latest",
		MountID:       "m2",
		MountPath:     filepath.Join(mgr.mountsDir, "m2", "merged"),
		LayerDigests:  []string{"sha256:a1"},
		ChainIDs:      []string{"sha256:ca1"},
		LowerDirs:     []string{"/layers/la1"},
		CreatedAtUnix: 200,
	}); err != nil {
		t.Fatalf("put mount m2: %v", err)
	}

	got, err := mgr.ListMountedDetails()
	if err != nil {
		t.Fatalf("ListMountedDetails() error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListMountedDetails() length = %d, want %d", len(got), 2)
	}
	if got[0].ImageURL != "docker.io/library/a:latest" || got[1].ImageURL != "docker.io/library/z:latest" {
		t.Fatalf("ListMountedDetails() sorting unexpected: %+v", got)
	}
	if got[0].MountID != "m2" || got[0].MountPath == "" {
		t.Fatalf("ListMountedDetails()[0] invalid detail: %+v", got[0])
	}

	// Mutating returned slices must not affect persisted records.
	got[1].LayerDigests[0] = "mutated"
	got[1].ChainIDs[0] = "mutated"
	got[1].LowerDirs[0] = "mutated"
	again, err := mgr.ListMountedDetails()
	if err != nil {
		t.Fatalf("ListMountedDetails() second call error: %v", err)
	}
	if again[1].LayerDigests[0] == "mutated" || again[1].ChainIDs[0] == "mutated" || again[1].LowerDirs[0] == "mutated" {
		t.Fatalf("ListMountedDetails() should return deep-copied slices")
	}
}

func TestBuildOverlayMountData(t *testing.T) {
	tests := []struct {
		name      string
		lowerDirs []string
		want      string
		wantErr   bool
	}{
		{
			name:      "single lowerdir",
			lowerDirs: []string{"/tmp/layers/l1/fs"},
			want:      "lowerdir=/tmp/layers/l1/fs",
		},
		{
			name:      "multiple lowerdirs",
			lowerDirs: []string{"/tmp/layers/l2/fs", "/tmp/layers/l1/fs"},
			want:      "lowerdir=/tmp/layers/l2/fs:/tmp/layers/l1/fs",
		},
		{
			name:      "empty lowerdirs",
			lowerDirs: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildOverlayMountData(tt.lowerDirs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("buildOverlayMountData() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildOverlayMountData() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("buildOverlayMountData() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrepareRuntimeDefaultsLowerDir(t *testing.T) {
	mountRoot := filepath.Join(t.TempDir(), "mount")

	lowerDir, err := prepareRuntimeDefaultsLowerDir(mountRoot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lowerDir != filepath.Join(mountRoot, "runtime-defaults") {
		t.Fatalf("lower dir = %q", lowerDir)
	}
	data, err := os.ReadFile(filepath.Join(lowerDir, "etc", "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != config.LocalhostHostsFileContent {
		t.Fatalf("hosts content = %q", data)
	}
	tmpDir := filepath.Join(lowerDir, "tmp")
	tmpInfo, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := tmpInfo.Mode().Perm(); got != 0777 || tmpInfo.Mode()&os.ModeSticky == 0 {
		t.Fatalf("tmp mode = %v, want 01777", tmpInfo.Mode())
	}
	if _, err := os.Stat(filepath.Join(tmpDir, runtimeTmpSentinel)); err != nil {
		t.Fatalf("runtime tmp sentinel: %v", err)
	}
}

func TestPrepareRuntimeDefaultsLowerDirKeepsImageHosts(t *testing.T) {
	mountRoot := filepath.Join(t.TempDir(), "mount")
	imageLower := filepath.Join(t.TempDir(), "lower")
	if err := os.MkdirAll(filepath.Join(imageLower, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(imageLower, "etc", "hosts"), []byte("10.0.0.1 custom\n"), 0644); err != nil {
		t.Fatal(err)
	}

	lowerDir, err := prepareRuntimeDefaultsLowerDir(mountRoot, []string{imageLower})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(lowerDir, "etc", "hosts")); !os.IsNotExist(err) {
		t.Fatalf("default hosts should be skipped when the image provides one, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(lowerDir, "tmp", runtimeTmpSentinel)); err != nil {
		t.Fatalf("runtime tmp sentinel: %v", err)
	}
}

func assertSameKeySerializes(t *testing.T, acquire func(string) func(), key string) {
	t.Helper()

	firstLocked := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondTrying := make(chan struct{})
	secondLocked := make(chan struct{})
	done := make(chan struct{}, 2)

	go func() {
		unlock := acquire(key)
		close(firstLocked)
		<-releaseFirst
		unlock()
		done <- struct{}{}
	}()

	waitForSignal(t, firstLocked, "first lock was not acquired")

	go func() {
		close(secondTrying)
		unlock := acquire(key)
		close(secondLocked)
		unlock()
		done <- struct{}{}
	}()

	waitForSignal(t, secondTrying, "second lock attempt did not start")
	assertNotSignaled(t, secondLocked, "same key lock should serialize")

	close(releaseFirst)

	waitForSignal(t, secondLocked, "second lock did not acquire after the first lock was released")
	waitForSignal(t, done, "first lock holder did not finish")
	waitForSignal(t, done, "second lock holder did not finish")
}

func assertDifferentKeysRunConcurrently(t *testing.T, acquire func(string) func(), firstKey string, secondKey string) {
	t.Helper()

	firstLocked := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondLocked := make(chan struct{})
	releaseSecond := make(chan struct{})
	done := make(chan struct{}, 2)

	go func() {
		unlock := acquire(firstKey)
		close(firstLocked)
		<-releaseFirst
		unlock()
		done <- struct{}{}
	}()

	waitForSignal(t, firstLocked, "first lock was not acquired")

	go func() {
		unlock := acquire(secondKey)
		close(secondLocked)
		<-releaseSecond
		unlock()
		done <- struct{}{}
	}()

	waitForSignal(t, secondLocked, "different keys should acquire locks independently")

	close(releaseSecond)
	close(releaseFirst)

	waitForSignal(t, done, "first lock holder did not finish")
	waitForSignal(t, done, "second lock holder did not finish")
}

func waitForSignal(t *testing.T, ch <-chan struct{}, failureMsg string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(failureMsg)
	}
}

func assertNotSignaled(t *testing.T, ch <-chan struct{}, failureMsg string) {
	t.Helper()

	select {
	case <-ch:
		t.Fatal(failureMsg)
	default:
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()

	root := t.TempDir()
	layersDir := filepath.Join(root, "layers")
	chainsDir := filepath.Join(root, "lowerdirs")
	mountsDir := filepath.Join(root, "mounts")
	if err := os.MkdirAll(layersDir, 0755); err != nil {
		t.Fatalf("mkdir layers dir: %v", err)
	}
	if err := os.MkdirAll(chainsDir, 0755); err != nil {
		t.Fatalf("mkdir lowerdirs dir: %v", err)
	}
	if err := os.MkdirAll(mountsDir, 0755); err != nil {
		t.Fatalf("mkdir mounts dir: %v", err)
	}

	store, err := openMetadataStore(filepath.Join(root, "metadata.db"))
	if err != nil {
		t.Fatalf("open metadata store: %v", err)
	}

	mgr := &Manager{
		root:         root,
		layersDir:    layersDir,
		chainsDir:    chainsDir,
		mountsDir:    mountsDir,
		store:        store,
		containers:   make(map[string]*ContainerInfo),
		imageLocks:   make(map[string]*imageLockEntry),
		layerLocks:   make(map[string]*imageLockEntry),
		chainLocks:   make(map[string]*imageLockEntry),
		stopCh:       make(chan struct{}),
		now:          func() time.Time { return time.Unix(1700000000, 0) },
		mountFn:      func(string, []string) error { return nil },
		unmountFn:    func(string) error { return nil },
		readMnts:     func() (map[string]struct{}, bool, error) { return map[string]struct{}{}, false, nil },
		diskUsage:    func(string) (float64, error) { return 0, nil },
		layerWorkers: defaultGlobalLayerWorkers,
		layerTTL:     defaultLayerZeroRefTTL,
	}
	t.Cleanup(func() {
		mgr.layerPoolMu.Lock()
		mgr.stopOnce.Do(func() {
			close(mgr.stopCh)
		})
		mgr.layerPoolWG.Wait()
		mgr.layerPoolMu.Unlock()
	})
	return mgr
}
