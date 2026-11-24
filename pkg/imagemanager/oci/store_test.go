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
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	bolt "go.etcd.io/bbolt"
)

func TestDiscardMountTxnReleasesReferencesExactlyOnce(t *testing.T) {
	store, err := openMetadataStore(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	const imageURL = "registry.example/image:v1"
	const digest = "sha256:shared"
	const chainID = "sha256:chain"
	if err := store.putLayer(&LayerRecord{Digest: digest, RefCount: 2}); err != nil {
		t.Fatal(err)
	}
	if err := store.putMountTxn(&OciMountTxnRecord{
		ImageURL: imageURL, LayerDigests: []string{digest}, ChainIDs: []string{chainID},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(chainRecordsBucket).Put([]byte(chainID), []byte("invalid record"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.discardMountTxn(imageURL, 1); err == nil {
		t.Fatal("expected a failed reference update")
	}
	if layer, err := store.getLayer(digest); err != nil || layer == nil || layer.RefCount != 2 {
		t.Fatalf("failed transaction partially released the shared layer: %v, %v", layer, err)
	}
	if err := store.putChain(&ChainRecord{ChainID: chainID, RefCount: 1}); err != nil {
		t.Fatal(err)
	}
	for _, now := range []int64{2, 3} {
		if err := store.discardMountTxn(imageURL, now); err != nil {
			t.Fatal(err)
		}
	}
	if layer, err := store.getLayer(digest); err != nil || layer == nil || layer.RefCount != 1 {
		t.Fatalf("shared layer reference was released more than once: %v, %v", layer, err)
	}
	if chain, err := store.getChain(chainID); err != nil || chain == nil || chain.RefCount != 0 || chain.RefZeroAtUnix != 2 {
		t.Fatalf("unexpected chain after retried rollback: %v, %v", chain, err)
	}
}

func TestMetadataStorePersistsImageProcess(t *testing.T) {
	store, err := openMetadataStore(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	want := &imageconfig.Process{
		Entrypoint: []string{"/entrypoint"},
		Cmd:        []string{"serve"},
		Cwd:        "/app",
		User:       "1000:1000",
	}
	if err := store.putMount(&OciMountRecord{
		ImageURL:     "registry.example/image:v1",
		ImageProcess: want,
	}); err != nil {
		t.Fatal(err)
	}
	record, err := store.getMount("registry.example/image:v1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record.ImageProcess, want) {
		t.Fatalf("image process = %#v, want %#v", record.ImageProcess, want)
	}
}

func TestMetadataStore_LayerRefCountAtomicUpdates(t *testing.T) {
	store, err := openMetadataStore(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatalf("openMetadataStore() error: %v", err)
	}
	defer store.close()

	if err := store.putLayer(&LayerRecord{
		Digest:       "sha256:test",
		Path:         "/tmp/layer",
		RefCount:     0,
		LastUsedUnix: 1,
	}); err != nil {
		t.Fatalf("putLayer() error: %v", err)
	}

	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if _, err := store.incrementLayerRef("sha256:test", 2); err != nil {
				t.Errorf("incrementLayerRef() error: %v", err)
			}
		}()
	}
	wg.Wait()

	rec, err := store.getLayer("sha256:test")
	if err != nil {
		t.Fatalf("getLayer() error: %v", err)
	}
	if rec.RefCount != workers {
		t.Fatalf("expected refcount=%d, got %d", workers, rec.RefCount)
	}
	if rec.RefZeroAtUnix != 0 {
		t.Fatalf("expected RefZeroAtUnix=0 while referenced, got %d", rec.RefZeroAtUnix)
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if _, err := store.decrementLayerRef("sha256:test", 3); err != nil {
				t.Errorf("decrementLayerRef() error: %v", err)
			}
		}()
	}
	wg.Wait()

	rec, err = store.getLayer("sha256:test")
	if err != nil {
		t.Fatalf("getLayer() error: %v", err)
	}
	if rec.RefCount != 0 {
		t.Fatalf("expected refcount=0, got %d", rec.RefCount)
	}
	if rec.RefZeroAtUnix != 3 {
		t.Fatalf("expected RefZeroAtUnix=3 after reaching zero, got %d", rec.RefZeroAtUnix)
	}
}

func TestMetadataStore_LayerRefCountNotFound(t *testing.T) {
	store, err := openMetadataStore(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatalf("openMetadataStore() error: %v", err)
	}
	defer store.close()

	if _, err := store.incrementLayerRef("sha256:missing", 1); !errors.Is(err, ErrLayerNotFound) {
		t.Fatalf("expected ErrLayerNotFound for increment, got %v", err)
	}
	if _, err := store.decrementLayerRef("sha256:missing", 1); !errors.Is(err, ErrLayerNotFound) {
		t.Fatalf("expected ErrLayerNotFound for decrement, got %v", err)
	}
}

func TestMetadataStore_GetOrCreateLayerDir(t *testing.T) {
	store, err := openMetadataStore(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatalf("openMetadataStore() error: %v", err)
	}
	defer store.close()

	dir1, err := store.getOrCreateLayerDir("sha256:aaa")
	if err != nil {
		t.Fatalf("getOrCreateLayerDir() error: %v", err)
	}
	dir1Again, err := store.getOrCreateLayerDir("sha256:aaa")
	if err != nil {
		t.Fatalf("getOrCreateLayerDir() error: %v", err)
	}
	if dir1 != dir1Again {
		t.Fatalf("expected stable layer dir mapping, got %s and %s", dir1, dir1Again)
	}

	dir2, err := store.getOrCreateLayerDir("sha256:bbb")
	if err != nil {
		t.Fatalf("getOrCreateLayerDir() error: %v", err)
	}
	if dir1 == dir2 {
		t.Fatalf("different digests should map to different dirs")
	}
	if !strings.HasPrefix(dir1, "l") || !strings.HasPrefix(dir2, "l") {
		t.Fatalf("expected compact layer dir names, got %s and %s", dir1, dir2)
	}

	got, err := store.getLayerDir("sha256:bbb")
	if err != nil {
		t.Fatalf("getLayerDir() error: %v", err)
	}
	if got != dir2 {
		t.Fatalf("expected getLayerDir=%s, got %s", dir2, got)
	}
}
