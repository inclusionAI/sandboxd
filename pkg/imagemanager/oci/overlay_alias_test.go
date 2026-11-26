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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/moby/sys/mountinfo"
)

func TestCompactLowerDirValidation(t *testing.T) {
	mgr := newTestManager(t)
	defer mgr.store.close()
	mgr.aliasRoot = filepath.Join(mgr.root, "aliases")
	txn := &OciMountTxnRecord{
		ImageURL:  "test/image",
		MountPath: filepath.Join(mgr.mountsDir, "image", "merged"),
		LowerDirs: []string{filepath.Join(mgr.chainsDir, "c1", "fs"), filepath.Join(mgr.chainsDir, "c2", "fs")},
	}
	if _, err := mgr.prepareCompactLowerDirs(txn, 1); err == nil || !strings.Contains(err.Error(), "1-byte budget") {
		t.Fatalf("compact options should exceed the budget: %v", err)
	}
	if _, err := os.Lstat(mgr.aliasRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("alias directory created despite byte limit: %v", err)
	}
	if err := os.Symlink(t.TempDir(), mgr.aliasRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.prepareCompactLowerDirs(txn, 4095); err == nil || !strings.Contains(err.Error(), "untrusted OCI alias directory") {
		t.Fatalf("accepted a symlink as the alias directory: %v", err)
	}
	txn.LowerDirs[0] = filepath.Join(mgr.root, "outside", "fs")
	if _, err := mgr.prepareCompactLowerDirs(txn, 4095); err == nil || !strings.Contains(err.Error(), "outside the lowerdir cache") {
		t.Fatalf("accepted a layer outside the cache: %v", err)
	}
	if pending, err := mgr.store.getMountTxn(txn.ImageURL); err != nil || pending != nil {
		t.Fatalf("rejected alias left a journal: %v, %v", pending, err)
	}
}

func TestCompactLowerDirRecovery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mounted   bool
		published bool
		replace   bool
		reorder   bool
		wantAdopt bool
	}{
		{name: "crash before mount"},
		{name: "crash before publish", mounted: true, wantAdopt: true},
		{name: "published", mounted: true, published: true, wantAdopt: true},
		{name: "stale published record", published: true},
		{name: "reordered mount", mounted: true, reorder: true},
		{name: "replaced alias", mounted: true, replace: true, published: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := newTestManager(t)
			defer mgr.store.close()
			mgr.aliasRoot = filepath.Join(mgr.root, "aliases")
			txn := &OciMountTxnRecord{
				ImageURL:     "test/image",
				MountPath:    filepath.Join(mgr.mountsDir, "image", "merged"),
				LayerDigests: []string{"base", "top"},
				ChainIDs:     []string{"c1", "c2"},
				LowerDirs:    []string{filepath.Join(mgr.chainsDir, "c2", "fs"), filepath.Join(mgr.chainsDir, "c1", "fs")},
			}
			for i, digest := range txn.LayerDigests {
				layer := filepath.Join(mgr.layersDir, digest, "fs")
				chain := txn.LowerDirs[len(txn.LowerDirs)-1-i]
				for _, dir := range []string{layer, chain, txn.MountPath} {
					if err := os.MkdirAll(dir, 0755); err != nil {
						t.Fatal(err)
					}
				}
				if err := mgr.store.putLayer(&LayerRecord{Digest: digest, Path: layer, RefCount: 1}); err != nil {
					t.Fatal(err)
				}
				if err := mgr.store.putChain(&ChainRecord{ChainID: txn.ChainIDs[i], Path: chain, RefCount: 1}); err != nil {
					t.Fatal(err)
				}
			}
			data, err := mgr.prepareCompactLowerDirs(txn, 4095)
			if err != nil {
				t.Fatal(err)
			}
			alias, err := mgr.lowerDirAlias(txn.LowerDirAlias)
			if err != nil {
				t.Fatal(err)
			}
			if tc.published {
				rec := &OciMountRecord{
					ImageURL: txn.ImageURL, MountPath: txn.MountPath, LayerDigests: txn.LayerDigests,
					ChainIDs: txn.ChainIDs, LowerDirs: txn.LowerDirs, LowerDirAlias: txn.LowerDirAlias,
				}
				if err := mgr.store.publishMount(rec); err != nil {
					t.Fatal(err)
				}
			}
			var replacement string
			if tc.replace {
				replacement = t.TempDir()
				if err := os.Remove(alias.path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(replacement, alias.path); err != nil {
					t.Fatal(err)
				}
			}
			if tc.reorder {
				data = "lowerdir=" + filepath.Join(alias.path, "c1", "fs") + ":" + filepath.Join(alias.path, "c2", "fs")
			}
			mounts := make(map[string]*mountinfo.Info)
			if tc.mounted {
				mounts[txn.MountPath] = &mountinfo.Info{Root: "/", FSType: "overlay", VFSOptions: "ro," + data}
			}
			mgr.readMnts = func() (map[string]*mountinfo.Info, bool, error) {
				return mounts, true, nil
			}
			mgr.unmountFn = func(path string) error {
				delete(mounts, path)
				return nil
			}
			if err := mgr.reconcileState(); err != nil {
				t.Fatal(err)
			}
			if adopted := mgr.getContainer(txn.ImageURL) != nil; adopted != tc.wantAdopt {
				t.Fatalf("adoption = %t, want %t", adopted, tc.wantAdopt)
			}
			if pending, err := mgr.store.getMountTxn(txn.ImageURL); err != nil || pending != nil {
				t.Fatalf("pending transaction after recovery: %v, %v", pending, err)
			}
			if tc.wantAdopt {
				// The verifier used before alias support sees the same mount
				// but only has the canonical lowerdirs from the record.
				if err := verifyOCIMountLayers(mounts[txn.MountPath], txn.MountPath, txn.LowerDirs); err == nil ||
					!strings.Contains(err.Error(), "does not contain the expected 2 lowerdirs in order") {
					t.Fatalf("canonical-only verifier on compact mount: %v", err)
				}
				if path, _, err := mgr.MountImage(txn.ImageURL); err != nil || path != txn.MountPath {
					t.Fatalf("reuse = %q, %v", path, err)
				}
				if err := alias.verify(); err != nil {
					t.Fatal(err)
				}
			}
			if tc.replace {
				if _, err := mgr.readVerifiedMount(txn.ImageURL); err == nil {
					t.Fatal("accepted a persisted mount with a replaced alias")
				}
			}
			if tc.wantAdopt || tc.replace {
				unmount := mgr.unmountFn
				mgr.unmountFn = func(string) error { return syscall.EBUSY }
				if err := mgr.UnmountImage(txn.ImageURL); !errors.Is(err, syscall.EBUSY) {
					t.Fatalf("busy unmount: %v", err)
				}
				if _, err := os.Readlink(alias.path); err != nil {
					t.Fatalf("failed unmount removed its alias: %v", err)
				}
				mgr.unmountFn = unmount
				if err := mgr.UnmountImage(txn.ImageURL); err != nil {
					t.Fatal(err)
				}
			}
			if len(mounts) != 0 {
				t.Fatalf("live mount after cleanup: %v", mounts)
			}
			if record, err := mgr.store.getMount(txn.ImageURL); err != nil || record != nil {
				t.Fatalf("published mount after cleanup: %v, %v", record, err)
			}
			if target, err := os.Readlink(alias.path); tc.replace {
				if err != nil || target != replacement {
					t.Fatalf("foreign link was removed or replaced: %q, %v", target, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("owned alias was not removed: %q, %v", target, err)
			}
			for _, digest := range txn.LayerDigests {
				if layer, err := mgr.store.getLayer(digest); err != nil || layer == nil || layer.RefCount != 0 {
					t.Fatalf("layer references after cleanup: %+v, %v", layer, err)
				}
			}
			for _, id := range txn.ChainIDs {
				if chain, err := mgr.store.getChain(id); err != nil || chain == nil || chain.RefCount != 0 {
					t.Fatalf("chain references after cleanup: %+v, %v", chain, err)
				}
			}
		})
	}
}
