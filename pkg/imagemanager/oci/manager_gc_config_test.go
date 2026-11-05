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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewManagerWithZeroRefTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, 2 * time.Hour, 150 * time.Second, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			mgr, err := NewManagerWithZeroRefTTL(t.TempDir(), "", ttl)
			if ttl < 0 {
				if err == nil {
					mgr.Close()
					t.Fatal("negative TTL was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer mgr.Close()
			if mgr.layerTTL != ttl {
				t.Fatalf("TTL = %s, want %s", mgr.layerTTL, ttl)
			}
		})
	}
}

func TestNewManagerPreservesDefaultTTL(t *testing.T) {
	mgr, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	if mgr.layerTTL != 30*time.Minute {
		t.Fatalf("legacy constructor TTL = %s, want 30m", mgr.layerTTL)
	}
}

func TestConfiguredZeroRefTTLAndDiskPressure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ttl        time.Duration
		pressure   bool
		keepOld    bool
		keepRecent bool
	}{
		{name: "default_expires_after_30_minutes", ttl: DefaultLayerZeroRefTTL},
		{name: "custom_ttl", ttl: 2 * time.Hour, keepRecent: true},
		{name: "disabled_ttl", ttl: 0, keepOld: true, keepRecent: true},
		{name: "disabled_ttl_under_pressure", ttl: 0, pressure: true},
		{name: "pressure_before_custom_ttl", ttl: 2 * time.Hour, pressure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr, err := NewManagerWithZeroRefTTL(t.TempDir(), "", tc.ttl)
			if err != nil {
				t.Fatal(err)
			}
			defer mgr.Close()
			now := time.Unix(1700000000, 0)
			mgr.now = func() time.Time { return now }
			mgr.diskUsage = func(string) (float64, error) {
				if tc.pressure {
					return 0.9, nil
				}
				return 0.5, nil
			}
			for _, entry := range []struct {
				name string
				age  time.Duration
				refs int
				keep bool
			}{
				{name: "old", age: 3 * time.Hour, keep: tc.keepOld},
				{name: "recent", age: 31 * time.Minute, keep: tc.keepRecent},
				{name: "referenced", age: 3 * time.Hour, refs: 1, keep: true},
			} {
				for _, kind := range []string{"layer", "chain"} {
					id := "sha256:" + entry.name + "-" + kind
					root := mgr.layersDir
					if kind == "chain" {
						root = mgr.chainsDir
					}
					path := filepath.Join(root, entry.name, "fs")
					if err := os.MkdirAll(path, 0755); err != nil {
						t.Fatal(err)
					}
					zeroAt := now.Add(-entry.age).Unix()
					if entry.refs > 0 {
						zeroAt = 0
					}
					if kind == "layer" {
						err = mgr.store.putLayer(&LayerRecord{Digest: id, Path: path, RefCount: entry.refs, RefZeroAtUnix: zeroAt, LastUsedUnix: zeroAt})
					} else {
						err = mgr.store.putChain(&ChainRecord{ChainID: id, Path: path, RefCount: entry.refs, RefZeroAtUnix: zeroAt, LastUsedUnix: zeroAt})
					}
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						var present bool
						if kind == "layer" {
							record, err := mgr.store.getLayer(id)
							if err != nil {
								t.Error(err)
							}
							present = record != nil
						} else {
							record, err := mgr.store.getChain(id)
							if err != nil {
								t.Error(err)
							}
							present = record != nil
						}
						if present != entry.keep {
							t.Errorf("%s/%s metadata present = %v, want %v", tc.name, id, present, entry.keep)
						}
						_, err := os.Stat(path)
						if entry.keep && err != nil {
							t.Errorf("%s/%s should remain: %v", tc.name, id, err)
						} else if !entry.keep && !os.IsNotExist(err) {
							t.Errorf("%s/%s should be removed: %v", tc.name, id, err)
						}
					}()
				}
			}
			if err := mgr.gcLayers(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfiguredZeroRefTTLRestartsAfterFinalRelease(t *testing.T) {
	const id = "sha256:reacquired"
	const ttl = 2 * time.Hour
	mgr := newTestManager(t)
	defer mgr.store.close()
	mgr.layerTTL = ttl
	now := time.Unix(1700000000, 0)
	mgr.now = func() time.Time { return now }
	layerPath := filepath.Join(mgr.layersDir, "reacquired", "fs")
	chainPath := filepath.Join(mgr.chainsDir, "reacquired", "fs")
	for _, path := range []string{layerPath, chainPath} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	initialZeroAt := now.Add(-ttl + time.Minute).Unix()
	if err := mgr.store.putLayer(&LayerRecord{Digest: id, Path: layerPath, RefZeroAtUnix: initialZeroAt}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.store.putChain(&ChainRecord{ChainID: id, Path: chainPath, RefZeroAtUnix: initialZeroAt}); err != nil {
		t.Fatal(err)
	}
	assertState := func(wantRefs int, wantZeroAt int64, wantPresent bool) {
		t.Helper()
		layer, err := mgr.store.getLayer(id)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := mgr.store.getChain(id)
		if err != nil {
			t.Fatal(err)
		}
		if (layer != nil) != wantPresent || (chain != nil) != wantPresent {
			t.Fatalf("layer/chain metadata = %+v / %+v, want present = %v", layer, chain, wantPresent)
		}
		if wantPresent && (layer.RefCount != wantRefs || chain.RefCount != wantRefs || layer.RefZeroAtUnix != wantZeroAt || chain.RefZeroAtUnix != wantZeroAt) {
			t.Fatalf("layer/chain = %+v / %+v, want refs = %d, zero at = %d", layer, chain, wantRefs, wantZeroAt)
		}
		for _, path := range []string{layerPath, chainPath} {
			_, err := os.Stat(path)
			if wantPresent && err != nil || !wantPresent && !os.IsNotExist(err) {
				t.Fatalf("path %s: %v, want present = %v", path, err, wantPresent)
			}
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := mgr.store.incrementLayerRef(id, now.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.store.incrementChainRef(id, now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	assertState(2, 0, true)
	// The original retention interval expires while both references are active.
	now = now.Add(ttl)
	if err := mgr.gcLayers(); err != nil {
		t.Fatal(err)
	}
	assertState(2, 0, true)
	for remaining := 1; remaining >= 0; remaining-- {
		now = now.Add(time.Minute)
		if _, err := mgr.store.decrementLayerRef(id, now.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.store.decrementChainRef(id, now.Unix()); err != nil {
			t.Fatal(err)
		}
		if err := mgr.gcLayers(); err != nil {
			t.Fatal(err)
		}
		zeroAt := int64(0)
		if remaining == 0 {
			zeroAt = now.Unix()
		}
		assertState(remaining, zeroAt, true)
	}
	finalReleaseAt := now.Unix()
	now = now.Add(ttl - time.Second)
	if err := mgr.gcLayers(); err != nil {
		t.Fatal(err)
	}
	assertState(0, finalReleaseAt, true)
	now = now.Add(time.Second)
	if err := mgr.gcLayers(); err != nil {
		t.Fatal(err)
	}
	assertState(0, 0, false)
}
