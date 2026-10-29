// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
)

func seedImmutable(t *testing.T, manager *Manager, image string, count int) *immutableImageRecord {
	t.Helper()
	record := &immutableImageRecord{ImageURL: image, Env: []string{"CASE=original"}, ImageProcess: &imageconfig.Process{Cmd: []string{"serve"}, Cwd: "/app"}}
	for i := range count {
		digest := "sha256:" + strings.Repeat(string(rune('a'+i)), 64)
		path := filepath.Join(manager.layersDir, string(rune('a'+i)), "fs")
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "original"), []byte("shared"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := manager.store.putLayer(&LayerRecord{Digest: digest, Path: path}); err != nil {
			t.Fatal(err)
		}
		record.LayerDigests = append(record.LayerDigests, digest)
		record.ChainIDs = append(record.ChainIDs, "sha256:"+strings.Repeat(string(rune('c'+i)), 64))
	}
	if err := manager.store.putImmutableImage(record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestImmutableMetadataSurvivesUnmountAndStoreReopen(t *testing.T) {
	m := newTestManager(t)
	image := "registry.example/base@sha256:" + strings.Repeat("1", 64)
	record := seedImmutable(t, m, image, 2)
	// The fixture has no registry client. Any network fallback would fail here.
	for round := 0; round < 2; round++ {
		_, env, process, err := m.MountImageConfigWithContext(context.Background(), image)
		if err != nil {
			t.Fatal(err)
		}
		if len(env) != 1 || env[0] != "CASE=original" || process.Cwd != "/app" {
			t.Fatalf("image identity changed: %v %+v", env, process)
		}
		if err := m.UnmountImage(image); err != nil {
			t.Fatal(err)
		}
		for _, digest := range record.LayerDigests {
			layer, err := m.store.getLayer(digest)
			if err != nil || layer.RefCount != 0 {
				t.Fatalf("metadata cache pins layers: %+v %v", layer, err)
			}
		}
		if round == 0 {
			path := m.store.db.Path()
			if err := m.store.close(); err != nil {
				t.Fatal(err)
			}
			store, err := openMetadataStore(path)
			if err != nil {
				t.Fatal(err)
			}
			m.store = store
		}
	}
}

func TestMissingCachedLayerReleasesPartialReservations(t *testing.T) {
	m := newTestManager(t)
	image := "registry.example/base@sha256:" + strings.Repeat("1", 64)
	record := seedImmutable(t, m, image, 2)
	layer, _ := m.store.getLayer(record.LayerDigests[1])
	if err := os.RemoveAll(layer.Path); err != nil {
		t.Fatal(err)
	}
	got, err := m.reserveCachedImage(context.Background(), image)
	if err != nil || got != nil {
		t.Fatalf("GC'd cache must fall back: %+v %v", got, err)
	}
	first, _ := m.store.getLayer(record.LayerDigests[0])
	if first.RefCount != 0 {
		t.Fatal("partial reservation leaked")
	}
}

func TestMutableTagsNeverUseImmutableMetadata(t *testing.T) {
	m := newTestManager(t)
	image := "registry.example/base:latest"
	seedImmutable(t, m, image, 1)
	got, err := m.reserveCachedImage(context.Background(), image)
	if got != nil || err != nil {
		t.Fatalf("mutable tag was cached: %+v %v", got, err)
	}
}
