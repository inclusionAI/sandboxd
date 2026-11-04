// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package runtime

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

func TestGenerateOciMountContract(t *testing.T) {
	bind := func(target, source string) Mount {
		return Mount{Destination: target, Source: source, Type: "bind", Options: []string{"rbind", "ro"}}
	}
	for _, tc := range []struct {
		name                  string
		base, requested, want []Mount
		wantError             string
	}{
		{name: "empty"},
		{
			name:      "replace all mount fields",
			base:      []Mount{bind("/data", "/default")},
			requested: []Mount{{Destination: "/data", Source: "tmpfs", Type: "tmpfs", Options: []string{"rw", "size=1m"}}},
			want:      []Mount{{Destination: "/data", Source: "tmpfs", Type: "tmpfs", Options: []string{"rw", "size=1m"}}},
		},
		{
			name:      "parent first with independent mounts",
			requested: []Mount{bind("/app/logs/nested", "/child"), bind("/unrelated", "/other"), bind("/app/logs", "/parent")},
			want:      []Mount{bind("/app/logs", "/parent"), bind("/app/logs/nested", "/child"), bind("/unrelated", "/other")},
		},
		{
			name:      "ancestor chain and component boundary",
			requested: []Mount{bind("/a/b/c", "/child"), bind("/ab", "/unrelated"), bind("/a", "/parent"), bind("/a/b", "/middle")},
			want:      []Mount{bind("/a", "/parent"), bind("/a/b", "/middle"), bind("/a/b/c", "/child"), bind("/ab", "/unrelated")},
		},
		{
			name:      "root mount precedes descendants",
			requested: []Mount{bind("/child", "/child-source"), bind("/", "/root-source")},
			want:      []Mount{bind("/", "/root-source"), bind("/child", "/child-source")},
		},
		{
			name:      "host source keeps original resolution",
			requested: []Mount{bind("/data", "link/../relative-source/")},
			want:      []Mount{bind("/data", "link/../relative-source/")},
		},
		{name: "duplicate baseline", base: []Mount{bind("/data", "/one"), bind("/data", "/two")}, wantError: "duplicate mount destination"},
		{name: "duplicate request", requested: []Mount{bind("/data", "/one"), bind("/data", "/two")}, wantError: "duplicate mount destination"},
		{name: "identical request duplicate", requested: []Mount{bind("/data", "/one"), bind("/data", "/one")}, wantError: "duplicate mount destination"},
		{name: "request trailing slash", requested: []Mount{bind("/data/", "/one")}, wantError: "canonical absolute"},
		{name: "request dot component", requested: []Mount{bind("/app/./logs", "/one")}, wantError: "canonical absolute"},
		{name: "request dot dot", requested: []Mount{bind("/app/../logs", "/one")}, wantError: "canonical absolute"},
		{name: "request duplicate separator", requested: []Mount{bind("/app//logs", "/one")}, wantError: "canonical absolute"},
		{name: "request relative", requested: []Mount{bind("data", "/one")}, wantError: "canonical absolute"},
		{name: "request empty", requested: []Mount{bind("", "/one")}, wantError: "canonical absolute"},
		{name: "request NUL", requested: []Mount{bind("/data\x00", "/one")}, wantError: "canonical absolute"},
		{name: "baseline alias", base: []Mount{bind("/data/", "/one")}, wantError: "canonical absolute"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundles := t.TempDir()
			loader, err := NewBundleLoader("", bundles)
			if err != nil {
				t.Fatal(err)
			}
			loader.baseSpec.Mounts = tc.base
			baseline := loader.baseSpec.DeepCopy()
			config := StartConfig{Rootfs: t.TempDir(), Resources: &api.LinuxSandboxResources{}}
			for _, m := range tc.requested {
				config.Mounts = append(config.Mounts, &api.Mount{Target: m.Destination, Type: m.Type, Options: m.Options, Source: &api.Mount_HostPath{HostPath: m.Source}})
			}
			bundle, spec, err := loader.GenerateOci(OciLoadOptions{SandboxID: "mount-contract", CgroupPath: "/test", Config: config})
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error = %v, want %q", err, tc.wantError)
				}
				if _, err := os.Stat(filepath.Join(bundles, "mount-contract", "config.json")); !os.IsNotExist(err) {
					t.Fatalf("invalid mounts created config: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(spec.Mounts, tc.want) {
				t.Fatalf("mounts = %#v, want %#v", spec.Mounts, tc.want)
			}
			saved, err := LoadSpec(filepath.Join(bundle, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(saved.Mounts, tc.want) {
				t.Fatalf("saved mounts = %#v, want %#v", saved.Mounts, tc.want)
			}
			if !reflect.DeepEqual(loader.baseSpec, baseline) {
				t.Fatal("mount merge changed shared baseline")
			}
		})
	}
}

func TestNewBundleLoaderRejectsInvalidBaseMounts(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base.json")
	if err := os.WriteFile(base, []byte(`{"mounts":[{"destination":"/data/"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	bundles := filepath.Join(t.TempDir(), "not-created")
	if _, err := NewBundleLoader(base, bundles); err == nil || !strings.Contains(err.Error(), "canonical absolute") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(bundles); !os.IsNotExist(err) {
		t.Fatalf("invalid base prepared bundle root: %v", err)
	}
}
