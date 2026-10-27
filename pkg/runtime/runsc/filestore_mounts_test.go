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
	"encoding/json"
	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileBackedTmpfsStorageBudget(t *testing.T) {
	h := Handler{sandboxRoot: t.TempDir()}
	original := runtimecore.StartConfig{ID: "quota", WritableLayerLimitBytes: 4 << 30, ExtraConfig: `{"fileBackedTmpfsMounts":[{"target":"/var/lib/snapshots","sizeMB":1024}]}`, Annotations: map[string]string{"keep": "value"}}
	got, enabled, err := h.prepareFileBackedTmpfs(original)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled || got.WritableLayerLimitBytes != 3<<30 {
		t.Fatalf("incorrect reservation: %+v", got)
	}
	if got.Mounts[0].GetTarget() != "/var/lib/snapshots" {
		t.Fatal(got.Mounts)
	}
	if _, err := os.Stat(got.Mounts[0].GetHostPath()); err != nil {
		t.Fatal(err)
	}
	if got.Annotations["dev.gvisor.spec.mount.akernel-filestore-0.filestore"] != "anonymous" {
		t.Fatal(got.Annotations)
	}
	if original.WritableLayerLimitBytes != 4<<30 || len(original.Mounts) != 0 || len(original.Annotations) != 1 {
		t.Fatal("caller configuration mutated")
	}
}

func TestFileBackedTmpfsRejectsInvalidStorage(t *testing.T) {
	for _, extra := range []string{
		`{"fileBackedTmpfsMounts":[{"target":"relative","sizeMB":1}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/","sizeMB":1}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/proc/data","sizeMB":1}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/mnt/data/..","sizeMB":1}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/data","sizeMB":0}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/data","sizeMB":4096}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/data","sizeMB":18446744073709551615}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/images/sub","sizeMB":1}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/data","sizeMB":1},{"target":"/data/sub","sizeMB":1}]}`,
		`{"fileBackedTmpfsMounts":[{"target":"/data","sizeMB":2048},{"target":"/other","sizeMB":2048}]}`,
	} {
		h := Handler{sandboxRoot: t.TempDir()}
		_, _, err := h.prepareFileBackedTmpfs(runtimecore.StartConfig{ID: "invalid", WritableLayerLimitBytes: 4 << 30, ExtraConfig: extra, Mounts: []*runtimeapi.Mount{{Target: "/images"}}})
		if err == nil {
			t.Fatalf("accepted invalid storage config %s", extra)
		}
	}
}

func TestFilestoreCheckpointOptInSurvivesClientRestart(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "runsc")
	argsFile := filepath.Join(dir, "args")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUNSC_TEST_ARGS\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNSC_TEST_ARGS", argsFile)
	client := NewClient(binary, dir)
	state := map[string]any{"spec": map[string]any{"annotations": map[string]string{filestoreCheckpointAnnotation: filestoreCheckpointFormat}}}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(client.stateFilePath("snapshot"), data, 0600); err != nil {
		t.Fatal(err)
	}
	filestores := filepath.Join(dir, "checkpoint", "filestores")
	if err := os.MkdirAll(filestores, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filestores, "filestores.json"), []byte(`{"filestores":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := client.Checkpoint(context.Background(), "snapshot", filepath.Join(dir, "checkpoint"), false, true); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--skip-filestore-pages\n", "--filestore-snapshot-dir=" + filepath.Join(dir, "checkpoint", "filestores") + "\n"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("missing %q: %s", want, args)
		}
	}
}

type filestoreRecordingClient struct {
	successfulRunscClient
	created       StartArgs
	restoredImage string
}

func (c *filestoreRecordingClient) Create(_ context.Context, args StartArgs) error {
	c.created = args
	return nil
}
func (c *filestoreRecordingClient) Restore(_ context.Context, _ StartArgs, image string) error {
	c.restoredImage = image
	return nil
}

func TestFilestoreRestoreUsesCheckpointSiblingDirectory(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "present"}[present], func(t *testing.T) {
			root := t.TempDir()
			checkpoint := t.TempDir()
			filestores := filepath.Join(checkpoint, "filestores")
			if err := os.WriteFile(filepath.Join(checkpoint, checkpointImageName), []byte("kernel state"), 0600); err != nil {
				t.Fatal(err)
			}
			if present {
				if err := os.Mkdir(filestores, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filestores, "filestores.json"), []byte(`{"filestores":[]}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			client := &filestoreRecordingClient{}
			h := Handler{runsc: client, sandboxRoot: root, filestoreDir: t.TempDir(), ociLoader: staticOciLoader{bundlePath: filepath.Join(root, "restore"), spec: &runtimecore.Spec{Root: &runtimecore.Root{Path: t.TempDir()}}}}
			err := h.Restore(context.Background(), runtimecore.StartConfig{ID: "restore", CheckpointDir: checkpoint, Network: &networkmanager.NetResource{}, WritableLayerLimitBytes: 4 << 30, ExtraConfig: `{"fileBackedTmpfsMounts":[{"target":"/data","sizeMB":1024}]}`})
			if !present {
				if err == nil || client.created.ID != "" {
					t.Fatalf("missing artifact must fail before create: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if client.created.FilestoreAdoptDir != filestores || client.restoredImage != filepath.Join(checkpoint, checkpointImageName) {
				t.Fatalf("incorrect artifact paths: %+v, %s", client.created, client.restoredImage)
			}
		})
	}
}
