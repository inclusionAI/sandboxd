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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func writeFilestoreFixture(t *testing.T, checkpointDir, manifest string) string {
	t.Helper()
	dir := filepath.Join(checkpointDir, filestoreDirectoryName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filestoreManifestName), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFilestoreRestoreDirectory(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, file string
		wantErr              bool
	}{
		{name: "empty-set", manifest: `{"filestores":[]}`},
		{name: "null-set", manifest: `{"filestores":null}`},
		{name: "unused-filestore", manifest: `{"filestores":[{"file":"filestore-0","size_bytes":0}]}`, file: "filestore-0"},
		{name: "missing-field", manifest: `{}`, wantErr: true},
		{name: "bad-json", manifest: `{`, wantErr: true},
		{name: "missing-file", manifest: `{"filestores":[{"file":"filestore-0"}]}`, wantErr: true},
		{name: "size-mismatch", manifest: `{"filestores":[{"file":"filestore-0","size_bytes":4}]}`, file: "filestore-0", wantErr: true},
		{name: "escape", manifest: `{"filestores":[{"file":"../outside"}]}`, wantErr: true},
		{name: "absolute", manifest: `{"filestores":[{"file":"/outside"}]}`, wantErr: true},
		{name: "duplicate", manifest: `{"filestores":[{"file":"filestore-0"},{"file":"filestore-0"}]}`, file: "filestore-0", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := writeFilestoreFixture(t, root, tc.manifest)
			if tc.file != "" {
				if err := os.WriteFile(filepath.Join(dir, tc.file), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := filestoreRestoreDirectory(root)
			if (err != nil) != tc.wantErr {
				t.Fatalf("directory=%q, error=%v, want error=%v", got, err, tc.wantErr)
			}
			if err == nil && got != dir {
				t.Fatalf("got %q, want %q", got, dir)
			}
		})
	}
}

func TestFilestoreRestoreRejectsPartialAndSymlinkedArtifacts(t *testing.T) {
	for _, target := range []string{"directory", "manifest", "filestore", "partial"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			dir := writeFilestoreFixture(t, root, `{"filestores":[{"file":"filestore-0","size_bytes":0}]}`)
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, nil, 0600); err != nil {
				t.Fatal(err)
			}
			var link string
			switch target {
			case "directory":
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				link = dir
			case "manifest", "partial":
				link = filepath.Join(dir, filestoreManifestName)
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
			case "filestore":
				link = filepath.Join(dir, "filestore-0")
			}
			if target != "partial" {
				if err := os.Symlink(outside, link); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := filestoreRestoreDirectory(root); err == nil {
				t.Fatal("accepted incomplete or symlinked artifact")
			}
		})
	}
	if dir, err := filestoreRestoreDirectory(t.TempDir()); err != nil || dir != "" {
		t.Fatalf("legacy checkpoint: %q, %v", dir, err)
	}
}

func TestReflinkCheckpointRequiresManifest(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "runsc")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	c := NewClientWithOptions(binary, dir, Options{ReflinkFilestores: true})
	if err := c.Checkpoint(context.Background(), "source", dir, false, true); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("checkpoint error = %v", err)
	}
}

func TestReflinkCheckpointArguments(t *testing.T) {
	root := t.TempDir()
	binary, argsPath := filepath.Join(root, "runsc"), filepath.Join(root, "args")
	t.Setenv("RUNSC_TEST_ARGS", argsPath)
	script := `#!/bin/sh
printf '%s\n' "$@" > "$RUNSC_TEST_ARGS"
for arg do
  case "$arg" in
    --filestore-snapshot-dir=*)
      dir="${arg#*=}"
      mkdir -p "$dir"
      printf '{"filestores":[]}\n' > "$dir/filestores.json"
      ;;
  esac
done
`
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(root, "checkpoint")
	c := NewClientWithOptions(binary, root, Options{ReflinkFilestores: true})
	if err := c.Checkpoint(context.Background(), "source", checkpoint, false, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, want := range []string{"--skip-filestore-pages", "--filestore-snapshot-dir=" + filepath.Join(checkpoint, "filestores"), "--leave-running"} {
		if !slices.Contains(args, want) {
			t.Fatalf("missing %q in %q", want, args)
		}
	}
}

func TestCreateAdoptsOnlyForRestore(t *testing.T) {
	root := t.TempDir()
	binary, argsPath := filepath.Join(root, "runsc"), filepath.Join(root, "args")
	t.Setenv("RUNSC_TEST_ARGS", argsPath)
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUNSC_TEST_ARGS\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	c := NewClientWithOptions(binary, root, Options{FilestoreDir: root, ReflinkFilestores: true})
	for _, adopt := range []string{filepath.Join(root, "saved", "filestores"), ""} {
		if err := c.Create(context.Background(), StartArgs{ID: "target", BundleDir: root, FilestoreAdoptDir: adopt}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(argsPath)
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Split(strings.TrimSpace(string(data)), "\n")
		parent := slices.Index(args, "--filestore-parent-mountns=true")
		if parent < 0 || parent >= slices.Index(args, "create") {
			t.Fatalf("source and checkpoint must use the launcher mount: %q", args)
		}
		clone := slices.Index(args, "--filestore-clone-on-adopt=true")
		if adopt == "" {
			if clone >= 0 {
				t.Fatal("adoption leaked into a fresh sandbox")
			}
		} else if clone < 0 || clone >= slices.Index(args, "create") || !slices.Contains(args, "--filestore-adopt-dir="+adopt) {
			t.Fatalf("adoption must precede create: %q", args)
		}
	}
	for _, arg := range []string{"--filestore-adopt-dir=/outside", "--filestore-clone-on-adopt=false", "--filestore-parent-mountns=false"} {
		if err := validateExtraArgs([]string{arg}); err == nil {
			t.Fatalf("operator flag overrode artifact ownership: %q", arg)
		}
	}
}

type filestoreRestoreClient struct {
	successfulRunscClient
	created  StartArgs
	restored bool
}

func (c *filestoreRestoreClient) Create(_ context.Context, args StartArgs) error {
	c.created = args
	return nil
}
func (c *filestoreRestoreClient) Restore(context.Context, StartArgs, string) error {
	c.restored = true
	return nil
}

func TestHandlerRestoresFilestoresInFullMode(t *testing.T) {
	root, checkpoint := t.TempDir(), t.TempDir()
	dir := writeFilestoreFixture(t, checkpoint, `{"filestores":[]}`)
	c := &filestoreRestoreClient{}
	h := &Handler{runsc: c, filestoreDir: root, ociLoader: staticOciLoader{bundlePath: root, spec: &runtimecore.Spec{Root: &runtimecore.Root{Path: root}}}}
	if err := h.Restore(context.Background(), runtimecore.StartConfig{ID: "target", CheckpointDir: checkpoint, Network: &networkmanager.NetResource{}}); err != nil {
		t.Fatal(err)
	}
	if c.created.FilestoreAdoptDir != dir || !c.restored {
		t.Fatalf("restore did not adopt artifact before loading state: %+v", c)
	}
}

func TestHandlerValidatesReflinkMode(t *testing.T) {
	cfg := config.Config{RootDir: filepath.Join(t.TempDir(), "root")}
	cfg.RuntimeConfig.FilestoreDir = t.TempDir()
	cfg.RuntimeConfig.Runsc.CheckpointMode = "reflink"
	h, err := NewHandler(cfg, "runsc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !h.runsc.(*Client).Options.ReflinkFilestores {
		t.Fatal("reflink mode was not propagated")
	}
	cfg.RuntimeConfig.Runsc.CheckpointMode = "incremental"
	if h, err := NewHandler(cfg, "runsc", nil); err != nil || !h.runsc.(*Client).Options.IncrementalFilestores {
		t.Fatalf("incremental mode was not propagated: %v", err)
	}
}

func TestIncrementalGenerationState(t *testing.T) {
	root := t.TempDir()
	c := NewClientWithOptions("runsc", root, Options{FilestoreDir: root, IncrementalFilestores: true})
	origin := t.TempDir()
	manifest := filepath.Join(origin, filestoreManifestName)
	if err := os.WriteFile(manifest, []byte(`{"filestores":[{"file":"filestore-0"},{"file":"filestore-1"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.createGenerationState("worker", origin); err == nil {
		t.Fatal("accepted multiple filestores")
	}
	if err := os.WriteFile(manifest, []byte(`{"filestores":[{"file":"filestore-0"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.createGenerationState("worker", origin); err != nil {
		t.Fatal(err)
	}
	// A running sandbox keeps its capture lineage across a daemon restart.
	restarted := NewClientWithOptions("runsc", root, Options{FilestoreDir: root})
	if exists, err := restarted.hasGenerationState("worker"); err != nil || !exists {
		t.Fatalf("lost capture state: %v", err)
	}
	if err := restarted.removeGenerationState("worker"); err != nil {
		t.Fatal(err)
	}
	if exists, err := restarted.hasGenerationState("worker"); err != nil || exists {
		t.Fatalf("retained deleted generation state: %v", err)
	}
}
