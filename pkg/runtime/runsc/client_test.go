// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"strings"
	"testing"
)

func TestCreateUsesExactDebugLogPath(t *testing.T) {
	tempDir := t.TempDir()
	argsFile := filepath.Join(tempDir, "args")
	binary := filepath.Join(tempDir, "runsc")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUNSC_TEST_ARGS\"\n"
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatalf("write fake runsc: %v", err)
	}
	t.Setenv("RUNSC_TEST_ARGS", argsFile)

	debugLogPath := filepath.Join(tempDir, "logs", "runsc.log")
	client := NewClientWithOptions(binary, filepath.Join(tempDir, "root"), Options{
		DebugLogPath: debugLogPath,
		FilestoreDir: filepath.Join(tempDir, "filestore"),
	})
	if err := client.Create(context.Background(), StartArgs{
		ID:         "sandbox-id",
		BundleDir:  filepath.Join(tempDir, "bundle"),
		UserStdout: filepath.Join(tempDir, "stdout"),
		UserStderr: filepath.Join(tempDir, "stderr"),
	}); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read fake runsc arguments: %v", err)
	}
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := "-debug-log=" + debugLogPath
	for _, arg := range args {
		if arg == want {
			return
		}
	}
	t.Fatalf("runsc arguments %q do not contain %q", args, want)
}

func TestCreateUsesFileBackedRootOverlay(t *testing.T) {
	tempDir := t.TempDir()
	argsFile := filepath.Join(tempDir, "args")
	binary := filepath.Join(tempDir, "runsc")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUNSC_TEST_ARGS\"\n"
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatalf("write fake runsc: %v", err)
	}
	t.Setenv("RUNSC_TEST_ARGS", argsFile)

	filestoreDir := filepath.Join(tempDir, "filestore")
	client := NewClientWithOptions(binary, filepath.Join(tempDir, "root"), Options{
		FilestoreDir:     filestoreDir,
		OverlayTmpfsSize: "10G",
	})
	if err := client.Create(context.Background(), StartArgs{
		ID:         "sandbox-storage",
		BundleDir:  filepath.Join(tempDir, "bundle"),
		UserStdout: filepath.Join(tempDir, "stdout"),
		UserStderr: filepath.Join(tempDir, "stderr"),
	}); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read fake runsc arguments: %v", err)
	}
	want := "--overlay2=root:dir=" + filestoreDir + ",size=10G\n"
	if !strings.Contains(string(data), want) {
		t.Fatalf("runsc arguments %q do not contain %q", string(data), want)
	}
}

func TestCreateRejectsMissingFilestore(t *testing.T) {
	client := NewClientWithOptions("/usr/local/bin/runsc", t.TempDir(), Options{})
	err := client.Create(context.Background(), StartArgs{
		ID:        "sandbox-storage",
		BundleDir: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "filestore directory is empty") {
		t.Fatalf("Create() error = %v, want missing filestore error", err)
	}
}

func TestGlobalArgsIncludePlatform(t *testing.T) {
	client := NewClientWithOptions("/usr/local/bin/runsc", "/run/runsc", Options{
		Platform: "kvm",
	})
	args := client.globalArgs()
	if got := strings.Join(args, " "); got != "--root /run/runsc --platform=kvm" {
		t.Fatalf("global args = %q", got)
	}
}

func TestGlobalArgsIgnoreCgroups(t *testing.T) {
	client := NewClientWithOptions("/usr/local/bin/runsc", "/run/runsc", Options{
		IgnoreCgroups: true,
	})
	args := client.globalArgs()
	if got := strings.Join(args, " "); got != "--root /run/runsc --ignore-cgroups" {
		t.Fatalf("global args = %q", got)
	}
}

func TestCreateUsesPerSandboxRootOverlay(t *testing.T) {
	tempDir := t.TempDir()
	argsFile := filepath.Join(tempDir, "args")
	binary := filepath.Join(tempDir, "runsc")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUNSC_TEST_ARGS\"\n"
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatalf("write fake runsc: %v", err)
	}
	t.Setenv("RUNSC_TEST_ARGS", argsFile)

	client := NewClientWithOptions(binary, filepath.Join(tempDir, "root"), Options{
		FilestoreDir:     filepath.Join(tempDir, "filestore"),
		OverlayTmpfsSize: "10G",
	})
	wantOverlay := "root:dir=/var/lib/sandboxd/filestore,size=1073741824"
	if err := client.Create(context.Background(), StartArgs{
		ID:          "sandbox-storage",
		BundleDir:   filepath.Join(tempDir, "bundle"),
		UserStdout:  filepath.Join(tempDir, "stdout"),
		UserStderr:  filepath.Join(tempDir, "stderr"),
		RootOverlay: wantOverlay,
	}); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read fake runsc arguments: %v", err)
	}
	if !strings.Contains(string(data), "--overlay2="+wantOverlay+"\n") {
		t.Fatalf("runsc arguments %q do not contain per-sandbox overlay %q", string(data), wantOverlay)
	}
}
