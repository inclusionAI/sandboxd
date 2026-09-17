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
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
		ExtraArgs:    []string{"--net-raw=true", "--allow-packet-socket-write=true"},
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
	for _, flag := range client.Options.ExtraArgs {
		if index := slices.Index(args, flag); index < 0 || index >= slices.Index(args, "create") {
			t.Fatalf("extra flag %q must precede create: %q", flag, args)
		}
	}
	want := "-debug-log=" + debugLogPath
	for _, arg := range args {
		if arg == want {
			return
		}
	}
	t.Fatalf("runsc arguments %q do not contain %q", args, want)
}

func TestExtraArgs(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--net-raw=false", "--allow-packet-socket-write=true"}} {
		if err := validateExtraArgs(args); err != nil {
			t.Fatal(err)
		}
		client := NewClientWithOptions("runsc", "/run/runsc", Options{ExtraArgs: args})
		want := args
		if want == nil {
			want = []string{"--net-raw=true"}
		}
		if !slices.Equal(client.Options.ExtraArgs, want) {
			t.Fatalf("extra args = %v, want %v", client.Options.ExtraArgs, want)
		}
	}
	for _, arg := range []string{"", "--", "--log", "--log-format", "--net-raw", "--allow-packet-socket-write", "create", "true", "--root=/other", "--network=host", "--platform=kvm", "--overlay2=none", "--ignore-cgroups=true", "--debug-log=/other", "--bundle=/other"} {
		if err := validateExtraArgs([]string{arg}); err == nil {
			t.Errorf("accepted invalid extra arg %q", arg)
		}
	}
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

func TestOpenPlatformDeviceForKVM(t *testing.T) {
	devicePath := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(devicePath, []byte("device"), 0600); err != nil {
		t.Fatal(err)
	}
	client := NewClientWithOptions("/usr/local/bin/runsc", t.TempDir(), Options{
		Platform:           "kvm",
		PlatformDevicePath: devicePath,
	})

	device, err := client.openPlatformDevice()
	if err != nil {
		t.Fatal(err)
	}
	if device == nil {
		t.Fatal("openPlatformDevice() returned nil for kvm")
	}
	defer device.Close()
	if got := device.Name(); got != devicePath {
		t.Fatalf("device path = %q, want %q", got, devicePath)
	}
}

func TestOpenPlatformDeviceSkipsSystrap(t *testing.T) {
	client := NewClientWithOptions("/usr/local/bin/runsc", t.TempDir(), Options{
		Platform:           "systrap",
		PlatformDevicePath: filepath.Join(t.TempDir(), "missing"),
	})

	device, err := client.openPlatformDevice()
	if err != nil {
		t.Fatal(err)
	}
	if device != nil {
		device.Close()
		t.Fatal("openPlatformDevice() returned a device for systrap")
	}
}

func TestCheckpointArguments(t *testing.T) {
	for _, test := range []struct {
		name         string
		compress     bool
		leaveRunning bool
		compression  string
	}{
		{name: "raw-stop", compression: "none"},
		{
			name: "compressed-leave-running", compress: true,
			leaveRunning: true, compression: "flate-best-speed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			argsFile := filepath.Join(tempDir, "args")
			binary := filepath.Join(tempDir, "runsc")
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUNSC_TEST_ARGS\"\n"
			if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RUNSC_TEST_ARGS", argsFile)
			client := NewClient(binary, filepath.Join(tempDir, "root"))
			if err := client.Checkpoint(
				context.Background(),
				"sbox-checkpoint",
				filepath.Join(tempDir, "checkpoint"),
				test.compress,
				test.leaveRunning,
			); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			arguments := string(data)
			if !strings.Contains(
				arguments,
				"--compression="+test.compression+"\n",
			) {
				t.Fatalf("checkpoint arguments = %q", arguments)
			}
			hasLeaveRunning := strings.Contains(arguments, "--leave-running\n")
			if hasLeaveRunning != test.leaveRunning {
				t.Fatalf("leave-running argument = %v, want %v", hasLeaveRunning, test.leaveRunning)
			}
		})
	}
}

func TestCheckpointCancellationTerminatesCommand(t *testing.T) {
	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "runsc")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 30\n"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := NewClient(binary, filepath.Join(tempDir, "root")).Checkpoint(
		ctx,
		"sbox-checkpoint",
		filepath.Join(tempDir, "checkpoint"),
		true,
		true,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("checkpoint error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("checkpoint cancellation took %s", elapsed)
	}
}

func TestOpenRestoreFilesSingleFile(t *testing.T) {
	tempDir := t.TempDir()
	imagePath := filepath.Join(tempDir, "checkpoint.img")
	if err := os.WriteFile(imagePath, []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}

	files, havePagesFile, err := openRestoreFiles(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	if havePagesFile {
		t.Fatal("HavePagesFile = true, want false")
	}
	if len(files) != 1 || files[0].Name() != imagePath {
		t.Fatalf("restore files = %v, want only %s", fileNames(files), imagePath)
	}
}

func TestOpenRestoreFilesSplitPages(t *testing.T) {
	tempDir := t.TempDir()
	paths := []string{
		filepath.Join(tempDir, "checkpoint.img"),
		filepath.Join(tempDir, checkpointPagesMetadataName),
		filepath.Join(tempDir, checkpointPagesName),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0600); err != nil {
			t.Fatal(err)
		}
	}

	files, havePagesFile, err := openRestoreFiles(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	if !havePagesFile {
		t.Fatal("HavePagesFile = false, want true")
	}
	if got := fileNames(files); strings.Join(got, "\n") != strings.Join(paths, "\n") {
		t.Fatalf("restore files = %v, want %v", got, paths)
	}
}

func TestOpenRestoreFilesRejectsIncompletePages(t *testing.T) {
	for _, presentName := range []string{
		checkpointPagesMetadataName,
		checkpointPagesName,
	} {
		t.Run(presentName, func(t *testing.T) {
			tempDir := t.TempDir()
			imagePath := filepath.Join(tempDir, "checkpoint.img")
			if err := os.WriteFile(imagePath, []byte("state"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tempDir, presentName), []byte("pages"), 0600); err != nil {
				t.Fatal(err)
			}

			files, havePagesFile, err := openRestoreFiles(imagePath)
			if err == nil || !strings.Contains(err.Error(), "incomplete checkpoint page files") {
				closeFiles(files)
				t.Fatalf("openRestoreFiles() error = %v, want incomplete page files", err)
			}
			if havePagesFile {
				t.Fatal("HavePagesFile = true after incomplete checkpoint")
			}
		})
	}
}

func fileNames(files []*os.File) []string {
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name())
	}
	return names
}
