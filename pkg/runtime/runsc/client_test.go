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

func TestSeededCreatePreservesHostPathsAndChangesOnlyChildCWD(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for _, directory := range []string{"bin", "bundle"} {
		if err := os.Mkdir(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	argsFile, cwdFile := filepath.Join(root, "args"), filepath.Join(root, "cwd")
	t.Setenv("RUNSC_TEST_ARGS", argsFile)
	t.Setenv("RUNSC_TEST_CWD", cwdFile)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUNSC_TEST_ARGS\"\npwd > \"$RUNSC_TEST_CWD\"\nprintf 'user output\\n'\n"
	if err := os.WriteFile("bin/runsc", []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	devicePaths := "--platform_device_path=kvm=devices/custom-kvm,systrap=/dev/systrap-device"
	c := NewClientWithOptions("./bin/runsc", "state", Options{FilestoreDir: "filestore", DebugLogPath: "logs/", ExtraArgs: []string{"--log=internal.log", "--profile-cpu=cpu.prof", "--profiling-metrics-log=-", devicePaths}})
	args := StartArgs{ID: "seeded", BundleDir: "bundle", UserStdout: "user.stdout", RootOverlay: "root:dir=private,size=10G", FilestoreAdoptDir: "adopt", SeededRootfs: true}
	if err := c.Create(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, want := range []string{filepath.Join(root, "state"), filepath.Join(root, "bundle"), "--overlay2=root:dir=" + filepath.Join(root, "private") + ",size=10G", "--filestore-adopt-dir=" + filepath.Join(root, "adopt"), "-debug-log=" + filepath.Join(root, "logs") + "/", "--log=" + filepath.Join(root, "internal.log"), "--profile-cpu=" + filepath.Join(root, "cpu.prof"), "--profiling-metrics-log=-", "--platform_device_path=kvm=" + filepath.Join(root, "devices/custom-kvm") + ",systrap=/dev/systrap-device", "--allow-rootfs-tar-annotation=true", "--restore-spec-validation=enforce"} {
		if !slices.Contains(got, want) {
			t.Fatalf("missing normalized argument %q: %q", want, got)
		}
	}
	cwd, err := os.ReadFile(cwdFile)
	if err != nil || strings.TrimSpace(string(cwd)) != filepath.Join(root, "bundle") {
		t.Fatalf("child cwd=%q err=%v", cwd, err)
	}
	if output, err := os.ReadFile("user.stdout"); err != nil || string(output) != "user output\n" {
		t.Fatalf("stdio moved with child cwd: %q %v", output, err)
	}
	if c.RootDir != "state" || c.Binary != "./bin/runsc" || c.Options.ExtraArgs[0] != "--log=internal.log" || c.Options.ExtraArgs[3] != devicePaths || args.BundleDir != "bundle" {
		t.Fatal("Create mutated shared client or caller arguments")
	}
	args.SeededRootfs = false
	if err := c.Create(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	cwd, err = os.ReadFile(cwdFile)
	if err != nil || strings.TrimSpace(string(cwd)) != root {
		t.Fatalf("unseeded child cwd changed: %q %v", cwd, err)
	}
	data, err = os.ReadFile(argsFile)
	if err != nil || !strings.Contains(string(data), "--restore-spec-validation=enforce\n") || strings.Contains(string(data), "--allow-rootfs-tar-annotation=true") || !strings.Contains(string(data), devicePaths+"\n") {
		t.Fatalf("legacy candidate lost strict validation or enabled tar import: %q %v", data, err)
	}
}

func TestAbsolutePlatformDevicePaths(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for _, tc := range []struct {
		name, value, want string
		wantErr           bool
	}{
		{name: "unset"},
		{name: "absolute single", value: "/dev/custom-kvm", want: "/dev/custom-kvm"},
		{name: "relative single", value: "devices/custom-kvm", want: filepath.Join(root, "devices/custom-kvm")},
		{name: "comma in single path", value: "devices/kvm,other", want: filepath.Join(root, "devices/kvm,other")},
		{name: "absolute mapping", value: "kvm=/dev/custom-kvm", want: "kvm=/dev/custom-kvm"},
		{name: "relative mapping", value: "kvm=devices/custom-kvm", want: "kvm=" + filepath.Join(root, "devices/custom-kvm")},
		{name: "multiple mappings", value: "kvm=/dev/custom-kvm,systrap=/dev/systrap-device", want: "kvm=/dev/custom-kvm,systrap=/dev/systrap-device"},
		{name: "mixed mappings", value: "kvm=devices/custom-kvm,future=/dev/future", want: "kvm=" + filepath.Join(root, "devices/custom-kvm") + ",future=/dev/future"},
		{name: "equals in mapped path", value: "kvm=devices/kvm=custom", want: "kvm=" + filepath.Join(root, "devices/kvm=custom")},
		{name: "empty name", value: "=/dev/kvm", wantErr: true},
		{name: "empty path", value: "kvm=", wantErr: true},
		{name: "empty mapping", value: "kvm=/dev/kvm,", wantErr: true},
		{name: "missing equals", value: "kvm=/dev/kvm,systrap", wantErr: true},
		{name: "duplicate platform", value: "kvm=/dev/kvm,kvm=/dev/other", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := absoluteRunscPathFlag("--platform_device_path", tc.value)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("normalize %q: got %q, err=%v; want %q, error=%v", tc.value, got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestSeededCreatePreservesSymlinkParentResolution(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	actual := filepath.Join(root, "actual")
	for _, name := range []string{"nested", "state", "bundle", "private", "adopt"} {
		directory := filepath.Join(actual, name)
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "marker"), []byte("intended-"+name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(actual, "nested"), "device-link"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actual, "device"), []byte("intended-device"), 0644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root|--bundle) key="${1#--}"; shift; cat "$1/marker" > "$RUNSC_TEST_PROOF/$key" ;;
        --overlay2=*) path="${1#--overlay2=root:dir=}"; path="${path%%,*}"; cat "$path/marker" > "$RUNSC_TEST_PROOF/overlay" ;;
        --filestore-adopt-dir=*) cat "${1#--filestore-adopt-dir=}/marker" > "$RUNSC_TEST_PROOF/adopt" ;;
        --platform_device_path=*) cat "${1#--platform_device_path=kvm=}" > "$RUNSC_TEST_PROOF/device" ;;
        -debug-log=*) printf debug > "${1#-debug-log=}" ;;
        --log=*) printf log > "${1#--log=}" ;;
    esac
    shift
done
pwd -P > "$RUNSC_TEST_PROOF/cwd"
`
	if err := os.WriteFile(filepath.Join(actual, "runsc"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("runsc", []byte("#!/bin/sh\nexit 93\n"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"relative", "absolute"} {
		t.Run(mode, func(t *testing.T) {
			prefix := "device-link/../"
			if mode == "absolute" {
				prefix = root + "/" + prefix
			}
			proof := t.TempDir()
			t.Setenv("RUNSC_TEST_PROOF", proof)
			c := NewClientWithOptions(prefix+"runsc", prefix+"state", Options{
				FilestoreDir: prefix + "private", DebugLogPath: prefix + mode + ".debug",
				ExtraArgs: []string{"--platform_device_path=kvm=" + prefix + "device", "--log=" + prefix + mode + ".log"},
			})
			overlay := "root:dir=" + prefix + "private,size=10G"
			if mode == "absolute" {
				overlay = "" // Exercise the normalized default filestore too.
			}
			if err := c.Create(context.Background(), StartArgs{ID: mode, BundleDir: prefix + "bundle", RootOverlay: overlay, FilestoreAdoptDir: prefix + "adopt", SeededRootfs: true}); err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]string{"root": "intended-state", "bundle": "intended-bundle", "overlay": "intended-private", "adopt": "intended-adopt", "device": "intended-device", "cwd": filepath.Join(actual, "bundle") + "\n"} {
				if data, err := os.ReadFile(filepath.Join(proof, name)); err != nil || string(data) != want {
					t.Fatalf("%s resolved incorrectly: %q, %v; want %q", name, data, err, want)
				}
			}
			for suffix, want := range map[string]string{".log": "log", ".debug": "debug"} {
				if data, err := os.ReadFile(filepath.Join(actual, mode+suffix)); err != nil || string(data) != want {
					t.Fatalf("new output path resolved incorrectly: %q, %v", data, err)
				}
				if _, err := os.Stat(filepath.Join(root, mode+suffix)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("output was written through a cleaned path: %v", err)
				}
			}
		})
	}
}

func TestSeededCreateRetainsPATHLookupAndRejectsManagedFlags(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "seeded-runsc"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	c := NewClientWithOptions("seeded-runsc", t.TempDir(), Options{FilestoreDir: t.TempDir()})
	if err := c.Create(context.Background(), StartArgs{ID: "path", BundleDir: t.TempDir(), SeededRootfs: true}); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Dir(root))
	t.Setenv("PATH", filepath.Base(root)+string(os.PathListSeparator)+os.Getenv("PATH"))
	// Preserve the caller's explicit opt-in to relative PATH lookup. The
	// production cmd.Err check still retains exec.ErrDot under default policy.
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",execerrdot=0")
	if err := c.Create(context.Background(), StartArgs{ID: "relative-path", BundleDir: t.TempDir(), SeededRootfs: true}); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--allow-rootfs-tar-annotation=true", "--allow-rootfs-tar-annotation=false", "--restore-spec-validation=ignore", "--restore-spec-validation=enforce"} {
		if err := validateExtraArgs([]string{flag}); err == nil {
			t.Fatalf("allowed managed flag %s", flag)
		}
	}
}

func TestDeleteDeadlineWithInheritedOutputPipe(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "runsc")
	// The direct child is killed on deadline, but a short-lived grandchild
	// keeps the output pipe open. WaitDelay must bound CombinedOutput too.
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nsleep 4 &\nwait\n"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := NewClient(binary, dir).Delete(ctx, "sbox-hung-delete", true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Delete error=%v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Delete blocked on inherited pipe for %s", elapsed)
	}
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
			if strings.Contains(arguments, "--skip-filestore-pages") || strings.Contains(arguments, "--filestore-snapshot-dir") {
				t.Fatalf("default checkpoint must retain full serialization: %q", arguments)
			}
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

func TestListDeadlineWithInheritedOutputPipe(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "runsc")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nsleep 4 &\nwait\n"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := NewClient(binary, dir).ListJSON(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ListJSON error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("ListJSON blocked on inherited pipe for %s", elapsed)
	}
}
