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

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"golang.org/x/sys/unix"
)

func TestSandboxInitCommandCreatesContainerNamespaces(t *testing.T) {
	configReader, configWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer configReader.Close()
	defer configWriter.Close()
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer statusReader.Close()
	defer statusWriter.Close()

	command := sandboxInitCommand(configReader, statusWriter)
	wantFlags := uintptr(
		unix.CLONE_NEWNS |
			unix.CLONE_NEWPID |
			unix.CLONE_NEWUTS |
			unix.CLONE_NEWIPC,
	)
	if command.Path != "/init" ||
		strings.Join(command.Args, " ") != "/init "+sandboxInitMode {
		t.Fatalf("sandbox init command = %q %q", command.Path, command.Args)
	}
	if command.SysProcAttr.Cloneflags != wantFlags {
		t.Fatalf(
			"sandbox clone flags = %#x, want %#x",
			command.SysProcAttr.Cloneflags,
			wantFlags,
		)
	}
	if command.SysProcAttr.Chroot != "" {
		t.Fatalf("agent started sandbox init in chroot %q", command.SysProcAttr.Chroot)
	}
	if command.SysProcAttr.Pdeathsig != 0 {
		t.Fatalf("sandbox init parent death signal = %v", command.SysProcAttr.Pdeathsig)
	}
}

func TestJoinSandboxNamespaces(t *testing.T) {
	var calls []string
	nextFD := 10
	ops := namespaceOperations{
		unshare: func(flags int) error {
			calls = append(calls, fmt.Sprintf("unshare:%#x", flags))
			return nil
		},
		open: func(path string, flags int, mode uint32) (int, error) {
			fd := nextFD
			nextFD++
			calls = append(calls, fmt.Sprintf("open:%s:%d", path, fd))
			return fd, nil
		},
		close: func(fd int) error {
			calls = append(calls, fmt.Sprintf("close:%d", fd))
			return nil
		},
		setns: func(fd, flag int) error {
			calls = append(calls, fmt.Sprintf("setns:%d:%#x", fd, flag))
			return nil
		},
	}
	if err := joinSandboxNamespaces(42, ops); err != nil {
		t.Fatal(err)
	}
	want := []string{
		fmt.Sprintf("unshare:%#x", unix.CLONE_FS),
		"open:/proc/42/ns/ipc:10",
		"open:/proc/42/ns/uts:11",
		"open:/proc/42/ns/mnt:12",
		"open:/proc/42/ns/pid:13",
		fmt.Sprintf("setns:10:%#x", unix.CLONE_NEWIPC),
		fmt.Sprintf("setns:11:%#x", unix.CLONE_NEWUTS),
		fmt.Sprintf("setns:12:%#x", unix.CLONE_NEWNS),
		fmt.Sprintf("setns:13:%#x", unix.CLONE_NEWPID),
		"close:10",
		"close:11",
		"close:12",
		"close:13",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("namespace calls = %q, want %q", calls, want)
	}
}

func TestSandboxExecCommandReliesOnJoinedRoot(t *testing.T) {
	command, err := sandboxCommand(firecrackerproto.ProcessSpec{
		Args: []string{"/bin/sh", "-c", "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if command.SysProcAttr.Chroot != "" {
		t.Fatalf("exec command chroot = %q", command.SysProcAttr.Chroot)
	}
	if command.SysProcAttr.Pdeathsig != 0 {
		t.Fatalf("exec command parent death signal = %v", command.SysProcAttr.Pdeathsig)
	}
}

func TestSwitchContainerRoot(t *testing.T) {
	var calls []string
	ops := rootSwitchOperations{
		mount: func(source, target, fsType string, flags uintptr, data string) error {
			calls = append(calls, "mount:"+source+":"+target+":"+strconv.FormatUint(uint64(flags), 10))
			return nil
		},
		open: func(path string, flags int, mode uint32) (int, error) {
			calls = append(calls, "open:"+path)
			return 42, nil
		},
		close: func(fd int) error {
			calls = append(calls, "close:"+strconv.Itoa(fd))
			return nil
		},
		fchdir: func(fd int) error {
			calls = append(calls, "fchdir:"+strconv.Itoa(fd))
			return nil
		},
		chroot: func(path string) error {
			calls = append(calls, "chroot:"+path)
			return nil
		},
		chdir: func(path string) error {
			calls = append(calls, "chdir:"+path)
			return nil
		},
	}
	if err := switchContainerRoot(containerMountRoot, ops); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mount::/:" + strconv.FormatUint(uint64(unix.MS_REC|unix.MS_PRIVATE), 10),
		"open:" + containerMountRoot,
		"mount:" + containerMountRoot + ":/:" + strconv.FormatUint(uint64(unix.MS_MOVE), 10),
		"fchdir:42",
		"chroot:.",
		"chdir:/",
		"close:42",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("root switch calls = %q, want %q", calls, want)
	}
}

func TestSwitchContainerRootStopsBeforeMoveWhenOpenFails(t *testing.T) {
	wantErr := errors.New("open failed")
	moveCalled := false
	ops := rootSwitchOperations{
		mount: func(source, target, fsType string, flags uintptr, data string) error {
			if flags == unix.MS_MOVE {
				moveCalled = true
			}
			return nil
		},
		open:   func(string, int, uint32) (int, error) { return -1, wantErr },
		close:  func(int) error { return nil },
		fchdir: func(int) error { return nil },
		chroot: func(string) error { return nil },
		chdir:  func(string) error { return nil },
	}
	err := switchContainerRoot(containerMountRoot, ops)
	if !errors.Is(err, wantErr) {
		t.Fatalf("root switch error = %v", err)
	}
	if moveCalled {
		t.Fatal("new root was moved after open failed")
	}
}

func TestContainerPathUnder(t *testing.T) {
	root := t.TempDir()
	path, err := containerPathUnder(root, "/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, "etc/resolv.conf") {
		t.Fatalf("container path = %q", path)
	}
	for _, invalid := range []string{"relative", "/"} {
		if _, err := containerPathUnder(root, invalid); err == nil {
			t.Fatalf("accepted target %q", invalid)
		}
	}
}

func TestEnsureContainerDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	_, err := ensureContainerDirectoryUnder(root, "/escape/data")
	if err == nil || !strings.Contains(err.Error(), "traverses symlink") {
		t.Fatalf("symlink error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "data")); !os.IsNotExist(err) {
		t.Fatalf("created directory outside root: %v", err)
	}
}

func TestMountNativeWritableUnder(t *testing.T) {
	sourceRoot := filepath.Join(t.TempDir(), "native")
	root := t.TempDir()
	var source, target string
	var flags uintptr
	err := mountNativeWritableUnder(
		sourceRoot,
		root,
		2,
		firecrackerproto.NativeWritableMountSpec{Target: "/var/lib/docker"},
		func(gotSource, gotTarget, fsType string, gotFlags uintptr, data string) error {
			source = gotSource
			target = gotTarget
			flags = gotFlags
			if fsType != "" || data != "" {
				t.Fatalf("bind mount arguments = %q, %q", fsType, data)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if source != filepath.Join(sourceRoot, "2") ||
		target != filepath.Join(root, "var/lib/docker") ||
		flags != unix.MS_BIND {
		t.Fatalf("bind mount = %q, %q, %#x", source, target, flags)
	}
	for _, path := range []string{source, target} {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			t.Fatalf("native writable directory %q = %+v, %v", path, info, err)
		}
	}
}

func TestMountNativeWritableUnderRejectsSymlinkTarget(t *testing.T) {
	sourceRoot := filepath.Join(t.TempDir(), "native")
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	mounted := false
	err := mountNativeWritableUnder(
		sourceRoot,
		root,
		0,
		firecrackerproto.NativeWritableMountSpec{Target: "/var/lib/docker"},
		func(string, string, string, uintptr, string) error {
			mounted = true
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "traverses symlink") {
		t.Fatalf("symlink error = %v", err)
	}
	if mounted {
		t.Fatal("native writable mount was attempted for a symlink target")
	}
}

func TestPrepareContainerFileReplacesFinalSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("safe"), 0644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "etc/resolv.conf")
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	resolved, err := prepareContainerFileUnder(root, "/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != target {
		t.Fatalf("resolved file = %q", resolved)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("final symlink still exists: %v", err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "safe" {
		t.Fatalf("outside file = %q, %v", data, err)
	}
}

func TestPrepareContainerFileAtRoot(t *testing.T) {
	root := t.TempDir()
	resolved, err := prepareContainerFileUnder(root, "/entry")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != filepath.Join(root, "entry") {
		t.Fatalf("root-level file = %q", resolved)
	}
}

func TestPrepareContainerFileRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	_, err := prepareContainerFileUnder(root, "/etc/resolv.conf")
	if err == nil || !strings.Contains(err.Error(), "traverses symlink") {
		t.Fatalf("symlink parent error = %v", err)
	}
}

func TestFinishExecInput(t *testing.T) {
	t.Run("pipe closes writer", func(t *testing.T) {
		writer := &recordingWriteCloser{}
		finishExecInput(writer, false)
		if !writer.closed {
			t.Fatal("pipe input was not closed")
		}
		if writer.Len() != 0 {
			t.Fatalf("pipe input = %q", writer.Bytes())
		}
	})

	t.Run("terminal sends EOF without closing master", func(t *testing.T) {
		writer := &recordingWriteCloser{}
		finishExecInput(writer, true)
		if writer.closed {
			t.Fatal("terminal master was closed")
		}
		if !bytes.Equal(writer.Bytes(), []byte{4}) {
			t.Fatalf("terminal input = %v", writer.Bytes())
		}
	})
}

func TestFirecrackerTmpfsParameters(t *testing.T) {
	flags, data, err := firecrackerTmpfsParameters([]string{
		"rw", "nosuid", "nodev", "noexec", "size=1m", "mode=0750",
	})
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.MS_NOSUID == 0 ||
		flags&unix.MS_NODEV == 0 ||
		flags&unix.MS_NOEXEC == 0 ||
		flags&unix.MS_RDONLY != 0 {
		t.Fatalf("tmpfs flags = %#x", flags)
	}
	if data != "size=1m,mode=0750" {
		t.Fatalf("tmpfs data = %q", data)
	}
	if _, _, err := firecrackerTmpfsParameters([]string{"bind"}); err == nil {
		t.Fatal("accepted unsafe tmpfs option")
	}
}

func TestCheckpointHandoff(t *testing.T) {
	root := t.TempDir()
	environment := []string{
		"RUNTIME_ID=source",
		"YR_SEED_FILE=/untrusted",
		"YR_ENV_FILE=/untrusted",
	}
	handoff, err := prepareCheckpointHandoff(root, environment)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.close()
	initialEnvironment, err := os.ReadFile(handoff.environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range environment {
		if !bytes.Contains(initialEnvironment, []byte(entry+"\x00")) {
			t.Fatalf("initial environment = %q, missing %q", initialEnvironment, entry)
		}
	}

	for _, outcome := range []string{"resume", "error", "resume", "resume"} {
		if err := handoff.signal(outcome); err != nil {
			t.Fatalf("signal without reader: %v", err)
		}
	}

	for _, outcome := range []string{"resume", "restore"} {
		result := make(chan struct {
			value string
			err   error
		}, 1)
		go func() {
			data, err := os.ReadFile(handoff.fifoPath)
			result <- struct {
				value string
				err   error
			}{string(data), err}
		}()
		waitForCheckpointReader(t, handoff)
		if err := handoff.signal(outcome); err != nil {
			t.Fatal(err)
		}
		select {
		case read := <-result:
			want := outcome + "\n"
			if read.err != nil || read.value != want {
				t.Fatalf("handoff = %q, %v, want %q", read.value, read.err, want)
			}
		case <-time.After(time.Second):
			t.Fatal("checkpoint handoff timed out")
		}
	}

	if err := writeCheckpointEnvironment(
		handoff.environmentPath,
		[]string{"RUNTIME_ID=restore"},
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(handoff.environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("RUNTIME_ID=restore\x00")) ||
		bytes.Contains(data, []byte("RUNTIME_ID=source")) {
		t.Fatalf("restored environment = %q", data)
	}
}

func TestCheckpointHandoffDeliversRestoreAfterReaderReopens(t *testing.T) {
	handoff, err := prepareCheckpointHandoff(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.close()

	type readResult struct {
		value string
		err   error
	}
	read := func() <-chan readResult {
		result := make(chan readResult, 1)
		go func() {
			data, err := os.ReadFile(handoff.fifoPath)
			result <- readResult{value: string(data), err: err}
		}()
		return result
	}

	result := read()
	waitForCheckpointReader(t, handoff)
	if err := handoff.signal("resume"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.value != "resume\n" {
			t.Fatalf("initial handoff = %q, %v", got.value, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("initial handoff timed out")
	}

	if err := handoff.signal("restore"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-read():
		if got.err != nil || got.value != "restore\n" {
			t.Fatalf("pending restore handoff = %q, %v", got.value, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("restore was not delivered after the FIFO reader reopened")
	}
}

func TestCheckpointHandoffRecreatesRemovedFIFO(t *testing.T) {
	handoff, err := prepareCheckpointHandoff(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.close()
	if err := os.Remove(handoff.fifoPath); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		info, statErr := os.Stat(handoff.fifoPath)
		if statErr == nil && info.Mode()&os.ModeNamedPipe != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("checkpoint FIFO was not recreated: %v", statErr)
		}
		time.Sleep(time.Millisecond)
	}
	result := make(chan struct {
		value string
		err   error
	}, 1)
	go func() {
		data, err := os.ReadFile(handoff.fifoPath)
		result <- struct {
			value string
			err   error
		}{value: string(data), err: err}
	}()
	waitForCheckpointReader(t, handoff)
	if err := handoff.signal("resume"); err != nil {
		t.Fatal(err)
	}
	select {
	case read := <-result:
		if read.err != nil || read.value != "resume\n" {
			t.Fatalf("recreated checkpoint handoff = %q, %v", read.value, read.err)
		}
	case <-time.After(time.Second):
		t.Fatal("recreated checkpoint handoff timed out")
	}
}

func TestCheckpointHandoffCloseWithoutReader(t *testing.T) {
	handoff, err := prepareCheckpointHandoff(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		handoff.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("checkpoint handoff close blocked without a reader")
	}
	if err := handoff.signal("resume"); err != nil {
		t.Fatalf("signal closed handoff: %v", err)
	}
}

func waitForCheckpointReader(t *testing.T, handoff *checkpointHandoff) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		handoff.mu.Lock()
		ready := handoff.reader != nil
		handoff.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("checkpoint handoff reader did not register")
}

type recordingWriteCloser struct {
	bytes.Buffer
	closed bool
}

func (w *recordingWriteCloser) Close() error {
	w.closed = true
	return nil
}
