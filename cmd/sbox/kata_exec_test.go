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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestKataExecProcess(t *testing.T) {
	bundlePath := t.TempDir()
	spec := specs.Spec{
		Process: &specs.Process{
			Args: []string{"/bin/sh"},
			Cwd:  "/",
			Env:  []string{"PATH=/bin", "A=old"},
			User: specs.User{UID: 1, GID: 2},
		},
	}
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	process, err := kataExecProcess(bundlePath, execRequest{
		command: "/bin/echo",
		args:    []string{"hello"},
		user:    "1000:1001",
		env:     []string{"A=new", "B=value"},
		cwd:     "/tmp",
		tty:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !process.Terminal || process.Cwd != "/tmp" {
		t.Fatalf("process terminal/cwd = %v/%q", process.Terminal, process.Cwd)
	}
	if process.User.UID != 1000 || process.User.GID != 1001 {
		t.Fatalf("process user = %+v", process.User)
	}
	if got := process.Args; len(got) != 2 || got[0] != "/bin/echo" || got[1] != "hello" {
		t.Fatalf("process args = %v", got)
	}
	wantEnv := []string{"PATH=/bin", "A=new", "B=value"}
	if len(process.Env) != len(wantEnv) {
		t.Fatalf("process env = %v", process.Env)
	}
	for index := range wantEnv {
		if process.Env[index] != wantEnv[index] {
			t.Fatalf("process env = %v, want %v", process.Env, wantEnv)
		}
	}
}

func TestOpenKataExecIOPreparesShimEndpoints(t *testing.T) {
	root := t.TempDir()
	stdinPath := filepath.Join(root, "stdin")
	stdoutPath := filepath.Join(root, "stdout")
	stderrPath := filepath.Join(root, "stderr")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streams, err := openKataExecIO(ctx, stdinPath, stdoutPath, stderrPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer streams.Close()

	for _, path := range []string{stdinPath, stdoutPath, stderrPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("%s is not a FIFO", path)
		}
	}

	// runtime-rs opens output FIFOs while registering an exec process. The
	// local readers must therefore exist before the Exec RPC is sent.
	deadline := time.Now().Add(time.Second)
	for {
		fd, err := syscall.Open(stdoutPath, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = syscall.Close(fd)
			break
		}
		if err != syscall.ENXIO || time.Now().After(deadline) {
			t.Fatalf("open shim stdout endpoint: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMergeKataExecEnv(t *testing.T) {
	got := mergeKataExecEnv([]string{"PATH=/bin", "A=old"}, []string{"A=new", "B=value"})
	want := []string{"PATH=/bin", "A=new", "B=value"}
	if len(got) != len(want) {
		t.Fatalf("environment = %v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("environment = %v, want %v", got, want)
		}
	}
}

func TestKataProcessTypeURL(t *testing.T) {
	if kataProcessTypeURL != "types.containerd.io/opencontainers/runtime-spec/1/Process" {
		t.Fatalf("unexpected Kata process type URL %q", kataProcessTypeURL)
	}
}
