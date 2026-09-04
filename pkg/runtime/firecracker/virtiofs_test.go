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

package firecracker

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFirecrackerVirtioFSExportPath(t *testing.T) {
	root := t.TempDir()
	path, err := firecrackerVirtioFSExportPath(root, "mounts/0001")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, "mounts/0001") {
		t.Fatalf("export path = %q", path)
	}
	for _, invalid := range []string{"", ".", "..", "../escape", "/absolute"} {
		if _, err := firecrackerVirtioFSExportPath(root, invalid); err == nil {
			t.Fatalf("accepted export path %q", invalid)
		}
	}
}

func TestCommandHasOption(t *testing.T) {
	arguments := []string{
		"virtiofsd",
		"--shared-dir", "/storage/shared",
		"--socket-path", "/run/virtiofs.sock",
		"--readonly",
		"--no-announce-submounts",
	}
	if !commandHasOption(arguments, "--shared-dir", "/storage/shared") {
		t.Fatal("shared-dir option was not found")
	}
	if commandHasOption(arguments, "--socket-path", "/run/other.sock") {
		t.Fatal("mismatched socket-path option was accepted")
	}
	if commandHasOption(arguments, "--readonly", "--sandbox") {
		t.Fatal("flag without a value was accepted as an option pair")
	}
	if !commandHasFlag(arguments, "--readonly") ||
		!commandHasFlag(arguments, "--no-announce-submounts") ||
		commandHasFlag(arguments, "--inode-file-handles=never") {
		t.Fatalf("flag matching failed for %q", arguments)
	}
}

func TestFirecrackerProcessGroupFromStat(t *testing.T) {
	for _, test := range []struct {
		name string
		stat string
		want int
	}{
		{
			name: "simple command",
			stat: "123 (virtiofsd) S 1 123 123 0 -1",
			want: 123,
		},
		{
			name: "command with parentheses",
			stat: "456 (virtiofsd (worker)) S 123 456 456 0 -1",
			want: 456,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := firecrackerProcessGroupFromStat([]byte(test.stat))
			if err != nil || got != test.want {
				t.Fatalf("process group = %d, %v; want %d", got, err, test.want)
			}
		})
	}
	for index, stat := range []string{
		"",
		"123 virtiofsd S 1 123",
		"123 (virtiofsd) S 1",
		"123 (virtiofsd) S 1 invalid",
		"123 (virtiofsd) S 1 1",
	} {
		t.Run(fmt.Sprintf("invalid-%d", index), func(t *testing.T) {
			if _, err := firecrackerProcessGroupFromStat([]byte(stat)); err == nil {
				t.Fatalf("accepted malformed stat %q", stat)
			}
		})
	}
}

func TestWaitFirecrackerVirtioFSCommandCanBeObservedMoreThanOnce(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "exit 23")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := waitFirecrackerVirtioFSCommand(command)
	for index := 0; index < 2; index++ {
		err := process.wait()
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 23 {
			t.Fatalf("wait %d error = %v, want exit status 23", index, err)
		}
	}
}
