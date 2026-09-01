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
