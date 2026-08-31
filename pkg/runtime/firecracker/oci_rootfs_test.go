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
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOCIRootfsConverterCachesMaterializedImage(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "rootfs")
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(source, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(artifacts, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "marker"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	counter := filepath.Join(root, "counter")
	t.Setenv("FAKE_MKFS_COUNTER", counter)
	mkfs := filepath.Join(root, "mkfs.erofs")
	script := `#!/bin/sh
set -eu
printf x >> "${FAKE_MKFS_COUNTER}"
dd if=/dev/zero of="$3" bs=2048 count=1 status=none
printf '\342\341\365\340' | dd of="$3" bs=1 seek=1024 conv=notrunc status=none
`
	if err := os.WriteFile(mkfs, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	converter, err := NewOCIRootfsConverter(mkfs)
	if err != nil {
		t.Fatal(err)
	}

	first, err := converter.Convert(
		context.Background(),
		"registry.example/image:v1",
		"sha256:content",
		artifacts,
		source,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := converter.Convert(
		context.Background(),
		"registry.example/image:updated-tag",
		"sha256:content",
		artifacts,
		source,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("cached paths differ: %q and %q", first, second)
	}
	if !validEROFSFile(first) {
		t.Fatalf("cached image %s is not EROFS", first)
	}
	data, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "x" {
		t.Fatalf("mkfs invocation count marker = %q, want one invocation", data)
	}
}

func TestOCIRootfsConverterRejectsNonDirectorySource(t *testing.T) {
	root := t.TempDir()
	mkfs := filepath.Join(root, "mkfs.erofs")
	if err := os.WriteFile(mkfs, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	converter, err := NewOCIRootfsConverter(mkfs)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "rootfs")
	if err := os.WriteFile(source, []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := converter.Convert(
		context.Background(),
		"registry.example/image:v1",
		"sha256:content",
		root,
		source,
	); err == nil {
		t.Fatal("Convert() succeeded for a non-directory source")
	}
}
