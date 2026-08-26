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
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirecrackerCheckpointArchiveRoundTrip(t *testing.T) {
	for _, compress := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "gzip"}[compress], func(t *testing.T) {
			root := t.TempDir()
			source := firecrackerCheckpointFiles{
				State:   filepath.Join(root, "source-state"),
				Memory:  filepath.Join(root, "source-memory"),
				Overlay: filepath.Join(root, "source-overlay"),
			}
			want := map[string]string{
				source.State:   "vm-state-data",
				source.Memory:  strings.Repeat("memory-page-", 4096),
				source.Overlay: strings.Repeat("overlay-block-", 4096),
			}
			for path, data := range want {
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			image := filepath.Join(root, "checkpoint.img")
			if err := createFirecrackerCheckpointArchive(
				context.Background(), image, compress, source,
			); err != nil {
				t.Fatal(err)
			}
			prefix, err := os.ReadFile(image)
			if err != nil {
				t.Fatal(err)
			}
			isGzip := len(prefix) >= 2 && prefix[0] == 0x1f && prefix[1] == 0x8b
			if isGzip != compress {
				t.Fatalf("gzip magic = %v, compress = %v", isGzip, compress)
			}

			destinationRoot := filepath.Join(root, "restore-with-new-id")
			if err := os.Mkdir(destinationRoot, 0700); err != nil {
				t.Fatal(err)
			}
			destination := firecrackerCheckpointFiles{
				State:   filepath.Join(destinationRoot, "vmstate"),
				Memory:  filepath.Join(destinationRoot, "memory"),
				Overlay: filepath.Join(destinationRoot, "overlay.ext4"),
			}
			if err := extractFirecrackerCheckpointArchive(
				context.Background(), image, destination,
			); err != nil {
				t.Fatal(err)
			}
			pairs := map[string]string{
				destination.State:   want[source.State],
				destination.Memory:  want[source.Memory],
				destination.Overlay: want[source.Overlay],
			}
			for path, expected := range pairs {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != expected {
					t.Fatalf("restored %s content differs", path)
				}
			}
		})
	}
}

func TestFirecrackerCheckpointArchiveCancellationRemovesOutput(t *testing.T) {
	root := t.TempDir()
	files := firecrackerCheckpointFiles{
		State:   filepath.Join(root, "state"),
		Memory:  filepath.Join(root, "memory"),
		Overlay: filepath.Join(root, "overlay"),
	}
	for _, path := range []string{files.State, files.Memory, files.Overlay} {
		if err := os.WriteFile(path, []byte("content"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	image := filepath.Join(root, "checkpoint.img")
	err := createFirecrackerCheckpointArchive(ctx, image, true, files)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("checkpoint error = %v, want context canceled", err)
	}
	if _, err := os.Stat(image); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial checkpoint retained: %v", err)
	}
}

func TestFirecrackerCheckpointArchiveReadsLegacyDenseFormat(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "legacy-checkpoint.img")
	file, err := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(file)
	contents := map[string]string{
		firecrackerCheckpointStateName:   "legacy-state",
		firecrackerCheckpointMemoryName:  "legacy-memory",
		firecrackerCheckpointOverlayName: "legacy-overlay",
	}
	for _, name := range []string{
		firecrackerCheckpointStateName,
		firecrackerCheckpointMemoryName,
		firecrackerCheckpointOverlayName,
	} {
		content := contents[name]
		if err := archive.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(archive, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(archive.Close(), file.Close()); err != nil {
		t.Fatal(err)
	}

	destination := firecrackerCheckpointFiles{
		State:   filepath.Join(root, "state"),
		Memory:  filepath.Join(root, "memory"),
		Overlay: filepath.Join(root, "overlay"),
	}
	if err := extractFirecrackerCheckpointArchive(
		context.Background(), image, destination,
	); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		firecrackerCheckpointStateName:   destination.State,
		firecrackerCheckpointMemoryName:  destination.Memory,
		firecrackerCheckpointOverlayName: destination.Overlay,
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != contents[name] {
			t.Fatalf("legacy %s = %q", name, data)
		}
	}
}

func TestFirecrackerCheckpointArchiveRejectsUnversionedPrivateMetadata(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "unversioned-checkpoint.img")
	file, err := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(file)
	if err := archive.WriteHeader(&tar.Header{
		Name: firecrackerCheckpointStateName,
		Mode: 0600,
		Size: 1,
		PAXRecords: map[string]string{
			firecrackerSparseSizePAX: "2",
			firecrackerSparseMapPAX:  "0:1",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(archive, "x"); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(archive.Close(), file.Close()); err != nil {
		t.Fatal(err)
	}
	err = extractFirecrackerCheckpointArchive(
		context.Background(),
		image,
		firecrackerCheckpointFiles{
			State:   filepath.Join(root, "state"),
			Memory:  filepath.Join(root, "memory"),
			Overlay: filepath.Join(root, "overlay"),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid Firecracker checkpoint entry") {
		t.Fatalf("unversioned private metadata error = %v", err)
	}
}

func TestFirecrackerCheckpointArchivePreservesSparseFiles(t *testing.T) {
	root := t.TempDir()
	files := firecrackerCheckpointFiles{
		State:   filepath.Join(root, "state"),
		Memory:  filepath.Join(root, "memory"),
		Overlay: filepath.Join(root, "overlay"),
	}
	for _, path := range []string{files.State, files.Memory} {
		if err := os.WriteFile(path, []byte("content"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	overlay, err := os.OpenFile(files.Overlay, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	const logicalSize = int64(1 << 30)
	if err := overlay.Truncate(logicalSize); err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt([]byte("first"), 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.WriteAt([]byte("last"), logicalSize-4096); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Close(); err != nil {
		t.Fatal(err)
	}

	image := filepath.Join(root, "checkpoint.img")
	if err := createFirecrackerCheckpointArchive(
		context.Background(), image, false, files,
	); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(image)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 1<<20 {
		t.Fatalf("sparse checkpoint archive size = %d", info.Size())
	}
	archiveFile, err := os.Open(image)
	if err != nil {
		t.Fatal(err)
	}
	header, err := tar.NewReader(archiveFile).Next()
	if err != nil {
		_ = archiveFile.Close()
		t.Fatal(err)
	}
	if header.Name != firecrackerCheckpointFormatName {
		_ = archiveFile.Close()
		t.Fatalf("first checkpoint entry = %q", header.Name)
	}
	if err := archiveFile.Close(); err != nil {
		t.Fatal(err)
	}

	destinationRoot := filepath.Join(root, "destination")
	if err := os.Mkdir(destinationRoot, 0700); err != nil {
		t.Fatal(err)
	}
	destination := firecrackerCheckpointFiles{
		State:   filepath.Join(destinationRoot, "state"),
		Memory:  filepath.Join(destinationRoot, "memory"),
		Overlay: filepath.Join(destinationRoot, "overlay"),
	}
	if err := extractFirecrackerCheckpointArchive(
		context.Background(), image, destination,
	); err != nil {
		t.Fatal(err)
	}
	restored, err := os.Open(destination.Overlay)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restoredInfo, err := restored.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if restoredInfo.Size() != logicalSize {
		t.Fatalf("restored sparse size = %d", restoredInfo.Size())
	}
	for offset, expected := range map[int64]string{
		4096:               "first",
		logicalSize - 4096: "last",
	} {
		data := make([]byte, len(expected))
		if _, err := restored.ReadAt(data, offset); err != nil {
			t.Fatal(err)
		}
		if string(data) != expected {
			t.Fatalf("restored data at %d = %q", offset, data)
		}
	}
}
