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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	firecrackerCheckpointManifestName = "manifest.json"
	firecrackerCheckpointVersion2     = 2
)

// Snapshot types recorded in a v2 manifest; the strings match the Firecracker
// API SnapshotCreateParams values.
const (
	firecrackerSnapshotTypeFull        = "Full"
	firecrackerSnapshotTypeIncremental = "Incremental"
	firecrackerSnapshotTypeSoftDirty   = "SoftDirty"
)

// firecrackerCheckpointCompat pins the software stack a checkpoint was
// produced on. A restore compares it against its own stack and refuses on a
// mismatch; manifests without a tuple (pre-M3 artifacts) restore without
// stack verification. Vcpus is informational — the vmstate already pins the
// count a restored VM comes up with.
type firecrackerCheckpointCompat struct {
	Arch        string `json:"arch,omitempty"`
	Firecracker string `json:"firecracker,omitempty"`
	VirtioFSD   string `json:"virtiofsd,omitempty"`
	Kernel      string `json:"kernel,omitempty"`
	Initrd      string `json:"initrd,omitempty"`
	Vcpus       uint32 `json:"vcpus,omitempty"`
	KernelArgs  string `json:"kernel_args,omitempty"`
}

// firecrackerCheckpointManifest describes the contents of a v2 checkpoint
// directory. It is written last so that its presence marks a self-consistent
// artifact: a restore never sees a half-written checkpoint.
type firecrackerCheckpointManifest struct {
	Version      int                          `json:"version"`
	SnapshotType string                       `json:"snapshot_type"`
	MemorySize   int64                        `json:"memory_size"`
	BaseMemory   string                       `json:"base_memory,omitempty"`
	VirtioFS     bool                         `json:"virtio_fs,omitempty"`
	Compat       *firecrackerCheckpointCompat `json:"compat,omitempty"`
	CreatedAt    time.Time                    `json:"created_at"`
	Digests      map[string]string            `json:"digests"`
}

type firecrackerCheckpointLayout int

const (
	// firecrackerCheckpointLayoutV1Archive is the legacy single-file
	// checkpoint.img tar (optionally gzipped) archive.
	firecrackerCheckpointLayoutV1Archive firecrackerCheckpointLayout = iota + 1
	// firecrackerCheckpointLayoutV2Directory is the uncompressed directory
	// layout whose memory file is a plain file that Firecracker patches in
	// place; the directory holds a manifest.json instead of an archive.
	firecrackerCheckpointLayoutV2Directory
)

// firecrackerCheckpointArtifact is the opened view of a caller-owned
// checkpoint directory, regardless of layout version.
type firecrackerCheckpointArtifact struct {
	Layout firecrackerCheckpointLayout
	// Manifest is set for v2 directories only.
	Manifest *firecrackerCheckpointManifest
	// Files holds the in-directory component paths for v2 directories only.
	Files firecrackerCheckpointFiles
}

// prepareFirecrackerCheckpointV2 lays out a caller-owned directory for a v2
// checkpoint before Firecracker is asked to snapshot into it. The memory file
// is either a reflink clone of the previous generation's memory (which
// Firecracker then patches in place) or, without lineage, a freshly
// preallocated zero file that receives the first dirty window. A directory
// that already holds a complete checkpoint is rejected instead of rewritten.
func prepareFirecrackerCheckpointV2(
	dir, baseMemoryPath string,
	memorySize int64,
) (files firecrackerCheckpointFiles, retErr error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return files, fmt.Errorf("create Firecracker checkpoint directory: %w", err)
	}
	manifestErr := checkFirecrackerCheckpointDirVacant(dir)
	if manifestErr != nil {
		return files, manifestErr
	}
	files = firecrackerCheckpointFiles{
		State:   filepath.Join(dir, firecrackerCheckpointStateName),
		Memory:  filepath.Join(dir, firecrackerCheckpointMemoryName),
		Overlay: filepath.Join(dir, firecrackerCheckpointOverlayName),
	}

	if baseMemoryPath == "" {
		if memorySize <= 0 {
			// Full snapshots have no base to patch and no size to preallocate:
			// Firecracker writes the whole memory file itself.
			return files, nil
		}
		memory, err := os.OpenFile(
			files.Memory,
			os.O_CREATE|os.O_EXCL|os.O_WRONLY,
			0600,
		)
		if err != nil {
			return files, fmt.Errorf("create Firecracker checkpoint memory: %w", err)
		}
		defer func() {
			retErr = errors.Join(retErr, memory.Close())
		}()
		// A sparse zero file: reads see zeroes without allocating extents,
		// and the pages the snapshot writes out become the only real
		// disk usage of the first window.
		if err := memory.Truncate(memorySize); err != nil {
			return files, fmt.Errorf("preallocate Firecracker checkpoint memory: %w", err)
		}
		return files, nil
	}

	if _, err := cloneFileNoSync(baseMemoryPath, files.Memory); err != nil {
		return files, err
	}
	return files, nil
}

// checkFirecrackerCheckpointDirVacant rejects a directory that already
// contains a complete checkpoint in either layout: a v2 manifest or a legacy
// v1 archive, which would otherwise shadow freshly written v2 components.
// Individual components are protected by O_EXCL at creation time instead.
func checkFirecrackerCheckpointDirVacant(dir string) error {
	for _, marker := range []string{
		firecrackerCheckpointManifestName,
		checkpointImageName,
	} {
		_, err := os.Lstat(filepath.Join(dir, marker))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect Firecracker checkpoint directory: %w", err)
		}
		return fmt.Errorf(
			"Firecracker checkpoint directory %s already contains a complete checkpoint",
			dir,
		)
	}
	return nil
}

// finalizeFirecrackerCheckpointV2 seals a v2 checkpoint after Firecracker has
// written its components: it records the small component digests and lands
// the manifest last as the logical commit marker. O_EXCL makes finalizing an
// already sealed directory an error.
func finalizeFirecrackerCheckpointV2(
	ctx context.Context,
	files firecrackerCheckpointFiles,
	manifest *firecrackerCheckpointManifest,
) (retErr error) {
	manifest.Version = firecrackerCheckpointVersion2
	manifest.CreatedAt = time.Now().UTC()
	if manifest.VirtioFS != (files.VirtioFSState != "") {
		return errors.New("Firecracker checkpoint virtio-fs manifest does not match its components")
	}
	if manifest.MemorySize <= 0 {
		// Full snapshots discover the guest memory size from the file
		// Firecracker just wrote.
		info, err := os.Lstat(files.Memory)
		if err != nil {
			return fmt.Errorf("inspect Firecracker checkpoint memory: %w", err)
		}
		manifest.MemorySize = info.Size()
	}
	// Only the small VM and optional virtio-fs state components are digested.
	// Hashing guest memory or the writable overlay costs seconds per GiB of CPU
	// and cache reads, which can dominate checkpoint latency. Their integrity
	// rests on local reflink copy-on-write and Firecracker's own writes.
	manifest.Digests = make(map[string]string, 2)
	for _, component := range firecrackerCheckpointComponents(files) {
		if component.name == firecrackerCheckpointMemoryName ||
			component.name == firecrackerCheckpointOverlayName {
			continue
		}
		digest, err := digestFirecrackerCheckpointComponent(ctx, component.name, component.path)
		if err != nil {
			return err
		}
		manifest.Digests[component.name] = digest
	}

	manifestPath := filepath.Join(
		filepath.Dir(files.State),
		firecrackerCheckpointManifestName,
	)
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Firecracker checkpoint manifest: %w", err)
	}
	onDisk, err := os.OpenFile(
		manifestPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create Firecracker checkpoint manifest: %w", err)
	}
	// Keep the manifest in the page cache with the checkpoint components.
	// Success publishes a logically complete generation but deliberately
	// does not promise immediate power-loss durability.
	writeErr := error(nil)
	if _, err := onDisk.Write(append(encoded, '\n')); err != nil {
		writeErr = fmt.Errorf("write Firecracker checkpoint manifest: %w", err)
	}
	retErr = errors.Join(writeErr, onDisk.Close())
	return retErr
}

// openFirecrackerCheckpoint inspects a caller-owned checkpoint directory and
// reports its layout: v1 single-file archives keep working unchanged, v2
// directories must carry a well-formed manifest and all components.
func openFirecrackerCheckpoint(dir string) (*firecrackerCheckpointArtifact, error) {
	imageInfo, err := os.Lstat(filepath.Join(dir, checkpointImageName))
	if err == nil {
		if !imageInfo.Mode().IsRegular() || imageInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("Firecracker checkpoint archive is not a regular file")
		}
		return &firecrackerCheckpointArtifact{
			Layout: firecrackerCheckpointLayoutV1Archive,
		}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Firecracker checkpoint directory: %w", err)
	}

	manifest, err := readFirecrackerCheckpointManifest(dir)
	if err != nil {
		return nil, err
	}
	artifact := &firecrackerCheckpointArtifact{
		Layout:   firecrackerCheckpointLayoutV2Directory,
		Manifest: manifest,
		Files: firecrackerCheckpointFiles{
			State:   filepath.Join(dir, firecrackerCheckpointStateName),
			Memory:  filepath.Join(dir, firecrackerCheckpointMemoryName),
			Overlay: filepath.Join(dir, firecrackerCheckpointOverlayName),
		},
	}
	if manifest.VirtioFS {
		artifact.Files.VirtioFSState = filepath.Join(
			dir,
			firecrackerCheckpointVirtioFSName,
		)
	}
	for _, component := range firecrackerCheckpointComponents(artifact.Files) {
		info, err := os.Lstat(component.path)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect Firecracker checkpoint component %s: %w",
				component.name, err,
			)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Size() <= 0 || info.Size() > firecrackerCheckpointMaxComponent {
			return nil, fmt.Errorf(
				"Firecracker checkpoint component %s is not a bounded regular file",
				component.name,
			)
		}
	}
	memoryInfo, err := os.Lstat(artifact.Files.Memory)
	if err != nil {
		return nil, fmt.Errorf("inspect Firecracker checkpoint memory: %w", err)
	}
	if memoryInfo.Size() != artifact.Manifest.MemorySize {
		return nil, fmt.Errorf(
			"Firecracker checkpoint memory is %d bytes, manifest expects %d",
			memoryInfo.Size(), artifact.Manifest.MemorySize,
		)
	}
	return artifact, nil
}

// readFirecrackerCheckpointManifest parses and validates the manifest of a v2
// checkpoint directory.
func readFirecrackerCheckpointManifest(dir string) (*firecrackerCheckpointManifest, error) {
	path := filepath.Join(dir, firecrackerCheckpointManifestName)
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Firecracker checkpoint manifest: %w", err)
	}
	var manifest firecrackerCheckpointManifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return nil, fmt.Errorf("decode Firecracker checkpoint manifest: %w", err)
	}
	if manifest.Version != firecrackerCheckpointVersion2 {
		return nil, fmt.Errorf(
			"unsupported Firecracker checkpoint manifest version %d",
			manifest.Version,
		)
	}
	switch manifest.SnapshotType {
	case firecrackerSnapshotTypeFull,
		firecrackerSnapshotTypeIncremental,
		firecrackerSnapshotTypeSoftDirty:
	default:
		return nil, fmt.Errorf(
			"invalid Firecracker checkpoint snapshot type %q",
			manifest.SnapshotType,
		)
	}
	if manifest.MemorySize <= 0 || manifest.MemorySize > firecrackerCheckpointMaxComponent {
		return nil, fmt.Errorf(
			"Firecracker checkpoint manifest has unbounded memory size %d",
			manifest.MemorySize,
		)
	}
	if manifest.Compat != nil {
		for name, digest := range map[string]string{
			"firecracker": manifest.Compat.Firecracker,
			"virtiofsd":   manifest.Compat.VirtioFSD,
			"kernel":      manifest.Compat.Kernel,
			"initrd":      manifest.Compat.Initrd,
		} {
			if digest != "" && !isFirecrackerCompatDigest(digest) {
				return nil, fmt.Errorf(
					"Firecracker checkpoint compat %s digest %q is not a sha256 hex string",
					name, digest,
				)
			}
		}
	}
	return &manifest, nil
}

func isFirecrackerCompatDigest(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	for _, c := range digest {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// cachedCheckpointDigest remembers a verified component digest together with
// the file identity it was computed from.
type cachedCheckpointDigest struct {
	size      int64
	modTimeNs int64
	digest    string
}

// checkpointDigestCache memoizes component digests across restores so a warm
// start from a stable checkpoint directory (typically a manufactured
// template) does not re-hash its vmstate and overlay every time. Entries are
// keyed by component path and invalidated by a size or mtime change; the
// granularity matches the nydus bootstrap cache. This trades detection of a
// same-stat content swap for memoization — the checkpoint directories are
// daemon-adjacent 0600 artifacts, not adversarial inputs. The cache is
// advisory and resets once it exceeds a generous entry bound (incremental
// chains mint a fresh directory per generation).
type checkpointDigestCache struct {
	mu      sync.Mutex
	entries map[string]cachedCheckpointDigest
	// hashes counts component hashes performed; it exists so tests can
	// observe cache hits without timing.
	hashes int
}

const checkpointDigestCacheMaxEntries = 1024

// verifyFirecrackerCheckpointDigests compares the components on disk against
// the digests the manifest recorded, hashing only components whose file
// identity is not already cached. Components without a recorded digest
// (memory, by design) are skipped.
func (cache *checkpointDigestCache) verifyFirecrackerCheckpointDigests(
	ctx context.Context,
	artifact *firecrackerCheckpointArtifact,
) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for _, component := range firecrackerCheckpointComponents(artifact.Files) {
		expected, recorded := artifact.Manifest.Digests[component.name]
		if !recorded || expected == "" {
			continue
		}
		info, err := os.Lstat(component.path)
		if err != nil {
			return fmt.Errorf(
				"inspect Firecracker checkpoint component %s: %w",
				component.name, err,
			)
		}
		digest, cached := cache.lookup(component.path, info)
		if !cached {
			digest, err = digestFirecrackerCheckpointComponent(
				ctx,
				component.name,
				component.path,
			)
			if err != nil {
				return err
			}
			cache.remember(component.path, info, digest)
		}
		if digest != expected {
			return fmt.Errorf(
				"Firecracker checkpoint component %s digest mismatch: manifest %s, on disk %s",
				component.name, expected, digest,
			)
		}
	}
	return nil
}

func (cache *checkpointDigestCache) lookup(
	path string, info os.FileInfo,
) (string, bool) {
	entry, ok := cache.entries[path]
	if !ok || entry.size != info.Size() ||
		entry.modTimeNs != info.ModTime().UnixNano() {
		return "", false
	}
	return entry.digest, true
}

func (cache *checkpointDigestCache) remember(
	path string, info os.FileInfo, digest string,
) {
	if cache.entries == nil {
		cache.entries = make(map[string]cachedCheckpointDigest)
	} else if len(cache.entries) >= checkpointDigestCacheMaxEntries {
		cache.entries = make(map[string]cachedCheckpointDigest)
	}
	cache.entries[path] = cachedCheckpointDigest{
		size:      info.Size(),
		modTimeNs: info.ModTime().UnixNano(),
		digest:    digest,
	}
	cache.hashes++
}

func firecrackerCheckpointComponents(
	files firecrackerCheckpointFiles,
) []struct{ name, path string } {
	components := []struct{ name, path string }{
		{name: firecrackerCheckpointStateName, path: files.State},
		{name: firecrackerCheckpointMemoryName, path: files.Memory},
		{name: firecrackerCheckpointOverlayName, path: files.Overlay},
	}
	if files.VirtioFSState != "" {
		components = append(components, struct{ name, path string }{
			name: firecrackerCheckpointVirtioFSName,
			path: files.VirtioFSState,
		})
	}
	return components
}

func digestFirecrackerCheckpointComponent(
	ctx context.Context,
	name, path string,
) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect Firecracker checkpoint component %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > firecrackerCheckpointMaxComponent {
		return "", fmt.Errorf(
			"Firecracker checkpoint component %s is not a bounded regular file",
			name,
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open Firecracker checkpoint component %s: %w", name, err)
	}
	defer file.Close()
	hash := sha256.New()
	written, err := copyFirecrackerCheckpoint(ctx, hash, file)
	if err != nil {
		return "", fmt.Errorf("digest Firecracker checkpoint component %s: %w", name, err)
	}
	if written != info.Size() {
		return "", fmt.Errorf(
			"Firecracker checkpoint component %s changed while reading",
			name,
		)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
