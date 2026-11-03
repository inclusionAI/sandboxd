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

package runtime

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/inclusionAI/sandboxd/config"
)

const (
	ManagedHostsVersion            = 1
	ManagedHostsStateFile          = "managed-hosts.json"
	RootfsSeedName                 = "rootfs-seed.tar"
	GVisorRootfsTarUpperAnnotation = "dev.gvisor.tar.rootfs.upper"
	managedHostsMetadataLimit      = 64 << 10
	ManagedHostsContentLimit       = 64 << 10
)

type HostsLayout string

const (
	HostsLayoutPrivateRootfs HostsLayout = "managed_rootfs_v1"
	HostsLayoutLegacy        HostsLayout = "legacy_readonly_mount"
	HostsLayoutExternal      HostsLayout = "external_mount"
)

// InitialFile is an internal initialization instruction, not a host mount.
type InitialFile struct {
	Path    string
	Content []byte
	Mode    uint32
}

// ManagedHostsState describes initialization dependencies, never live hosts data.
// A nil state preserves the behavior of snapshots made before this schema.
type ManagedHostsState struct {
	Version      int         `json:"schema_version"`
	Layout       HostsLayout `json:"hosts_layout"`
	Runtime      string      `json:"runtime"`
	RootReadonly bool        `json:"root_readonly"`
	Seed         *RootfsSeed `json:"seed,omitempty"`
}

type RootfsSeed struct {
	File            string `json:"artifact_path"`
	SHA256          string `json:"sha256"`
	AnnotationKey   string `json:"annotation_key"`
	AnnotationValue string `json:"annotation_value"`
}

// EffectiveRootReadonly preserves the existing quota and provider-root rules.
// The runsc NVIDIA hook already requires a writable final rootfs view.
func EffectiveRootReadonly(readonly bool, writableLimit uint64, updates *SpecUpdates) bool {
	return readonly && writableLimit == 0 && (updates == nil || !updates.RequiresHostWritableRootfs)
}

// ValidateInitialFiles keeps the internal channel restricted to managed hosts.
func ValidateInitialFiles(files []InitialFile) error {
	if len(files) > 1 {
		return errors.New("initial files may contain only one /etc/hosts entry")
	}
	for _, file := range files {
		if file.Path != "/etc/hosts" || file.Mode != 0644 {
			return errors.New("initial files require /etc/hosts with mode 0644")
		}
		if len(file.Content) > ManagedHostsContentLimit {
			return fmt.Errorf("initial hosts exceeds %d bytes", ManagedHostsContentLimit)
		}
	}
	return nil
}

// ValidateManagedHostsState validates a completed, persistable state. Fresh
// runsc initialization must fill Seed before calling this function.
func ValidateManagedHostsState(state *ManagedHostsState) error {
	if state == nil {
		return errors.New("managed hosts state is missing")
	}
	if state.Version != ManagedHostsVersion {
		return fmt.Errorf("unsupported managed hosts schema version %d", state.Version)
	}
	if state.Runtime != config.RuntimeNameRunsc {
		return fmt.Errorf("unsupported managed hosts runtime %q", state.Runtime)
	}
	switch state.Layout {
	case HostsLayoutPrivateRootfs:
		if state.RootReadonly {
			return errors.New("managed rootfs hosts require a writable root")
		}
	case HostsLayoutLegacy:
		if !state.RootReadonly {
			return errors.New("new legacy hosts metadata requires a readonly root")
		}
	case HostsLayoutExternal:
	default:
		return fmt.Errorf("unsupported managed hosts layout %q", state.Layout)
	}
	needsSeed := state.Layout == HostsLayoutPrivateRootfs
	if !needsSeed {
		if state.Seed != nil {
			return errors.New("managed hosts seed is only supported for runsc private rootfs")
		}
		return nil
	}
	seed := state.Seed
	if seed == nil {
		return errors.New("managed hosts rootfs seed is missing")
	}
	if seed.File != RootfsSeedName || seed.AnnotationKey != GVisorRootfsTarUpperAnnotation || seed.AnnotationValue != RootfsSeedName {
		return errors.New("managed hosts rootfs seed path or annotation is invalid")
	}
	decoded, err := hex.DecodeString(seed.SHA256)
	if err != nil || len(decoded) != 32 || seed.SHA256 != strings.ToLower(seed.SHA256) {
		return errors.New("managed hosts rootfs seed SHA-256 is invalid")
	}
	return nil
}

// ValidateManagedHostsCompatibility prevents layout changes during restore.
// ownsHosts describes caller/base-spec mounts before platform defaults are added.
func ValidateManagedHostsCompatibility(state *ManagedHostsState, runtimeName string, rootReadonly, ownsHosts bool) error {
	if err := ValidateManagedHostsState(state); err != nil {
		return err
	}
	if state.Runtime != runtimeName {
		return fmt.Errorf("managed hosts runtime mismatch: saved %q, requested %q", state.Runtime, runtimeName)
	}
	if state.RootReadonly != rootReadonly {
		return errors.New("managed hosts root readonly mode differs from checkpoint")
	}
	if (state.Layout == HostsLayoutExternal) != ownsHosts {
		return errors.New("managed hosts mount ownership differs from checkpoint")
	}
	return nil
}

// ReadManagedHostsState returns nil only for an absent sidecar. Runtime-specific
// manifest/spec validation must still distinguish missing new state from legacy.
func ReadManagedHostsState(dir string) (*ManagedHostsState, error) {
	filename := filepath.Join(dir, ManagedHostsStateFile)
	f, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", ManagedHostsStateFile, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", ManagedHostsStateFile, err)
	}
	if !info.Mode().IsRegular() || info.Size() > managedHostsMetadataLimit {
		return nil, fmt.Errorf("%s must be a regular file of at most %d bytes", ManagedHostsStateFile, managedHostsMetadataLimit)
	}
	// A pointer distinguishes an explicit false from a missing/null root mode.
	var wire struct {
		Version      int         `json:"schema_version"`
		Layout       HostsLayout `json:"hosts_layout"`
		Runtime      string      `json:"runtime"`
		RootReadonly *bool       `json:"root_readonly"`
		Seed         *RootfsSeed `json:"seed,omitempty"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, managedHostsMetadataLimit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return nil, fmt.Errorf("decode %s: %w", ManagedHostsStateFile, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%s has trailing data", ManagedHostsStateFile)
	}
	if wire.RootReadonly == nil {
		return nil, fmt.Errorf("%s is missing root_readonly", ManagedHostsStateFile)
	}
	state := &ManagedHostsState{Version: wire.Version, Layout: wire.Layout, Runtime: wire.Runtime, RootReadonly: *wire.RootReadonly, Seed: wire.Seed}
	if err := ValidateManagedHostsState(state); err != nil {
		return nil, fmt.Errorf("validate %s: %w", ManagedHostsStateFile, err)
	}
	return state, nil
}

// WriteManagedHostsState publishes durable metadata before reporting success.
func WriteManagedHostsState(dir string, state *ManagedHostsState) (retErr error) {
	if err := ValidateManagedHostsState(state); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", ManagedHostsStateFile, err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".managed-hosts-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(tmp) }()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, ManagedHostsStateFile)); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// ManagedRootfsAnnotation is reserved even when a request does not select the
// writable hosts layout: user/provider annotations must not inject arbitrary tar.
func ManagedRootfsAnnotation(key string) bool {
	return key == GVisorRootfsTarUpperAnnotation ||
		strings.HasPrefix(key, GVisorRootfsTarUpperAnnotation+".") ||
		key == "dev.gvisor.flag.allow-rootfs-tar-annotation" ||
		key == "dev.gvisor.flag.restore-spec-validation"
}
