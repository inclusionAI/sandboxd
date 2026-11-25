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

package oci

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const defaultOverlayAliasRoot = "/run/sandboxd-oci"
const overlayAliasIDBytes = 16

type overlayAlias struct {
	path      string
	chainsDir string
}

func (m *Manager) lowerDirAlias(name string) (overlayAlias, error) {
	if id, err := base64.RawURLEncoding.DecodeString(name); err != nil || len(id) != overlayAliasIDBytes ||
		len(name) != base64.RawURLEncoding.EncodedLen(overlayAliasIDBytes) {
		return overlayAlias{}, fmt.Errorf("invalid OCI lowerdir alias name %q", name)
	}
	chainsDir, err := filepath.Abs(m.chainsDir)
	if err != nil {
		return overlayAlias{}, err
	}
	return overlayAlias{path: filepath.Join(m.aliasRoot, name), chainsDir: chainsDir}, nil
}

func (a overlayAlias) lowerDirs(lowerDirs []string) ([]string, error) {
	compact := make([]string, len(lowerDirs))
	for i, dir := range lowerDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(a.chainsDir, abs)
		if err != nil || rel == "." || !filepath.IsLocal(rel) {
			return nil, fmt.Errorf("OCI layer %d is outside the lowerdir cache %s", i+1, a.chainsDir)
		}
		compact[i] = filepath.Join(a.path, rel)
	}
	return compact, nil
}

func checkAliasDirectory(path string, forbidden os.FileMode, allowRoot bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&forbidden != 0 ||
		!ok || (stat.Uid != uint32(os.Geteuid()) && !(allowRoot && stat.Uid == 0)) {
		return fmt.Errorf("untrusted OCI alias directory %s", path)
	}
	return nil
}

func (a overlayAlias) ensureParent() error {
	root := filepath.Dir(a.path)
	if err := checkAliasDirectory(filepath.Dir(root), 0022, true); err != nil {
		return err
	}
	if err := os.Mkdir(root, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkAliasDirectory(root, 0077, false)
}

func (a overlayAlias) readTarget() (string, error) {
	root := filepath.Dir(a.path)
	if err := checkAliasDirectory(filepath.Dir(root), 0022, true); err != nil {
		return "", err
	}
	if err := checkAliasDirectory(root, 0077, false); err != nil {
		return "", err
	}
	return os.Readlink(a.path)
}

func (a overlayAlias) verify() error {
	target, err := a.readTarget()
	if err != nil {
		return fmt.Errorf("read OCI lowerdir alias %s: %w", a.path, err)
	}
	if target != a.chainsDir {
		return fmt.Errorf("OCI lowerdir alias %s does not point to %s", a.path, a.chainsDir)
	}
	return nil
}

func (a overlayAlias) remove() error {
	target, err := a.readTarget()
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.EINVAL) {
		return nil
	}
	if err != nil {
		return err
	}
	if target != a.chainsDir {
		return nil
	}
	if err := syscall.Unlink(a.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m *Manager) prepareCompactLowerDirs(txn *OciMountTxnRecord, budget int) (string, error) {
	// A random identity also distinguishes caches with identical paths in
	// separate mount namespaces sharing /run.
	var id [overlayAliasIDBytes]byte
	rand.Read(id[:])
	name := base64.RawURLEncoding.EncodeToString(id[:])
	alias, err := m.lowerDirAlias(name)
	if err != nil {
		return "", err
	}
	dirs, err := alias.lowerDirs(txn.LowerDirs)
	if err != nil {
		return "", err
	}
	data, err := buildOverlayMountData(dirs)
	if err != nil {
		return "", err
	}
	if len(data) > budget {
		return "", fmt.Errorf("compact lowerdir options use %d bytes with a %d-byte budget (use a kernel with native lowerdir+ support)", len(data), budget)
	}
	if err := alias.ensureParent(); err != nil {
		return "", fmt.Errorf("prepare OCI lowerdir alias directory: %w", err)
	}
	if _, err := os.Lstat(alias.path); err == nil {
		return "", fmt.Errorf("OCI lowerdir alias %s already exists", alias.path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// Journal ownership before creating the symlink so recovery can roll it
	// back even if the daemon exits before the mount syscall.
	pending := *txn
	pending.LowerDirAlias = name
	if err := m.store.putMountTxn(&pending); err != nil {
		return "", fmt.Errorf("record OCI lowerdir alias ownership: %w", err)
	}
	txn.LowerDirAlias = name
	if err := os.Symlink(alias.chainsDir, alias.path); err != nil {
		return "", fmt.Errorf("create OCI lowerdir alias: %w", err)
	}
	if err := alias.verify(); err != nil {
		return "", err
	}
	return data, nil
}

func (m *Manager) removeLowerDirAlias(name string) error {
	if name == "" {
		return nil
	}
	alias, err := m.lowerDirAlias(name)
	if err == nil {
		err = alias.remove()
	}
	if err != nil {
		return fmt.Errorf("remove OCI lowerdir alias %s: %w", name, err)
	}
	return nil
}
