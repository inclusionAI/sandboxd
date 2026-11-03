// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package runsc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func cloneManagedHosts(state *runtimecore.ManagedHostsState) *runtimecore.ManagedHostsState {
	if state == nil {
		return nil
	}
	copy := *state
	if state.Seed != nil {
		seed := *state.Seed
		copy.Seed = &seed
	}
	return &copy
}

func privateManagedHosts(state *runtimecore.ManagedHostsState) bool {
	return state != nil && state.Layout == runtimecore.HostsLayoutPrivateRootfs
}

func hostsMountOwned(spec *runtimecore.Spec) bool {
	for _, mount := range spec.Mounts {
		target := path.Clean(mount.Destination)
		if target == "/" || target == "/etc" || target == "/etc/hosts" {
			return true
		}
	}
	return false
}

func validateManagedHostsSpec(state *runtimecore.ManagedHostsState, spec *runtimecore.Spec) error {
	if state == nil {
		return nil
	}
	if spec == nil || spec.Root == nil {
		return errors.New("managed hosts require an OCI root")
	}
	if state.Version != runtimecore.ManagedHostsVersion || state.Runtime != config.RuntimeNameRunsc {
		return errors.New("managed hosts state does not describe this runsc runtime")
	}
	if state.RootReadonly != spec.Root.Readonly {
		return errors.New("managed hosts root mode differs from the final OCI root")
	}
	if privateManagedHosts(state) {
		if spec.Root.Readonly || hostsMountOwned(spec) {
			return errors.New("managed rootfs hosts require a writable root without a mount owning /etc/hosts")
		}
		// A gofer in an explicit user namespace sees translated ownership and
		// ACLs. Host-side stat/xattr metadata cannot safely seed that view.
		// Direct EROFS is decoded by runsc using image IDs instead.
		if _, directEROFS := runscNVProxyEROFSImageSource(spec); !directEROFS && spec.Linux != nil {
			for _, namespace := range spec.Linux.Namespaces {
				if namespace.Type == "user" {
					return errors.New("managed rootfs hosts do not support directory roots with an explicit user namespace; use a direct EROFS root or an external hosts mount")
				}
			}
		}
		// RootfsTarUpperPath ignores the unsuffixed key in containerd's
		// multi-container mode. sandboxd launches standalone containers.
		if spec.Annotations["io.kubernetes.cri.container-name"] != "" || spec.Annotations["io.kubernetes.cri.container-type"] != "" || spec.Annotations["io.kubernetes.cri-o.ContainerType"] != "" {
			return errors.New("managed rootfs hosts require standalone runsc container annotations")
		}
	} else if !hostsMountOwned(spec) {
		return errors.New("mounted hosts layout requires a final OCI mount owning /etc/hosts")
	}
	return nil
}

func (r *Handler) prepareFreshManagedHosts(bundle string, spec *runtimecore.Spec, start runtimecore.StartConfig) (*runtimecore.ManagedHostsState, error) {
	if err := runtimecore.ValidateInitialFiles(start.InitialFiles); err != nil {
		return nil, err
	}
	if err := removeManagedHostsFiles(bundle); err != nil {
		return nil, err
	}
	state := cloneManagedHosts(start.ManagedHosts)
	if !privateManagedHosts(state) {
		if len(start.InitialFiles) != 0 {
			return nil, errors.New("initial hosts require the managed rootfs layout")
		}
		if state != nil {
			if err := runtimecore.ValidateManagedHostsState(state); err != nil {
				return nil, err
			}
		}
		return state, validateManagedHostsSpec(state, spec)
	}
	if state.Seed != nil {
		return nil, errors.New("fresh hosts initialization cannot supply an existing seed")
	}
	if len(start.InitialFiles) != 1 {
		return nil, errors.New("fresh managed rootfs requires initial hosts")
	}
	if err := validateManagedHostsSpec(state, spec); err != nil {
		return nil, err
	}
	headers, err := r.readHostsSeedHeaders(bundle, spec)
	if err != nil {
		return nil, err
	}
	data, err := encodeHostsSeed(headers, start.InitialFiles)
	if err != nil {
		return nil, fmt.Errorf("encode initial hosts seed: %w", err)
	}
	digest := sha256.Sum256(data)
	state.Seed = &runtimecore.RootfsSeed{
		File:            runtimecore.RootfsSeedName,
		SHA256:          hex.EncodeToString(digest[:]),
		AnnotationKey:   runtimecore.GVisorRootfsTarUpperAnnotation,
		AnnotationValue: runtimecore.RootfsSeedName,
	}
	if err := runtimecore.ValidateManagedHostsState(state); err != nil {
		return nil, err
	}
	if err := writeHostsSeed(bundle, data); err != nil {
		return nil, err
	}
	return state, nil
}

func prepareRestoredManagedHosts(bundle string, spec *runtimecore.Spec, start runtimecore.StartConfig) (*runtimecore.ManagedHostsState, error) {
	if len(start.InitialFiles) != 0 {
		return nil, errors.New("restore must not initialize hosts")
	}
	if err := util.ValidateRestoreDirectorySeparation(start.CheckpointDir, bundle); err != nil {
		return nil, err
	}
	state, err := runtimecore.ReadManagedHostsState(start.CheckpointDir)
	if err != nil {
		return nil, err
	}
	if start.ManagedHosts != nil && !reflect.DeepEqual(start.ManagedHosts, state) {
		return nil, errors.New("restore hosts metadata differs from the checkpoint")
	}
	if err := validateManagedHostsSpec(state, spec); err != nil {
		return nil, err
	}
	if err := removeManagedHostsFiles(bundle); err != nil {
		return nil, err
	}
	if privateManagedHosts(state) {
		data, err := readHostsSeed(start.CheckpointDir, state)
		if err != nil {
			return nil, err
		}
		if err := writeHostsSeed(bundle, data); err != nil {
			return nil, err
		}
	}
	return state, nil
}

// finalizeManagedHosts runs after all OCI changes, including host-root fallback.
// The seed annotation is installed only here, after the loader has rejected
// caller/provider attempts to set any managed annotation.
func finalizeManagedHosts(bundle string, spec *runtimecore.Spec, state *runtimecore.ManagedHostsState) error {
	if state == nil {
		return nil
	}
	if err := runtimecore.ValidateManagedHostsState(state); err != nil {
		return err
	}
	if err := validateManagedHostsSpec(state, spec); err != nil {
		return err
	}
	for key := range spec.Annotations {
		if runtimecore.ManagedRootfsAnnotation(key) {
			return fmt.Errorf("OCI spec already contains reserved hosts annotation %q", key)
		}
	}
	if privateManagedHosts(state) {
		if spec.Annotations == nil {
			spec.Annotations = make(map[string]string)
		}
		spec.Annotations[state.Seed.AnnotationKey] = state.Seed.AnnotationValue
		// Leave OCI root and mount sources bundle-relative, as runsc fixSpec
		// resolves them independently of its working directory. Annotation
		// and flag host paths retain their original daemon-relative meaning.
		for key, value := range spec.Annotations {
			if name, ok := strings.CutPrefix(key, "dev.gvisor.flag."); ok {
				absolute, err := absoluteRunscPathFlag("--"+name, value)
				if err != nil {
					return err
				}
				spec.Annotations[key] = absolute
			}
			if key == runtimecore.GVisorRootfsAnnotationPrefix+"source" && value != "" && !filepath.IsAbs(value) {
				absolute, err := absoluteHostPath(value)
				if err != nil {
					return err
				}
				spec.Annotations[key] = absolute
			}
			if key == runtimecore.GVisorRootfsAnnotationPrefix+"overlay" && strings.HasPrefix(value, "dir=") {
				absolute, err := absoluteOverlayDirectory(value)
				if err != nil {
					return err
				}
				spec.Annotations[key] = absolute
			}
		}
		if err := writeRunscNVProxySpec(filepath.Join(bundle, "config.json"), spec); err != nil {
			return err
		}
	}
	return runtimecore.WriteManagedHostsState(bundle, state)
}

func readHostsSeed(dir string, state *runtimecore.ManagedHostsState) ([]byte, error) {
	if err := runtimecore.ValidateManagedHostsState(state); err != nil {
		return nil, err
	}
	if !privateManagedHosts(state) || state.Seed == nil {
		return nil, errors.New("hosts seed is not declared")
	}
	f, err := os.OpenFile(filepath.Join(dir, state.Seed.File), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open hosts seed: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxHostsSeedBytes {
		return nil, errors.New("hosts seed must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxHostsSeedBytes+1))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if len(data) > maxHostsSeedBytes || hex.EncodeToString(digest[:]) != state.Seed.SHA256 {
		return nil, errors.New("hosts seed SHA-256 mismatch")
	}
	return data, nil
}

func writeHostsSeed(dir string, data []byte) error {
	f, err := os.CreateTemp(dir, ".hosts-seed-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(name) }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, runtimecore.RootfsSeedName)); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removeManagedHostsFiles(bundle string) error {
	var result error
	for _, name := range []string{runtimecore.ManagedHostsStateFile, runtimecore.RootfsSeedName} {
		if err := os.Remove(filepath.Join(bundle, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	return result
}

// Check the saved spec as well as the sidecar: removing a new bundle's sidecar
// must never silently create a checkpoint without its initialization dependency.
func managedHostsCheckpointMaterial(bundle string) (*runtimecore.ManagedHostsState, []byte, error) {
	state, err := runtimecore.ReadManagedHostsState(bundle)
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("read checkpoint OCI spec: %w", err)
	}
	var spec runtimecore.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, nil, err
	}
	for key, value := range spec.Annotations {
		if runtimecore.ManagedRootfsAnnotation(key) {
			if !privateManagedHosts(state) || key != state.Seed.AnnotationKey || value != state.Seed.AnnotationValue {
				return nil, nil, errors.New("saved OCI hosts annotation has no matching managed metadata")
			}
		}
	}
	if state == nil {
		return nil, nil, nil
	}
	if err := validateManagedHostsSpec(state, &spec); err != nil {
		return nil, nil, err
	}
	if !privateManagedHosts(state) {
		return state, nil, nil
	}
	if spec.Annotations[state.Seed.AnnotationKey] != state.Seed.AnnotationValue {
		return nil, nil, errors.New("saved OCI spec lost its managed hosts annotation")
	}
	seed, err := readHostsSeed(bundle, state)
	return state, seed, err
}
