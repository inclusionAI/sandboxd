// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package runsc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

type hostsLifecycleClient struct {
	successfulRunscClient
	created     StartArgs
	checkpoints int
	deleted     bool
	startError  error
}

func (c *hostsLifecycleClient) Create(_ context.Context, args StartArgs) error {
	c.created = args
	return nil
}
func (c *hostsLifecycleClient) Start(context.Context, StartArgs) error { return c.startError }
func (c *hostsLifecycleClient) Delete(context.Context, string, bool) error {
	c.deleted = true
	return nil
}
func (c *hostsLifecycleClient) Checkpoint(_ context.Context, _, dir string, _, _ bool) error {
	c.checkpoints++
	return os.MkdirAll(dir, 0700)
}

func freshHostsState() *runtimecore.ManagedHostsState {
	return &runtimecore.ManagedHostsState{Version: runtimecore.ManagedHostsVersion, Runtime: "runsc", Layout: runtimecore.HostsLayoutPrivateRootfs}
}

func hostsHandlerFixture(t *testing.T, id string, client *hostsLifecycleClient) (*Handler, runtimecore.StartConfig, string) {
	t.Helper()
	bundles, lower := t.TempDir(), t.TempDir()
	bundle := filepath.Join(bundles, id)
	if err := os.Mkdir(bundle, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(lower, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	h := &Handler{runsc: client, sandboxRoot: bundles, filestoreDir: t.TempDir(), ociLoader: staticOciLoader{bundlePath: bundle, spec: &runtimecore.Spec{Root: &runtimecore.Root{Path: lower}}}}
	start := runtimecore.StartConfig{ID: id, Network: &networkmanager.NetResource{}, ManagedHosts: freshHostsState(), InitialFiles: []runtimecore.InitialFile{{Path: "/etc/hosts", Content: []byte("original-host\n"), Mode: 0644}}}
	return h, start, bundle
}

func TestManagedHostsSurviveDaemonRestartAndRepeatedCheckpoint(t *testing.T) {
	client := &hostsLifecycleClient{}
	h, start, bundle := hostsHandlerFixture(t, "source", client)
	if err := h.Start(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if !client.created.SeededRootfs || start.ManagedHosts.Seed != nil {
		t.Fatalf("seed setup missing or mutated caller state: %+v", client.created)
	}
	original, err := runtimecore.ReadManagedHostsState(bundle)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(t.TempDir(), "snapshot")
	// A new Handler has no in-memory seed information after daemon restart.
	restarted := &Handler{runsc: client, sandboxRoot: h.sandboxRoot}
	if err := restarted.Checkpoint(context.Background(), runtimecore.CheckpointConfig{ID: start.ID, Directory: checkpoint}); err != nil {
		t.Fatal(err)
	}
	saved, err := runtimecore.ReadManagedHostsState(checkpoint)
	if err != nil || !reflect.DeepEqual(original, saved) {
		t.Fatalf("checkpoint state=%+v err=%v", saved, err)
	}
	if err := os.RemoveAll(bundle); err != nil {
		t.Fatal(err)
	}
	targetClient := &hostsLifecycleClient{}
	target, restore, targetBundle := hostsHandlerFixture(t, "target", targetClient)
	restore.InitialFiles, restore.ManagedHosts, restore.CheckpointDir = nil, saved, checkpoint
	// Restore must not inspect the image's parent metadata or regenerate a tar.
	target.mountEROFS = func(string, string) error { t.Fatal("restore read fresh image metadata"); return nil }
	if err := target.Restore(context.Background(), restore); err != nil {
		t.Fatal(err)
	}
	restored, err := runtimecore.ReadManagedHostsState(targetBundle)
	if err != nil || !reflect.DeepEqual(restored, saved) || !targetClient.created.SeededRootfs {
		t.Fatalf("restored state=%+v err=%v", restored, err)
	}
	second := filepath.Join(t.TempDir(), "second")
	secondHandler := &Handler{runsc: targetClient, sandboxRoot: target.sandboxRoot}
	if err := secondHandler.Checkpoint(context.Background(), runtimecore.CheckpointConfig{ID: restore.ID, Directory: second}); err != nil {
		t.Fatal(err)
	}
	if _, err := readHostsSeed(second, saved); err != nil {
		t.Fatal(err)
	}
}

func TestManagedHostsCheckpointRejectsLostOrChangedMaterials(t *testing.T) {
	for _, mutation := range []string{"missing-state", "corrupt-seed", "symlink-seed", "missing-annotation"} {
		t.Run(mutation, func(t *testing.T) {
			client := &hostsLifecycleClient{}
			h, start, bundle := hostsHandlerFixture(t, "source", client)
			if err := h.Start(context.Background(), start); err != nil {
				t.Fatal(err)
			}
			seed := filepath.Join(bundle, runtimecore.RootfsSeedName)
			switch mutation {
			case "missing-state":
				if err := os.Remove(filepath.Join(bundle, runtimecore.ManagedHostsStateFile)); err != nil {
					t.Fatal(err)
				}
			case "corrupt-seed":
				if err := os.WriteFile(seed, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink-seed":
				if err := os.Rename(seed, seed+"-outside"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(seed+"-outside", seed); err != nil {
					t.Fatal(err)
				}
			case "missing-annotation":
				spec := h.ociLoader.(staticOciLoader).spec.DeepCopy()
				delete(spec.Annotations, runtimecore.GVisorRootfsTarUpperAnnotation)
				if err := writeRunscNVProxySpec(filepath.Join(bundle, "config.json"), spec); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.Checkpoint(context.Background(), runtimecore.CheckpointConfig{ID: start.ID, Directory: t.TempDir()}); err == nil {
				t.Fatal("accepted incomplete checkpoint dependencies")
			}
			if client.checkpoints != 0 {
				t.Fatal("native checkpoint ran before material validation")
			}
		})
	}
}

func TestManagedHostsStartFailureRemovesMaterials(t *testing.T) {
	client := &hostsLifecycleClient{startError: errors.New("start failed")}
	h, start, bundle := hostsHandlerFixture(t, "failure", client)
	if err := h.Start(context.Background(), start); err == nil {
		t.Fatal("expected start failure")
	}
	if !client.deleted {
		t.Fatal("failed runtime was not deleted")
	}
	for _, name := range []string{runtimecore.RootfsSeedName, runtimecore.ManagedHostsStateFile} {
		if _, err := os.Lstat(filepath.Join(bundle, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed start retained %s: %v", name, err)
		}
	}
}

func TestManagedHostsFinalSpecChecks(t *testing.T) {
	for _, mutation := range []string{"readonly", "parent-mount", "hosts-mount", "container-name"} {
		t.Run(mutation, func(t *testing.T) {
			client := &hostsLifecycleClient{}
			h, start, bundle := hostsHandlerFixture(t, "rejected", client)
			spec := h.ociLoader.(staticOciLoader).spec
			switch mutation {
			case "readonly":
				spec.Root.Readonly = true
			case "parent-mount":
				spec.Mounts = []runtimecore.Mount{{Destination: "/etc"}}
			case "hosts-mount":
				spec.Mounts = []runtimecore.Mount{{Destination: "/etc/hosts"}}
			case "container-name":
				spec.Annotations = map[string]string{"io.kubernetes.cri.container-name": "named"}
			}
			if err := h.Start(context.Background(), start); err == nil {
				t.Fatal("accepted conflicting OCI root/mount")
			}
			if client.created.ID != "" {
				t.Fatal("runtime created despite conflict")
			}
			if _, err := os.Stat(filepath.Join(bundle, runtimecore.RootfsSeedName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected layout retained seed")
			}
		})
	}
}

func TestManagedHostsLegacyCheckpointAndRestoreInitializationRejection(t *testing.T) {
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte(`{"root":{"path":"rootfs"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	state, seed, err := managedHostsCheckpointMaterial(bundle)
	if err != nil || state != nil || seed != nil {
		t.Fatalf("legacy checkpoint=%+v/%v, %v", state, seed, err)
	}
	_, err = prepareRestoredManagedHosts(t.TempDir(), nil, runtimecore.StartConfig{InitialFiles: []runtimecore.InitialFile{{Path: "/etc/hosts"}}})
	if err == nil || !strings.Contains(err.Error(), "must not initialize") {
		t.Fatalf("restore initialization error=%v", err)
	}
}

func TestManagedHostsHandlerRejectsOverlappingArtifactWithoutCleanup(t *testing.T) {
	client := &hostsLifecycleClient{}
	h, start, bundle := hostsHandlerFixture(t, "source", client)
	if err := h.Start(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	state, err := runtimecore.ReadManagedHostsState(bundle)
	if err != nil {
		t.Fatal(err)
	}
	seedBefore, err := os.ReadFile(filepath.Join(bundle, runtimecore.RootfsSeedName))
	if err != nil {
		t.Fatal(err)
	}
	start.InitialFiles, start.ManagedHosts, start.CheckpointDir = nil, state, bundle
	if err := h.Restore(context.Background(), start); err == nil {
		t.Fatal("accepted checkpoint as restore bundle")
	}
	if err := h.Checkpoint(context.Background(), runtimecore.CheckpointConfig{ID: start.ID, Directory: bundle}); err == nil {
		t.Fatal("accepted source bundle as checkpoint output")
	}
	seedAfter, err := os.ReadFile(filepath.Join(bundle, runtimecore.RootfsSeedName))
	if err != nil || !reflect.DeepEqual(seedBefore, seedAfter) {
		t.Fatalf("rejected operation changed input seed: %v", err)
	}
	stateAfter, err := runtimecore.ReadManagedHostsState(bundle)
	if err != nil || !reflect.DeepEqual(state, stateAfter) {
		t.Fatalf("rejected operation changed input state: %+v %v", stateAfter, err)
	}
	if client.deleted || client.checkpoints != 0 {
		t.Fatal("rejected operation reached runtime or cleanup")
	}
}

func TestManagedHostsPreserveSymlinkParentAnnotations(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	actual := filepath.Join(root, "actual")
	if err := os.MkdirAll(filepath.Join(actual, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(actual, "nested"), "image-link"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"image", "device", "overlay"} {
		if err := os.WriteFile(filepath.Join(actual, name), []byte("intended-"+name), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("wrong-"+name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"relative", "absolute"} {
		t.Run(mode, func(t *testing.T) {
			h, start, bundle := hostsHandlerFixture(t, mode, &hostsLifecycleClient{})
			spec := h.ociLoader.(staticOciLoader).spec
			state, err := h.prepareFreshManagedHosts(bundle, spec, start)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "image-link/../"
			if mode == "absolute" {
				prefix = root + "/" + prefix
			}
			spec.Annotations = map[string]string{
				runtimecore.GVisorRootfsAnnotationPrefix + "type":    "erofs",
				runtimecore.GVisorRootfsAnnotationPrefix + "source":  prefix + "image",
				runtimecore.GVisorRootfsAnnotationPrefix + "overlay": "dir=" + prefix + "overlay",
				"dev.gvisor.flag.platform_device_path":               "kvm=" + prefix + "device",
			}
			if err := finalizeManagedHosts(bundle, spec, state); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			var saved runtimecore.Spec
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			for name, key := range map[string]string{"image": runtimecore.GVisorRootfsAnnotationPrefix + "source", "device": "dev.gvisor.flag.platform_device_path", "overlay": runtimecore.GVisorRootfsAnnotationPrefix + "overlay"} {
				path := saved.Annotations[key]
				path = strings.TrimPrefix(strings.TrimPrefix(path, "kvm="), "dir=")
				if !filepath.IsAbs(path) {
					t.Fatalf("annotation %s is still relative: %q", key, path)
				}
				if got, err := os.ReadFile(path); err != nil || string(got) != "intended-"+name {
					t.Fatalf("annotation %s changed path meaning: %q, %v", key, got, err)
				}
			}
		})
	}
}

func TestManagedHostsPreserveBundleRelativeMountsAcrossRestore(t *testing.T) {
	client := &hostsLifecycleClient{}
	h, start, bundle := hostsHandlerFixture(t, "source", client)
	spec := h.ociLoader.(staticOciLoader).spec
	t.Chdir(t.TempDir())
	for _, kind := range []string{"bind", "erofs"} {
		if err := os.Mkdir(filepath.Join(spec.Root.Path, kind), 0755); err != nil {
			t.Fatal(err)
		}
	}
	spec.Mounts = []runtimecore.Mount{
		{Type: "bind", Source: "../shared", Destination: "/bind", Options: []string{"ro", "bind"}},
		{Type: "erofs", Source: "../shared.erofs", Destination: "/erofs", Options: []string{"ro"}},
	}
	freshSpec := spec.DeepCopy()
	assertMounts := func(bundle string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		var saved runtimecore.Spec
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(saved.Mounts, freshSpec.Mounts) {
			t.Fatalf("bundle-relative mount sources changed: %+v", saved.Mounts)
		}
	}
	if err := h.Start(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	assertMounts(bundle)
	checkpoint := filepath.Join(t.TempDir(), "checkpoint")
	if err := h.Checkpoint(context.Background(), runtimecore.CheckpointConfig{ID: start.ID, Directory: checkpoint}); err != nil {
		t.Fatal(err)
	}
	targetBundle := filepath.Join(h.sandboxRoot, "target")
	if err := os.Mkdir(targetBundle, 0755); err != nil {
		t.Fatal(err)
	}
	target := &Handler{runsc: &hostsLifecycleClient{}, sandboxRoot: h.sandboxRoot, filestoreDir: h.filestoreDir, ociLoader: staticOciLoader{bundlePath: targetBundle, spec: freshSpec}}
	restore := start
	restore.ID, restore.InitialFiles, restore.ManagedHosts, restore.CheckpointDir = "target", nil, nil, checkpoint
	if err := target.Restore(context.Background(), restore); err != nil {
		t.Fatal(err)
	}
	assertMounts(targetBundle)
}

func TestManagedHostsUserNamespaceDirectoryLifecycleRejected(t *testing.T) {
	for _, namespacePath := range []string{"", "/proc/123/ns/user"} {
		t.Run(namespacePath, func(t *testing.T) {
			client := &hostsLifecycleClient{}
			handler, start, bundle := hostsHandlerFixture(t, "remapped", client)
			spec := handler.ociLoader.(staticOciLoader).spec
			spec.Linux = &runtimecore.Linux{Namespaces: []runtimecore.LinuxNamespace{{Type: runtimecore.UserNamespace, Path: namespacePath}}, UIDMappings: []runtimecore.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}, GIDMappings: []runtimecore.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}}
			err := handler.Start(context.Background(), start)
			if err == nil || !strings.Contains(err.Error(), "explicit user namespace") {
				t.Fatalf("unsafe fresh initialization accepted: %v", err)
			}
			if client.created.ID != "" {
				t.Fatal("runtime reached before namespace rejection")
			}
			if _, err := os.Stat(filepath.Join(bundle, runtimecore.RootfsSeedName)); !os.IsNotExist(err) {
				t.Fatalf("fresh seed persisted: %v", err)
			}

			// A valid checkpoint must not be mutated when the requested final gofer
			// view cannot preserve its parent metadata.
			sourceClient := &hostsLifecycleClient{}
			source, fresh, sourceBundle := hostsHandlerFixture(t, "source", sourceClient)
			if err := source.Start(context.Background(), fresh); err != nil {
				t.Fatal(err)
			}
			seedPath := filepath.Join(sourceBundle, runtimecore.RootfsSeedName)
			before, err := os.ReadFile(seedPath)
			if err != nil {
				t.Fatal(err)
			}
			saved, err := runtimecore.ReadManagedHostsState(sourceBundle)
			if err != nil {
				t.Fatal(err)
			}
			_, err = prepareRestoredManagedHosts(bundle, spec, runtimecore.StartConfig{CheckpointDir: sourceBundle, ManagedHosts: saved})
			if err == nil || !strings.Contains(err.Error(), "explicit user namespace") {
				t.Fatalf("unsafe restore accepted: %v", err)
			}
			after, err := os.ReadFile(seedPath)
			if err != nil || string(before) != string(after) {
				t.Fatalf("input seed changed: %v", err)
			}

			// A direct EROFS view uses image IDs. If a provider later converts it
			// to a host directory, finalization must recheck the actual root type.
			spec.Annotations = map[string]string{runtimecore.GVisorRootfsAnnotationPrefix + "type": "erofs", runtimecore.GVisorRootfsAnnotationPrefix + "source": "/image.erofs"}
			if err := validateManagedHostsSpec(saved, spec); err != nil {
				t.Fatalf("direct EROFS rejected: %v", err)
			}
			spec.Annotations = nil
			if err := finalizeManagedHosts(bundle, spec, saved); err == nil || !strings.Contains(err.Error(), "explicit user namespace") {
				t.Fatalf("directory fallback accepted: %v", err)
			}

			for _, layout := range []runtimecore.HostsLayout{runtimecore.HostsLayoutExternal, runtimecore.HostsLayoutLegacy} {
				mounted := &runtimecore.ManagedHostsState{Version: runtimecore.ManagedHostsVersion, Runtime: "runsc", Layout: layout, RootReadonly: layout == runtimecore.HostsLayoutLegacy}
				spec.Root.Readonly = mounted.RootReadonly
				spec.Mounts = []runtimecore.Mount{{Destination: "/etc/hosts", Type: "bind", Source: "/approved/hosts"}}
				if err := validateManagedHostsSpec(mounted, spec); err != nil {
					t.Fatalf("existing mounted layout rejected: %v", err)
				}
			}
		})
	}
}
