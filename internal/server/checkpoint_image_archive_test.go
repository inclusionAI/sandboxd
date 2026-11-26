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

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCheckpointImageArchiveLifecycle(t *testing.T) {
	root := t.TempDir()
	password := filepath.Join(root, "worker-token")
	require.NoError(t, os.WriteFile(password, []byte("test-credential"), 0600))
	artifacts := filepath.Join(root, "artifacts")
	require.NoError(t, os.MkdirAll(artifacts, 0700))
	artifact := "39f55353-1878-4315-9f56-b4cf4fabfaff"
	dir := filepath.Join(artifacts, artifact)
	require.NoError(t, os.Mkdir(dir, 0700))

	digest := "sha256:" + strings.Repeat("a", 64)
	const registry = "registry.example:5443"
	image := registry + "/akernel-ephemeral/" + strings.Repeat("b", 32) + "/service-0@" + digest
	type action struct {
		path   string
		fields map[string]string
	}
	actions := make(chan action, 3)
	var origin string
	var unavailable atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-credential" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fields := make(map[string]string)
		_ = json.NewDecoder(r.Body).Decode(&fields)
		if r.URL.Path == "/v1/archive/release" && unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"offline"}`))
			return
		}
		actions <- action{path: r.URL.Path, fields: fields}
		switch r.URL.Path {
		case "/v1/archive/restore":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"reference": origin + "/akernel-checkpoint/" + fields["lease"] + "@" + digest,
			})
		default:
			_, _ = w.Write([]byte("{}"))
		}
	}))
	defer server.Close()
	origin = server.URL

	a, err := newCheckpointImageArchive(config.CheckpointImageArchiveConfig{
		Origin: origin, WorkerTokenFile: password, CheckpointArtifacts: artifacts,
	}, filepath.Join(root, "state"))
	require.NoError(t, err)
	source := &runtime.RootfsConfig{
		Type:   runtime.RootfsSrcType_IMAGE,
		Source: &runtime.RootfsConfig_ImageUrl{ImageUrl: image},
	}
	raw, err := proto.Marshal(source)
	require.NoError(t, err)
	h := &sandboxService{
		checkpointImageArchive: a,
		fsMgr: &fsManager{sandboxState: map[string]sandboxFSState{
			"source": {Rootfs: raw},
		}},
	}
	h.config.ManagedRuntimeProfiles = map[string]config.ManagedRuntimeProfile{
		"harbor-ephemeral-a": {Registry: registry, RepositoryPrefix: "akernel-ephemeral"},
	}
	ctx := context.Background()
	require.NoError(t, h.captureCheckpointImage(ctx, "source", dir))
	got := <-actions
	require.Equal(t, "/v1/archive/capture", got.path)
	require.Equal(t, image, got.fields["reference"])
	require.Equal(t, artifact, got.fields["artifact"])
	require.Regexp(t, checkpointRuntimeLease, got.fields["lease"])
	require.FileExists(t, a.leaseFile("source"))

	restored := proto.Clone(source).(*runtime.RootfsConfig)
	_, err = h.restoreCheckpointImage(ctx, "restored", dir, restored)
	require.ErrorContains(t, err, "archive receipt")
	require.NoFileExists(t, a.leaseFile("restored"))

	require.NoError(t, os.WriteFile(filepath.Join(dir, checkpointImageArchiveReceipt), []byte("{}"), 0600))
	leased, err := h.restoreCheckpointImage(ctx, "restored", dir, restored)
	require.NoError(t, err)
	require.True(t, leased)
	restore := <-actions
	require.Equal(t, "/v1/archive/restore", restore.path)
	require.Equal(t, image, restore.fields["reference"])
	require.NotEqual(t, got.fields["lease"], restore.fields["lease"])
	require.Equal(t, normalizeCheckpointImage(origin)+"/akernel-checkpoint/"+restore.fields["lease"]+"@"+digest, restored.GetImageUrl())
	require.Equal(t, image, source.GetImageUrl())

	require.NoError(t, a.queueRelease("restored"))
	pending := filepath.Join(a.state, checkpointReleasePrefix+restore.fields["lease"])
	require.FileExists(t, pending)
	unavailable.Store(true)
	require.ErrorContains(t, a.drainPendingReleases(ctx), "HTTP 503")
	require.FileExists(t, pending)
	unavailable.Store(false)
	require.NoError(t, a.drainPendingReleases(ctx))
	released := <-actions
	require.Equal(t, "/v1/archive/release", released.path)
	require.Equal(t, restore.fields["lease"], released.fields["lease"])
	require.NoFileExists(t, a.leaseFile("restored"))
	require.NoFileExists(t, filepath.Join(a.state, checkpointReleasePrefix+restore.fields["lease"]))
	require.FileExists(t, a.leaseFile("source"))

	mount := &runtime.Mount{Source: &runtime.Mount_ImageUrl{ImageUrl: restored.GetImageUrl()}}
	require.ErrorContains(t, a.validateUserImages(&runtime.StartRequest{Mounts: []*runtime.Mount{mount}}), "cannot be mounted by callers")
	require.ErrorContains(t, a.validateUserImages(&runtime.StartRequest{Rootfs: restored}), "internal to restore")
}

func TestCheckpointImageArchiveSourcePolicy(t *testing.T) {
	const temporaryRegistry = "temporary.example:5443"
	const durableRegistry = "durable.example:5443"
	profiles := map[string]config.ManagedRuntimeProfile{
		"harbor-ephemeral-a": {Registry: temporaryRegistry, RepositoryPrefix: "akernel-ephemeral"},
		"durable":            {Registry: durableRegistry, RepositoryPrefix: "managed"},
	}
	build := "/" + strings.Repeat("b", 32) + "/service-0@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name      string
		image     string
		profiles  map[string]config.ManagedRuntimeProfile
		temporary bool
	}{
		{"configured temporary source", "https://" + temporaryRegistry + "/akernel-ephemeral" + build, profiles, true},
		{"unconfigured Registry", "other.example:5443/akernel-ephemeral" + build, profiles, false},
		{"different port", "temporary.example:5000/akernel-ephemeral" + build, profiles, false},
		{"configured durable Registry", durableRegistry + "/akernel-ephemeral" + build, profiles, false},
		{"different repository prefix", temporaryRegistry + "/akernel-ephemeral-copy" + build, profiles, false},
		{"no managed profiles", temporaryRegistry + "/akernel-ephemeral" + build, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootfs := &runtime.RootfsConfig{
				Type:   runtime.RootfsSrcType_IMAGE,
				Source: &runtime.RootfsConfig_ImageUrl{ImageUrl: tc.image},
			}
			raw, err := proto.Marshal(rootfs)
			require.NoError(t, err)
			worker := &sandboxService{
				fsMgr: &fsManager{sandboxState: map[string]sandboxFSState{
					"source": {Rootfs: raw},
				}},
			}
			worker.config.ManagedRuntimeProfiles = tc.profiles
			dir := t.TempDir()

			captureErr := worker.captureCheckpointImage(t.Context(), "source", dir)
			leased, restoreErr := worker.restoreCheckpointImage(t.Context(), "restored", dir, rootfs)
			require.False(t, leased)
			require.Equal(t, tc.image, rootfs.GetImageUrl())
			if tc.temporary {
				require.ErrorIs(t, captureErr, errord.ErrFailedPrecondition)
				require.ErrorIs(t, restoreErr, errord.ErrFailedPrecondition)
			} else {
				require.NoError(t, captureErr)
				require.NoError(t, restoreErr)
			}
		})
	}
}

type checkpointImageInventory struct {
	svc.FakeRuntimeHandler
	states []*svc.State
}

func (i *checkpointImageInventory) List(context.Context) ([]*svc.State, error) {
	return i.states, nil
}

func TestRecoverCheckpointImageLeasesQueuesOrphans(t *testing.T) {
	var available atomic.Bool
	releases := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var fields map[string]string
		if r.URL.Path != "/v1/archive/release" || json.NewDecoder(r.Body).Decode(&fields) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		releases <- fields["lease"]
		if !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(server.Close)

	root := t.TempDir()
	cfg := config.CheckpointImageArchiveConfig{
		Origin:              server.URL,
		WorkerTokenFile:     filepath.Join(root, "worker-token"),
		CheckpointArtifacts: filepath.Join(root, "artifacts"),
	}
	require.NoError(t, os.WriteFile(cfg.WorkerTokenFile, []byte("test-credential"), 0600))
	store := filepath.Join(root, "store")
	archive, err := newCheckpointImageArchive(cfg, store)
	require.NoError(t, err)
	const orphan = "sbox-orphan"
	const live = "sbox-active"
	const tracked = "sbox-tracked"
	orphanLease, err := archive.reserve(orphan)
	require.NoError(t, err)
	_, err = archive.reserve(live)
	require.NoError(t, err)
	_, err = archive.reserve(tracked)
	require.NoError(t, err)

	inventory := &checkpointImageInventory{states: []*svc.State{
		{ID: live, Status: svc.SandboxStatusRunning},
	}}
	worker := newTestService(t, map[string]svc.Handler{config.RuntimeNameRunsc: inventory})
	t.Cleanup(worker.sandboxManager.Stop)
	require.NoError(t, worker.sandboxManager.StoreMetadata(tracked, &runtime.SandboxMetadata{
		ID: tracked, RuntimeHandler: config.RuntimeNameRunsc,
	}))
	worker.checkpointImageArchive = archive

	ctx := t.Context()
	require.NoError(t, worker.recoverCheckpointImageLeases(ctx))
	require.Empty(t, releases, "startup recovery must not contact the archive")
	pending := filepath.Join(archive.state, checkpointReleasePrefix+orphanLease)
	require.FileExists(t, pending)
	require.NoFileExists(t, archive.leaseFile(orphan))
	require.FileExists(t, archive.leaseFile(live))
	require.FileExists(t, archive.leaseFile(tracked))

	require.ErrorContains(t, archive.drainPendingReleases(ctx), "HTTP 503")
	require.Len(t, releases, 1)
	require.Equal(t, orphanLease, <-releases)
	require.FileExists(t, pending)

	restarted, err := newCheckpointImageArchive(cfg, store)
	require.NoError(t, err)
	available.Store(true)
	require.NoError(t, restarted.drainPendingReleases(ctx))
	require.Len(t, releases, 1)
	require.Equal(t, orphanLease, <-releases)
	require.NoFileExists(t, pending)
	require.FileExists(t, restarted.leaseFile(live))
	require.FileExists(t, restarted.leaseFile(tracked))
}
