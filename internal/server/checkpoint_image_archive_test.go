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
	image := "registry.example/akernel-ephemeral/" + strings.Repeat("b", 32) + "/service-0@" + digest
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
