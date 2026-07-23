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
	"encoding/json"
	"sync"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
	"github.com/inclusionAI/sandboxd/pkg/store"
)

type fsTestImageService struct {
	mu             sync.Mutex
	ociMountCalls  map[string]int
	ociUmountCalls map[string]int
}

func newFSTestImageService() *fsTestImageService {
	return &fsTestImageService{
		ociMountCalls:  make(map[string]int),
		ociUmountCalls: make(map[string]int),
	}
}

func (s *fsTestImageService) MountOSS(req *imageapi.OSSMountRequest) (*imageapi.MountInfo, error) {
	return &imageapi.MountInfo{FilePath: "/mnt/s3/" + req.Object}, nil
}

func (s *fsTestImageService) UmountOSS(*imageapi.OSSUmountRequest) error { return nil }

func (s *fsTestImageService) MountOCI(req *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	s.mu.Lock()
	s.ociMountCalls[req.ImageURL]++
	s.mu.Unlock()
	return &imageapi.OCIMountResponse{MountPath: "/mnt/oci/" + req.ImageURL}, nil
}

func (s *fsTestImageService) UmountOCI(req *imageapi.OCIUmountRequest) error {
	s.mu.Lock()
	s.ociUmountCalls[req.ImageURL]++
	s.mu.Unlock()
	return nil
}

func (s *fsTestImageService) MountNydus(*imageapi.NydusMountRequest) (*imageapi.MountInfo, error) {
	return &imageapi.MountInfo{}, nil
}

func (s *fsTestImageService) UmountNydus(*imageapi.NydusUmountRequest) error { return nil }
func (s *fsTestImageService) CleanupDaemon(*imageapi.CleanupDaemonRequest) error {
	return nil
}
func (s *fsTestImageService) ListDaemons() ([]distillfs.DaemonInfo, error) { return nil, nil }
func (s *fsTestImageService) ListMountedOCIImages() ([]string, error)      { return nil, nil }
func (s *fsTestImageService) ListMountedOCIDetails() ([]oci.OciMountRecord, error) {
	return nil, nil
}

func (s *fsTestImageService) mountCalls(imageURL string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ociMountCalls[imageURL]
}

func (s *fsTestImageService) umountCalls(imageURL string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ociUmountCalls[imageURL]
}

func fsTestStartRequest(id string) *runtime.StartRequest {
	return &runtime.StartRequest{
		SandboxID: id,
		Rootfs: &runtime.RootfsConfig{
			Type: runtime.RootfsSrcType_IMAGE,
			Source: &runtime.RootfsConfig_ImageUrl{
				ImageUrl: "registry.example/rootfs:latest",
			},
		},
		Mounts: []*runtime.Mount{
			{
				Target:  "/opt/data",
				Options: []string{"ro"},
				Source: &runtime.Mount_ImageUrl{
					ImageUrl: "registry.example/data:latest",
				},
			},
		},
	}
}

func prepareAndCommitFS(t *testing.T, manager *fsManager, sandboxID string) {
	t.Helper()
	prepared, err := manager.Prepare(fsTestStartRequest(sandboxID))
	if err != nil {
		t.Fatalf("Prepare(%s) failed: %v", sandboxID, err)
	}
	manager.Commit(sandboxID, prepared)
}

func TestFSManagerRestoresSharedRootfsAndMountReferences(t *testing.T) {
	stateStore := store.NewMockStore()
	service := newFSTestImageService()
	beforeCrash := newFSManager(service, stateStore)
	prepareAndCommitFS(t, beforeCrash, "sandbox-a")
	prepareAndCommitFS(t, beforeCrash, "sandbox-b")

	if got := service.mountCalls("registry.example/rootfs:latest"); got != 1 {
		t.Fatalf("rootfs mount calls before restart = %d, want 1", got)
	}
	if got := service.mountCalls("registry.example/data:latest"); got != 1 {
		t.Fatalf("additional mount calls before restart = %d, want 1", got)
	}

	afterCrash := newFSManager(service, stateStore)
	if err := afterCrash.Restore(func(string) bool { return true }); err != nil {
		t.Fatalf("Restore() failed: %v", err)
	}
	if got := afterCrash.oci.entries["registry.example/data:latest"].refcount; got != 2 {
		t.Fatalf("restored additional mount refcount = %d, want 2", got)
	}

	afterCrash.Release("sandbox-a")
	if got := service.umountCalls("registry.example/rootfs:latest"); got != 0 {
		t.Fatalf("rootfs unmounted while sandbox-b still uses it: calls=%d", got)
	}
	if got := service.umountCalls("registry.example/data:latest"); got != 0 {
		t.Fatalf("additional mount unmounted while sandbox-b still uses it: calls=%d", got)
	}

	afterCrash.Release("sandbox-b")
	if got := service.umountCalls("registry.example/rootfs:latest"); got != 1 {
		t.Fatalf("rootfs unmount calls after last release = %d, want 1", got)
	}
	if got := service.umountCalls("registry.example/data:latest"); got != 1 {
		t.Fatalf("additional unmount calls after last release = %d, want 1", got)
	}

	data, err := stateStore.LoadRaw(config.SandboxFSStateBucket)
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	var persisted storedSandboxFSStates
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("decode persisted state: %v", err)
	}
	if len(persisted.Items) != 0 {
		t.Fatalf("persisted state not empty after releases: %+v", persisted.Items)
	}
}

func TestFSManagerRestoreCleansOrphanState(t *testing.T) {
	stateStore := store.NewMockStore()
	service := newFSTestImageService()
	beforeCrash := newFSManager(service, stateStore)
	prepareAndCommitFS(t, beforeCrash, "orphan")

	afterCrash := newFSManager(service, stateStore)
	if err := afterCrash.Restore(func(string) bool { return false }); err != nil {
		t.Fatalf("Restore() failed: %v", err)
	}
	if len(afterCrash.sandboxState) != 0 {
		t.Fatalf("orphan state was retained: %+v", afterCrash.sandboxState)
	}
	if got := service.umountCalls("registry.example/rootfs:latest"); got != 1 {
		t.Fatalf("orphan rootfs unmount calls = %d, want 1", got)
	}
	if got := service.umountCalls("registry.example/data:latest"); got != 1 {
		t.Fatalf("orphan additional unmount calls = %d, want 1", got)
	}
}
