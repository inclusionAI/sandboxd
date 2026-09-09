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
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConfigureFirecrackerVM(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var mu sync.Mutex
	var paths []string
	var payloads []map[string]any
	server := &http.Server{Handler: http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		defer request.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode %s: %v", request.URL.Path, err)
		}
		mu.Lock()
		paths = append(paths, request.URL.Path)
		payloads = append(payloads, payload)
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	})}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(listener)
	}()
	defer func() {
		_ = server.Close()
		<-serverDone
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api := newFirecrackerAPI(socket)
	if err := api.waitReady(ctx); err != nil {
		t.Fatal(err)
	}
	err = configureFirecrackerVM(
		ctx,
		api,
		"/opt/firecracker/vmlinux",
		"/opt/firecracker/initrd.img",
		"console=ttyS0 init=/init",
		2,
		256,
		"tap-test",
		"02:fc:0a:2a:00:02",
		"/run/firecracker/vsock",
		"",
		[]firecrackerDrive{
			{ID: "rootfs", Path: "/images/root.erofs", ReadOnly: true},
			{ID: "overlay", Path: "/storage/overlay.ext4", IOEngine: "AsyncDirect", CacheType: "Writeback"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	wantPaths := []string{
		"/boot-source",
		"/machine-config",
		"/drives/rootfs",
		"/drives/overlay",
		"/network-interfaces/eth0",
		"/vsock",
		"/actions",
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != len(wantPaths) {
		t.Fatalf("API paths = %v", paths)
	}
	for index := range wantPaths {
		if paths[index] != wantPaths[index] {
			t.Fatalf("API path %d = %q, want %q", index, paths[index], wantPaths[index])
		}
	}
	if payloads[1]["vcpu_count"] != float64(2) ||
		payloads[1]["mem_size_mib"] != float64(256) ||
		payloads[1]["track_dirty_pages"] != true {
		t.Fatalf("machine config = %+v", payloads[1])
	}
	if payloads[2]["is_read_only"] != true ||
		payloads[3]["is_read_only"] != false {
		t.Fatalf("drive configs = %+v %+v", payloads[2], payloads[3])
	}
	if payloads[3]["io_engine"] != "AsyncDirect" || payloads[3]["cache_type"] != "Writeback" {
		t.Fatalf("writable disk policy missing: %+v", payloads[3])
	}
	if _, ok := payloads[2]["io_engine"]; ok {
		t.Fatal("root disk policy changed")
	}
	if _, ok := payloads[2]["cache_type"]; ok {
		t.Fatal("root disk caching changed")
	}
	if payloads[4]["host_dev_name"] != "tap-test" ||
		payloads[4]["guest_mac"] != "02:fc:0a:2a:00:02" {
		t.Fatalf("network config = %+v", payloads[4])
	}
	if payloads[6]["action_type"] != "InstanceStart" {
		t.Fatalf("start action = %+v", payloads[6])
	}
}

func TestFirecrackerSnapshotAPI(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	type call struct {
		method  string
		path    string
		payload map[string]any
	}
	var mu sync.Mutex
	var calls []call
	server := &http.Server{Handler: http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		defer request.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode %s: %v", request.URL.Path, err)
		}
		mu.Lock()
		calls = append(calls, call{
			method: request.Method, path: request.URL.Path, payload: payload,
		})
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	})}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		<-serverDone
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api := newFirecrackerAPI(socket)
	if err := api.pause(ctx); err != nil {
		t.Fatal(err)
	}
	if err := api.createSnapshot(
		ctx,
		"/tmp/vmstate",
		"/tmp/memory",
		"",
		firecrackerSnapshotTypeFull,
	); err != nil {
		t.Fatal(err)
	}
	if err := api.resume(ctx); err != nil {
		t.Fatal(err)
	}
	if err := api.loadSnapshot(
		ctx,
		"/tmp/vmstate",
		"/tmp/memory",
		"",
		"tap-restored",
		"/run/firecracker/restored.vsock",
		"",
		"",
	); err != nil {
		t.Fatal(err)
	}
	if err := api.createSnapshot(
		ctx,
		"/checkpoint/vmstate",
		"/checkpoint/memory",
		"/checkpoint/virtiofs.state",
		firecrackerSnapshotTypeIncremental,
	); err != nil {
		t.Fatal(err)
	}
	if err := api.loadSnapshot(
		ctx,
		"/checkpoint/vmstate",
		"/checkpoint/memory",
		"/storage/memory.live",
		"tap-virtiofs",
		"/run/firecracker/virtiofs.vsock",
		"/run/firecracker/virtiofs.sock",
		"/checkpoint/virtiofs.state",
	); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 6 {
		t.Fatalf("snapshot API calls = %+v", calls)
	}
	if calls[0].method != http.MethodPatch || calls[0].path != "/vm" ||
		calls[0].payload["state"] != "Paused" {
		t.Fatalf("pause call = %+v", calls[0])
	}
	if calls[1].method != http.MethodPut ||
		calls[1].path != "/snapshot/create" ||
		calls[1].payload["snapshot_type"] != "Full" ||
		calls[1].payload["deferred_sync"] != true {
		t.Fatalf("create snapshot call = %+v", calls[1])
	}
	if calls[2].method != http.MethodPatch ||
		calls[2].payload["state"] != "Resumed" {
		t.Fatalf("resume call = %+v", calls[2])
	}
	if calls[3].method != http.MethodPut ||
		calls[3].path != "/snapshot/load" ||
		calls[3].payload["resume_vm"] != true ||
		calls[3].payload["track_dirty_pages"] != true {
		t.Fatalf("load snapshot call = %+v", calls[3])
	}
	backends, ok := calls[3].payload["network_overrides"].([]any)
	if !ok || len(backends) != 1 ||
		backends[0].(map[string]any)["host_dev_name"] != "tap-restored" {
		t.Fatalf("network overrides = %+v", calls[3].payload["network_overrides"])
	}
	vsock := calls[3].payload["vsock_override"].(map[string]any)
	if vsock["uds_path"] != "/run/firecracker/restored.vsock" {
		t.Fatalf("vsock override = %+v", vsock)
	}
	memory := calls[3].payload["mem_backend"].(map[string]any)
	if memory["backend_type"] != "File" || memory["backend_path"] != "/tmp/memory" {
		t.Fatalf("memory backend = %+v", memory)
	}
	if calls[4].payload["fs_state_path"] != "/checkpoint/virtiofs.state" {
		t.Fatalf("virtio-fs snapshot create = %+v", calls[4])
	}
	sharedMemory := calls[5].payload["mem_backend"].(map[string]any)
	if sharedMemory["backend_type"] != "SharedFile" ||
		sharedMemory["backend_path"] != "/storage/memory.live" ||
		sharedMemory["source_path"] != "/checkpoint/memory" {
		t.Fatalf("shared memory backend = %+v", sharedMemory)
	}
	fsOverride := calls[5].payload["fs_override"].(map[string]any)
	if fsOverride["fs_id"] != "root" ||
		fsOverride["socket_path"] != "/run/firecracker/virtiofs.sock" ||
		fsOverride["state_path"] != "/checkpoint/virtiofs.state" {
		t.Fatalf("virtio-fs override = %+v", fsOverride)
	}
}

func TestFirecrackerAPIErrorIncludesBody(t *testing.T) {
	api := &firecrackerAPI{client: &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Status:     "400 Bad Request",
				Body:       http.NoBody,
			}, nil
		}),
	}}
	if err := api.put(context.Background(), "/machine-config", map[string]int{
		"vcpu_count": 0,
	}); err == nil {
		t.Fatal("Firecracker API error was ignored")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return function(request)
}
