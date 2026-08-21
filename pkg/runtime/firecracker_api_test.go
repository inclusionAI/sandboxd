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
		[]firecrackerDrive{
			{ID: "rootfs", Path: "/images/root.erofs", ReadOnly: true},
			{ID: "overlay", Path: "/storage/overlay.ext4"},
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
		payloads[1]["mem_size_mib"] != float64(256) {
		t.Fatalf("machine config = %+v", payloads[1])
	}
	if payloads[2]["is_read_only"] != true ||
		payloads[3]["is_read_only"] != false {
		t.Fatalf("drive configs = %+v %+v", payloads[2], payloads[3])
	}
	if payloads[4]["host_dev_name"] != "tap-test" ||
		payloads[4]["guest_mac"] != "02:fc:0a:2a:00:02" {
		t.Fatalf("network config = %+v", payloads[4])
	}
	if payloads[6]["action_type"] != "InstanceStart" {
		t.Fatalf("start action = %+v", payloads[6])
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
