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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

type firecrackerAPI struct {
	socket string
	client *http.Client
}

func newFirecrackerAPI(socket string) *firecrackerAPI {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
	return &firecrackerAPI{
		socket: socket,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
	}
}

func (api *firecrackerAPI) waitReady(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := net.DialTimeout("unix", api.socket, 50*time.Millisecond)
		if err == nil {
			connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Firecracker API socket %s: %w", api.socket, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (api *firecrackerAPI) put(ctx context.Context, path string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPut,
		"http://localhost"+path,
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := api.client.Do(request)
	if err != nil {
		return fmt.Errorf("Firecracker PUT %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusBadRequest {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf(
		"Firecracker PUT %s returned %s: %s",
		path,
		response.Status,
		bytes.TrimSpace(body),
	)
}

func firecrackerDrivePath(id string) string {
	return "/drives/" + url.PathEscape(id)
}

func configureFirecrackerVM(
	ctx context.Context,
	api *firecrackerAPI,
	kernelPath,
	initrdPath,
	kernelArgs string,
	vcpus,
	memoryMiB uint32,
	tapName,
	guestMAC,
	vsockPath string,
	drives []firecrackerDrive,
) error {
	if err := api.put(ctx, "/boot-source", map[string]any{
		"kernel_image_path": kernelPath,
		"initrd_path":       initrdPath,
		"boot_args":         kernelArgs,
	}); err != nil {
		return err
	}
	if err := api.put(ctx, "/machine-config", map[string]any{
		"vcpu_count":   vcpus,
		"mem_size_mib": memoryMiB,
		"smt":          false,
	}); err != nil {
		return err
	}
	for _, drive := range drives {
		if err := api.put(ctx, firecrackerDrivePath(drive.ID), map[string]any{
			"drive_id":       drive.ID,
			"path_on_host":   drive.Path,
			"is_root_device": false,
			"is_read_only":   drive.ReadOnly,
		}); err != nil {
			return err
		}
	}
	if err := api.put(ctx, "/network-interfaces/eth0", map[string]any{
		"iface_id":      "eth0",
		"host_dev_name": tapName,
		"guest_mac":     guestMAC,
	}); err != nil {
		return err
	}
	if err := api.put(ctx, "/vsock", map[string]any{
		"guest_cid": 3,
		"uds_path":  vsockPath,
	}); err != nil {
		return err
	}
	return api.put(ctx, "/actions", map[string]any{
		"action_type": "InstanceStart",
	})
}

func removeFirecrackerSocket(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
