// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStartRejectsInvalidMountDestinationsBeforePreparation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mounts []*api.Mount
	}{
		{"duplicate", []*api.Mount{{Target: "/data"}, {Target: "/data"}}},
		{"trailing slash", []*api.Mount{{Target: "/data/"}}},
		{"dot component", []*api.Mount{{Target: "/app/./logs"}}},
		{"relative", []*api.Mount{{Target: "data"}}},
		{"nil", []*api.Mount{nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
			// No preparation service is installed: invalid destinations must be
			// rejected before an image pull, resource allocation or runtime call.
			service.fsMgr = nil
			response, err := service.Start(context.Background(), &api.StartRequest{
				Rootfs: &api.RootfsConfig{Type: api.RootfsSrcType_IMAGE, Source: &api.RootfsConfig_ImageUrl{ImageUrl: "must-not-be-pulled"}},
				Mounts: tc.mounts,
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("error = %v, want InvalidArgument", err)
			}
			if response == nil || response.Code != -1 {
				t.Fatalf("response = %v", response)
			}
		})
	}
}

// Managed preparation can allocate collection directories and inspect mounts.
// The ordinary mount contract must reject invalid inputs before either happens.
func TestManagedStartRejectsInvalidMountsBeforeProfilePreparation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mounts []*api.Mount
	}{
		{"duplicate", []*api.Mount{{Target: "/data"}, {Target: "/data"}}},
		{"trailing slash", []*api.Mount{{Target: "/data/"}}},
		{"dot component", []*api.Mount{{Target: "/app/./logs"}}},
		{"relative", []*api.Mount{{Target: "data"}}},
		{"nil", []*api.Mount{nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := managedTestService(t)
			service.recoveryReady.Store(true)
			response, err := service.Start(context.Background(), &api.StartRequest{
				ExtraConfig:             `{"managedRuntimeProfile":"compose-v1"}`,
				Labels:                  map[string]string{"adx.tenant_id": "allowed"},
				WritableLayerLimitBytes: 8192 << 20,
				Mounts:                  tc.mounts,
			})
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "mount destination") {
				t.Fatalf("error = %v, want invalid mount destination", err)
			}
			if response == nil || response.Code != -1 {
				t.Fatalf("response = %v", response)
			}
			entries, readErr := os.ReadDir(service.config.ManagedRuntimeRoot)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("invalid mounts changed managed state: entries=%v err=%v", entries, readErr)
			}
		})
	}
}

func TestManagedStartRejectsDisabledOCIImageVolumeBeforeProfilePreparation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  string
		code    codes.Code
		message string
	}{
		{"disabled_volume", "/data", codes.FailedPrecondition, "OCI image volumes are disabled on this worker"},
		{"invalid_destination", "relative", codes.InvalidArgument, "mount destination"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := managedTestService(t)
			service.recoveryReady.Store(true)
			service.config.DisableOCIImageMounts = true
			root := service.config.ManagedRuntimeRoot
			// Block profile preparation before it can attempt a kernel mount.
			if err := os.WriteFile(filepath.Join(root, "collections"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			request := fsTestStartRequest("sbox-disabled-image-volume")
			request.ExtraConfig = `{"managedRuntimeProfile":"compose-v1"}`
			request.Labels = map[string]string{"adx.tenant_id": "allowed"}
			request.WritableLayerLimitBytes = 8192 << 20
			request.Mounts[0].Target = tc.target

			response, err := service.Start(context.Background(), request)
			if status.Code(err) != tc.code || !strings.Contains(status.Convert(err).Message(), tc.message) {
				t.Errorf("error = %v, want %s with %q", err, tc.code, tc.message)
			}
			if response == nil || response.Code != -1 {
				t.Errorf("response = %v, want rejection", response)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != "collections" || entries[0].IsDir() {
				t.Fatalf("request changed managed state: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestStartPreparesOCIRootfsWhenOCIImageVolumesAreDisabled(t *testing.T) {
	service := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	service.config.DisableOCIImageMounts = true
	images := newFSTestImageService()
	service.fsMgr = newFSManager(images)
	request := fsTestStartRequest("sbox-image-rootfs")
	request.Mounts = nil

	// The fixture has no resource managers. It mounts the rootfs, then rolls
	// it back when the separate resource preparation fails.
	_, err := service.Start(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "allocate resource") {
		t.Fatalf("error = %v, want resource allocation failure", err)
	}
	image := request.Rootfs.GetImageUrl()
	if mounted, unmounted := images.mountCalls(image), images.umountCalls(image); mounted != 1 || unmounted != 1 {
		t.Fatalf("OCI rootfs calls = %d mounts, %d unmounts, want one each", mounted, unmounted)
	}
}
