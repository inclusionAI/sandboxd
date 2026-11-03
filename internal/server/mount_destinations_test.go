// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package server

import (
	"context"
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
