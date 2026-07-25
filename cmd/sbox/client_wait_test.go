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

package main

import (
	"context"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc"
)

type deadlineCapturingClient struct {
	runtime.SandboxServiceClient
	hasDeadline bool
}

func (c *deadlineCapturingClient) Wait(ctx context.Context, _ *runtime.WaitRequest, _ ...grpc.CallOption) (*runtime.WaitResponse, error) {
	_, c.hasDeadline = ctx.Deadline()
	return &runtime.WaitResponse{}, nil
}

func TestWaitSandboxPreservesUnboundedDefault(t *testing.T) {
	fake := &deadlineCapturingClient{}
	client := &SandboxClient{client: fake, timeout: 10 * time.Millisecond}
	if _, err := client.WaitSandbox(&runtime.WaitRequest{ID: "sbox-test"}); err != nil {
		t.Fatal(err)
	}
	if fake.hasDeadline {
		t.Fatal("default WaitSandbox unexpectedly installed a deadline")
	}
}

func TestWaitSandboxWithTimeoutInstallsDeadline(t *testing.T) {
	fake := &deadlineCapturingClient{}
	client := &SandboxClient{client: fake, timeout: time.Second}
	if _, err := client.WaitSandboxWithTimeout(&runtime.WaitRequest{ID: "sbox-test"}); err != nil {
		t.Fatal(err)
	}
	if !fake.hasDeadline {
		t.Fatal("WaitSandboxWithTimeout did not install a deadline")
	}
}
