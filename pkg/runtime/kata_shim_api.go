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
	taskv2 "github.com/containerd/containerd/api/runtime/task/v2"
	containerdtypes "github.com/containerd/containerd/api/types"
)

type shimCreateTaskRequest = taskv2.CreateTaskRequest
type shimCreateTaskResponse = taskv2.CreateTaskResponse
type shimStartRequest = taskv2.StartRequest
type shimStartResponse = taskv2.StartResponse
type shimDeleteRequest = taskv2.DeleteRequest
type shimDeleteResponse = taskv2.DeleteResponse
type shimKillRequest = taskv2.KillRequest
type shimShutdownRequest = taskv2.ShutdownRequest
type shimWaitRequest = taskv2.WaitRequest
type shimWaitResponse = taskv2.WaitResponse
type shimStateRequest = taskv2.StateRequest
type shimStateResponse = taskv2.StateResponse
type shimMount = containerdtypes.Mount
