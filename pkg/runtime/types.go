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

import "time"

type State struct {
	ID             string        `json:"id"`
	InitProcessPid int           `json:"pid"`
	Status         SandboxStatus `json:"status"`
	Created        string        `json:"created"`
}

type SandboxStatus string

const (
	// SandboxStatusCreated is the status of a container after it has been created.
	SandboxStatusCreated SandboxStatus = "created"
	// SandboxStatusRunning is the status of a container after it has been started.
	SandboxStatusRunning SandboxStatus = "running"
	// SandboxStatusExited is the status of a container after it has exited.
	SandboxStatusExited SandboxStatus = "stopped"
	// SandboxStatusUnknown is the status of a container when its status cannot be determined.
	SandboxStatusUnknown SandboxStatus = "unknown"
)

type Exit struct {
	ExitedAt time.Time
	ExitCode int
}
