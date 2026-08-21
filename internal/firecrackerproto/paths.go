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

package firecrackerproto

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

const (
	HostRuntimeRoot     = "/run/sandboxd/firecracker"
	HostAgentSocketName = "agent.vsock"
)

// HostRuntimeDirectory returns a bounded stable directory for host-side
// Firecracker sockets. Hashing keeps valid long sandbox IDs below sockaddr_un's
// path limit while each state file retains the original ID for recovery.
func HostRuntimeDirectory(root, sandboxID string) string {
	sum := sha256.Sum256([]byte(sandboxID))
	return filepath.Join(root, fmt.Sprintf("%x", sum[:12]))
}

func HostAgentSocket(root, sandboxID string) string {
	return filepath.Join(
		HostRuntimeDirectory(root, sandboxID),
		HostAgentSocketName,
	)
}
