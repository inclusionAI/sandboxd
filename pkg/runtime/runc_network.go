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
	"fmt"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
)

// runcNetworkNamespace validates the attachment prepared by NetworkManager.
// Runc deliberately does not create, move, recycle, or delete links here: the
// component that allocates the IP and veth owns their complete lifecycle.
func runcNetworkNamespace(resource *networkmanager.NetResource) (string, error) {
	if resource == nil || resource.Interface == nil || resource.Interface.Name == "" {
		return "", fmt.Errorf("runc network interface is missing")
	}
	if resource.Lifecycle != networkmanager.InterfaceLifecycleEphemeral {
		return "", fmt.Errorf("runc requires an ephemeral network attachment")
	}
	path := filepath.Clean(resource.NetNSPath)
	if err := networkmanager.ValidateEphemeralNetNSPath(path); err != nil {
		return "", fmt.Errorf("invalid runc network namespace: %w", err)
	}
	return path, nil
}
