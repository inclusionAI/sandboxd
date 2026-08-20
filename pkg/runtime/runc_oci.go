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
)

const runcConsoleMountTarget = "/dev/pts"

// ensureRuncConsoleMount supplies the devpts instance required by OCI console
// sockets. runsc virtualizes this mount itself, while runc expects it to be
// present in the bundle specification before allocating a terminal.
func ensureRuncConsoleMount(spec *Spec) error {
	for _, mount := range spec.Mounts {
		if filepath.Clean(mount.Destination) != runcConsoleMountTarget {
			continue
		}
		if mount.Type != "devpts" {
			return fmt.Errorf(
				"runc console mount %s has incompatible type %q",
				runcConsoleMountTarget,
				mount.Type,
			)
		}
		return nil
	}
	spec.Mounts = append(spec.Mounts, Mount{
		Destination: runcConsoleMountTarget,
		Type:        "devpts",
		Source:      "devpts",
		Options: []string{
			"nosuid",
			"noexec",
			"newinstance",
			"ptmxmode=0666",
			"mode=0620",
			"gid=5",
		},
	})
	return nil
}
