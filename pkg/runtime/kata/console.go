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

package kata

import (
	"fmt"
	"path/filepath"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// prepareKataConsoleSpec provides the guest's PTY filesystem. Kata consumes the
// serialized bundle, so updating only the in-memory OCI spec is insufficient.
func prepareKataConsoleSpec(bundlePath string, spec *runtimecore.Spec) error {
	for _, mount := range spec.Mounts {
		if filepath.Clean(mount.Destination) != "/dev/pts" {
			continue
		}
		if mount.Type != "devpts" {
			return fmt.Errorf("Kata /dev/pts mount has incompatible type %q", mount.Type)
		}
		return nil
	}
	spec.Mounts = append(spec.Mounts, runtimecore.Mount{
		Destination: "/dev/pts", Type: "devpts", Source: "devpts",
		Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"},
	})
	return writeKataSpec(filepath.Join(bundlePath, "config.json"), spec)
}
