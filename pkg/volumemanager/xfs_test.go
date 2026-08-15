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

package volumemanager

import "testing"

func TestParseMountedFilesystemFindsLoopSource(t *testing.T) {
	data := []byte("91 80 7:12 / /var/lib/sandboxd/filestore rw,relatime - ext4 /dev/loop12 rw,discard\n")
	info := parseMountedFilesystem(data, "/var/lib/sandboxd/filestore")
	if info.fsType != "ext4" || info.source != "/dev/loop12" {
		t.Fatalf("mount info = %+v", info)
	}
}

func TestParseMountedFilesystemUnescapesMountpoint(t *testing.T) {
	data := []byte("91 80 7:12 / /path\\040with\\040spaces rw - xfs /dev/loop9 rw\n")
	info := parseMountedFilesystem(data, "/path with spaces")
	if info.fsType != "xfs" || info.source != "/dev/loop9" {
		t.Fatalf("mount info = %+v", info)
	}
}
