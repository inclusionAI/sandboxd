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

package checkpoint

const manifestVersion = 1

// Manifest is the durable identity and integrity record published atomically
// with a checkpoint image.
type Manifest struct {
	Version      int    `json:"version"`
	CheckpointID string `json:"checkpointId"`
	SourceID     string `json:"sourceId"`
	Runtime      string `json:"runtime"`
	RootfsSHA256 string `json:"rootfsSha256"`
	LeaveRunning bool   `json:"leaveRunning,omitempty"`
	ImageSHA256  string `json:"imageSha256"`
	ImageSize    int64  `json:"imageSize"`
}

// SourceIdentity describes the logical source whose checkpoint may be
// replayed. It deliberately excludes transient process and node identities.
type SourceIdentity struct {
	CheckpointID string
	SourceID     string
	Runtime      string
	RootfsSHA256 string
	LeaveRunning bool
}

// Paths are the sandboxd-owned paths for a checkpoint fact.
type Paths struct {
	Dir      string
	Image    string
	Manifest string
}

// Fact is a validated, committed checkpoint artifact.
type Fact struct {
	Paths    Paths
	Manifest Manifest
}

func (manifest Manifest) sourceIdentity() SourceIdentity {
	return SourceIdentity{
		CheckpointID: manifest.CheckpointID,
		SourceID:     manifest.SourceID,
		Runtime:      manifest.Runtime,
		RootfsSHA256: manifest.RootfsSHA256,
		LeaveRunning: manifest.LeaveRunning,
	}
}
