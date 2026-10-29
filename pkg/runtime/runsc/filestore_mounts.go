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

package runsc

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/util"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

const filestoreCheckpointAnnotation = "sandbox.akernel.dev/filestore-checkpoint"
const filestoreCheckpointFormat = "reflink-v1"

type fileBackedTmpfsMount struct {
	Target string `json:"target"`
	SizeMB uint64 `json:"sizeMB"`
}

type runscStorageConfig struct {
	FileBackedTmpfsMounts []fileBackedTmpfsMount `json:"fileBackedTmpfsMounts"`
}

// The per-sandbox marker survives a sandboxd restart and does not change the
// checkpoint behavior of unrelated sandboxes when the node default is full.
func (c *Client) useReflinkCheckpoint(id string) (bool, error) {
	if c.Options.ReflinkFilestores {
		return true, nil
	}
	data, err := os.ReadFile(c.stateFilePath(id))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var state struct {
		Spec struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return false, fmt.Errorf("read filestore checkpoint mode: %w", err)
	}
	return state.Spec.Annotations[filestoreCheckpointAnnotation] == filestoreCheckpointFormat, nil
}

// prepareFileBackedTmpfs reserves each mount's quota from the sandbox storage
// budget. The host source is only an empty mount identity; guest file bytes live
// in an anonymous filestore in the configured node filestore directory.
func (r *Handler) prepareFileBackedTmpfs(config runtimecore.StartConfig) (runtimecore.StartConfig, bool, error) {
	var storage runscStorageConfig
	if strings.TrimSpace(config.ExtraConfig) != "" {
		if err := json.Unmarshal([]byte(config.ExtraConfig), &storage); err != nil {
			return config, false, fmt.Errorf("decode runsc storage config: %w", err)
		}
	}
	config.Annotations = maps.Clone(config.Annotations)
	delete(config.Annotations, filestoreCheckpointAnnotation)
	if len(storage.FileBackedTmpfsMounts) == 0 {
		return config, false, nil
	}
	if len(storage.FileBackedTmpfsMounts) > 16 {
		return config, false, fmt.Errorf("at most 16 file-backed tmpfs mounts are supported")
	}
	remaining := config.WritableLayerLimitBytes
	targets := []string{"/dev", "/proc", "/sys", "/run", "/tmp"}
	for _, mount := range config.Mounts {
		targets = append(targets, mount.GetTarget())
	}
	for _, mount := range storage.FileBackedTmpfsMounts {
		if !filepath.IsAbs(mount.Target) || filepath.Clean(mount.Target) != mount.Target || mount.Target == "/" {
			return config, false, fmt.Errorf("invalid file-backed tmpfs target %q", mount.Target)
		}
		for _, target := range targets {
			if target == "" {
				continue
			}
			a, b := strings.TrimSuffix(mount.Target, "/")+"/", strings.TrimSuffix(filepath.Clean(target), "/")+"/"
			if strings.HasPrefix(a, b) || strings.HasPrefix(b, a) {
				return config, false, fmt.Errorf("file-backed tmpfs target %q overlaps %q", mount.Target, target)
			}
		}
		targets = append(targets, mount.Target)
		if mount.SizeMB == 0 || mount.SizeMB > (^uint64(0)>>20) || mount.SizeMB<<20 >= remaining {
			return config, false, fmt.Errorf("file-backed tmpfs quota must be positive and leave storage for the root filesystem")
		}
		remaining -= mount.SizeMB << 20
	}
	bundle, err := util.JoinWithinRoot(r.sandboxRoot, config.ID)
	if err != nil {
		return config, false, err
	}
	config.Mounts = append([]*runtimeapi.Mount(nil), config.Mounts...)
	if config.Annotations == nil {
		config.Annotations = map[string]string{}
	}
	for index, mount := range storage.FileBackedTmpfsMounts {
		source := filepath.Join(bundle, "filestore-mounts", strconv.Itoa(index))
		if err := os.MkdirAll(source, 0700); err != nil {
			return config, false, err
		}
		config.Mounts = append(config.Mounts, &runtimeapi.Mount{Source: &runtimeapi.Mount_HostPath{HostPath: source}, Target: mount.Target, Type: "bind", Options: []string{"rbind", "rw"}})
		prefix := "dev.gvisor.spec.mount.akernel-filestore-" + strconv.Itoa(index) + "."
		for key, value := range map[string]string{"source": source, "type": "tmpfs", "share": "container", "filestore": "anonymous", "options": "rw,size=" + strconv.FormatUint(mount.SizeMB<<20, 10)} {
			config.Annotations[prefix+key] = value
		}
	}
	config.WritableLayerLimitBytes = remaining
	config.Annotations[filestoreCheckpointAnnotation] = filestoreCheckpointFormat
	return config, true, nil
}
