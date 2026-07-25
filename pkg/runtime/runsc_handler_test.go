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
	"os"
	"path/filepath"
	"testing"

	cg "github.com/containerd/cgroups/v3/cgroup1"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/cgroupops"
	runscapi "github.com/inclusionAI/sandboxd/pkg/runtime/runsc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
)

func TestNewRunscHandlerUsesSharedLogFile(t *testing.T) {
	baseDir := t.TempDir()
	rootDir := filepath.Join(baseDir, "sandboxd", "root")
	handler, err := NewRunscHandler(config.Config{RootDir: rootDir}, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client, ok := handler.runsc.(*runscapi.Client)
	if !ok {
		t.Fatalf("runsc client has unexpected type %T", handler.runsc)
	}
	assert.Equal(t, filepath.Join(baseDir, "logs", config.RuntimeNameRunsc, "runsc.log"), client.Options.DebugLogPath)
}

var CpuShares uint64 = 128
var CpuPeriod uint64 = 10000
var CpuQuota int64 = 8000
var CpusetCpus string = "0"
var CpusetMems string = "0"
var MemoryLimit int64 = 268435456

func Test_UpdateCgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Requires root to create cgroups")
	}
	const cgroupPath = "test-update-cgroup-for-runsc"
	// resource is nil, do nothing, just return OK
	err := updateCgroup(cgroupPath, nil)
	assert.NoError(t, err)

	cgroupHandler := &cgroupops.CgroupHandlerImpl{}
	cgroup, err := cgroupHandler.Create(cg.StaticPath(cgroupPath), &specs.LinuxResources{}, cg.WithHiearchy(cg.Default))
	assert.NoError(t, err)

	defer func() {
		cgroup.Delete()
	}()

	resource := runtime.LinuxSandboxResources{
		CpuShares:          CpuShares,
		CpuPeriod:          CpuPeriod,
		CpuQuota:           CpuQuota,
		CpusetCpus:         CpusetCpus,
		CpusetMems:         CpusetMems,
		MemoryLimitInBytes: MemoryLimit,
	}

	err = updateCgroup(cgroupPath, &resource)
	assert.NoError(t, err)

}
