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

package cgroupmanager

import (
	"errors"
	sysos "os"
	"sync/atomic"
	"testing"

	gomonkey "github.com/agiledragon/gomonkey/v2"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/cgroupops"
	"github.com/inclusionAI/sandboxd/internal/util"
	cg "github.com/containerd/cgroups/v3/cgroup1"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
)

type FakeCgroupHandler struct {
	root      string
	resources *spec.LinuxResources
}

func (f *FakeCgroupHandler) Create(path cg.Path, resources *spec.LinuxResources, opts ...cg.InitOpts) (cg.Cgroup, error) {
	f.resources = resources
	return &MockCgroup{}, nil
}

func (f *FakeCgroupHandler) Load(path cg.Path, opts ...cg.InitOpts) (cg.Cgroup, error) {
	return &MockCgroup{}, nil
}

var _ cgroupops.CgroupHandler = &FakeCgroupHandler{}

func TestCgroupRecycle(t *testing.T) {
	cgroupManager := &CgroupManager{
		max:                  10,
		rootName:             "sandbox",
		usingID:              cmap.New[struct{}](),
		idleID:               util.New[string](""),
		cgroups:              cmap.New[struct{}](),
		generator:            nil,
		enableDestroyRecycle: false,
		storeMark:            atomic.Bool{},
		gcQueue:              util.New[string](""),
	}

	cgroupManager.cgroups.Set("/sandbox/1", struct{}{})
	cgroupManager.cgroups.Set("/sandbox/2", struct{}{})
	cgroupManager.cgroups.Set("/sandbox/3", struct{}{})

	cgroupManager.usingID.Set("/sandbox/1", struct{}{})
	cgroupManager.usingID.Set("/sandbox/2", struct{}{})

	// Recycle cgroups not in c.cgroups - should ignore and not add to idle
	err := cgroupManager.Recycle("/sandbox/xx1")
	assert.NoError(t, err)
	assert.Equal(t, 2, cgroupManager.usingID.Count())
	assert.Equal(t, 0, cgroupManager.idleID.Length())

	// Recycle cgroups in c.cgroups with reuse mode
	err = cgroupManager.Recycle("/sandbox/1")
	assert.NoError(t, err)
	assert.Equal(t, 1, cgroupManager.usingID.Count())
	assert.Equal(t, 1, cgroupManager.idleID.Length())

	// Test destroy mode
	cgroupManager.usingID.Set("/sandbox/2", struct{}{})
	cgroupManager.enableDestroyRecycle = true
	err = cgroupManager.Recycle("/sandbox/2")
	assert.NoError(t, err)
	assert.Equal(t, 0, cgroupManager.usingID.Count())
	assert.Equal(t, 1, cgroupManager.idleID.Length())
}

func TestSubystemsCpuMemory(t *testing.T) {
	subystemsCpuMemory()
	openFailedPatches := gomonkey.ApplyFunc(sysos.Open, func(name string) (*sysos.File, error) {
		return nil, errors.New("fake destroyDevice error")
	})
	defer openFailedPatches.Reset()
	subystemsCpuMemory()
}

func TestDoCreateSetsPidsMax(t *testing.T) {
	handler := &FakeCgroupHandler{}
	manager := &CgroupManager{
		pidsMax:       4096,
		cgroups:       cmap.New[struct{}](),
		generator:     util.NewFixedLengthIDGenerator(12, nil, util.PrefixID("/sandbox/")),
		storeMark:     atomic.Bool{},
		cgroupHandler: handler,
	}

	id, err := manager.doCreate()
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
	if assert.NotNil(t, handler.resources) && assert.NotNil(t, handler.resources.Pids) {
		assert.Equal(t, int64(4096), handler.resources.Pids.Limit)
	}
}

func TestCgroupResourcesDefaultsToUnlimitedPids(t *testing.T) {
	manager := &CgroupManager{}
	assert.Nil(t, manager.cgroupResources().Pids)
}

func TestNewCgroupManagerRejectsNegativePidsMax(t *testing.T) {
	_, err := NewCgroupManager(nil, config.ResourceConfig{PidsMax: -1}, 1)
	assert.EqualError(t, err, "pids_max must be non-negative")
}
