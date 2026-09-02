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

package main

import (
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseXPUAllocationFlags(t *testing.T) {
	allocations, err := parseXPUAllocationFlags([]string{"GPU:0,2"})
	require.NoError(t, err)
	assert.Equal(t, []*runtime.XpuAllocation{{
		Type:      "gpu",
		DeviceIds: []uint32{0, 2},
	}}, allocations)
}

func TestParseXPUAllocationFlagsRejectsInvalidInput(t *testing.T) {
	for _, flag := range []string{
		"gpu",
		"gpu:",
		":0",
		"gpu:0,",
		"gpu:-1",
		"gpu:0,0",
	} {
		t.Run(flag, func(t *testing.T) {
			_, err := parseXPUAllocationFlags([]string{flag})
			require.Error(t, err)
		})
	}
}

func TestParseXPUAllocationFlagsRejectsMultipleAllocations(t *testing.T) {
	_, err := parseXPUAllocationFlags([]string{"gpu:0", "npu:0"})
	require.ErrorContains(t, err, "exactly one")
}

func TestStorageMBToBytes(t *testing.T) {
	got, err := storageMBToBytes(10 * 1024)
	require.NoError(t, err)
	assert.Equal(t, uint64(10<<30), got)

	_, err = storageMBToBytes(^uint64(0))
	require.Error(t, err)
}

func TestStartExtraConfig(t *testing.T) {
	value, err := startExtraConfig("", false)
	require.NoError(t, err)
	assert.Empty(t, value)

	value, err = startExtraConfig("", true)
	require.NoError(t, err)
	assert.JSONEq(t, `{"enableKVM":true}`, value)

	value, err = startExtraConfig(
		`{"nativeWritableMounts":[{"target":"/var/lib/docker"}]}`,
		false,
	)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"nativeWritableMounts":[{"target":"/var/lib/docker"}]}`,
		value,
	)

	value, err = startExtraConfig(
		`{"enableKVM":false,"runtimeOption":"kept"}`,
		true,
	)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"enableKVM":true,"runtimeOption":"kept"}`,
		value,
	)

	for _, invalid := range []string{"null", "[]", "not-json"} {
		_, err = startExtraConfig(invalid, false)
		require.Error(t, err)
	}
}

func TestStartRootfs(t *testing.T) {
	local, err := startRootfs("/rootfs", "", false)
	require.NoError(t, err)
	assert.Equal(t, runtime.RootfsSrcType_LOCAL, local.Type)
	assert.Equal(t, "/rootfs", local.GetPath())

	image, err := startRootfs("", "registry.example/image:tag", true)
	require.NoError(t, err)
	assert.Equal(t, runtime.RootfsSrcType_IMAGE, image.Type)
	assert.Equal(t, "registry.example/image:tag", image.GetImageUrl())
	assert.True(t, image.Readonly)

	_, err = startRootfs("", "", false)
	require.ErrorContains(t, err, "exactly one")
	_, err = startRootfs("/rootfs", "registry.example/image:tag", false)
	require.ErrorContains(t, err, "mutually exclusive")
}
