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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetNetworkNamespaceReusesExistingEntry(t *testing.T) {
	linux := &Linux{Namespaces: []LinuxNamespace{
		{Type: PIDNamespace},
		{Type: NetworkNamespace},
	}}
	setNetworkNamespace(linux, "/var/run/netns/sbox-test")
	require.Len(t, linux.Namespaces, 2)
	assert.Equal(t, "/var/run/netns/sbox-test", linux.Namespaces[1].Path)
}

func TestSetNetworkNamespaceAddsMissingEntry(t *testing.T) {
	linux := &Linux{Namespaces: []LinuxNamespace{{Type: PIDNamespace}}}
	setNetworkNamespace(linux, "/var/run/netns/sbox-test")
	require.Len(t, linux.Namespaces, 2)
	assert.Equal(t, NetworkNamespace, linux.Namespaces[1].Type)
}

func TestEnsureRuncConsoleMount(t *testing.T) {
	spec := &Spec{}
	require.NoError(t, ensureRuncConsoleMount(spec))
	require.Len(t, spec.Mounts, 1)
	assert.Equal(t, "/dev/pts", spec.Mounts[0].Destination)
	assert.Equal(t, "devpts", spec.Mounts[0].Type)
	assert.Equal(t, "devpts", spec.Mounts[0].Source)
	assert.Contains(t, spec.Mounts[0].Options, "newinstance")
	assert.Contains(t, spec.Mounts[0].Options, "ptmxmode=0666")

	require.NoError(t, ensureRuncConsoleMount(spec))
	assert.Len(t, spec.Mounts, 1)
}

func TestEnsureRuncConsoleMountRejectsConflict(t *testing.T) {
	spec := &Spec{Mounts: []Mount{{
		Destination: "/dev/pts",
		Type:        "bind",
		Source:      "/host/devpts",
	}}}
	err := ensureRuncConsoleMount(spec)
	assert.ErrorContains(t, err, "incompatible type")
}
