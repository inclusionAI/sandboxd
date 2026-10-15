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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareKataConsoleSpecPersistsGuestPTYMount(t *testing.T) {
	bundle := t.TempDir()
	spec := &runtimecore.Spec{Mounts: []runtimecore.Mount{{Destination: "/dev", Type: "tmpfs", Source: "tmpfs"}}}
	require.NoError(t, writeKataSpec(filepath.Join(bundle, "config.json"), spec))
	require.NoError(t, prepareKataConsoleSpec(bundle, spec))
	require.NoError(t, prepareKataConsoleSpec(bundle, spec))
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	require.NoError(t, err)
	var actual runtimecore.Spec
	require.NoError(t, json.Unmarshal(data, &actual))
	require.Len(t, actual.Mounts, 2)
	assert.Equal(t, "/dev/pts", actual.Mounts[1].Destination)
	assert.Equal(t, "devpts", actual.Mounts[1].Type)
	assert.Contains(t, actual.Mounts[1].Options, "newinstance")
	assert.Contains(t, actual.Mounts[1].Options, "ptmxmode=0666")
}

func TestPrepareKataConsoleSpecPreservesCustomDevpts(t *testing.T) {
	bundle := t.TempDir()
	spec := &runtimecore.Spec{Mounts: []runtimecore.Mount{{Destination: "/dev/pts/", Type: "devpts", Source: "devpts", Options: []string{"newinstance", "ptmxmode=0660"}}}}
	require.NoError(t, writeKataSpec(filepath.Join(bundle, "config.json"), spec))
	original, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	require.NoError(t, err)
	require.NoError(t, prepareKataConsoleSpec(bundle, spec))
	actual, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	require.NoError(t, err)
	assert.Equal(t, original, actual)
}

func TestPrepareKataConsoleSpecRejectsConflictingMount(t *testing.T) {
	bundle := t.TempDir()
	spec := &runtimecore.Spec{Mounts: []runtimecore.Mount{{Destination: "/dev/pts", Type: "bind", Source: "/host/pts"}}}
	require.NoError(t, writeKataSpec(filepath.Join(bundle, "config.json"), spec))
	require.ErrorContains(t, prepareKataConsoleSpec(bundle, spec), "incompatible type")
}
