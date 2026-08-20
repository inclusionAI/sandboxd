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

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloneRuncStartConfigDoesNotMutateRequest(t *testing.T) {
	original := StartConfig{Mounts: []*runtimeapi.Mount{{
		Target:  "/data",
		Type:    "erofs",
		Options: []string{"ro"},
		Source:  &runtimeapi.Mount_HostPath{HostPath: "/image"},
	}}}
	cloned := cloneRuncStartConfig(original)
	cloned.Mounts[0].Type = "bind"
	cloned.Mounts[0].Options[0] = "rbind"
	assert.Equal(t, "erofs", original.Mounts[0].Type)
	assert.Equal(t, []string{"ro"}, original.Mounts[0].Options)
}

func TestPrepareRuncMountsNormalizesEROFS(t *testing.T) {
	bundle := t.TempDir()
	image := filepath.Join(t.TempDir(), "data.erofs")
	require.NoError(t, os.WriteFile(image, []byte("image"), 0644))
	config := StartConfig{Mounts: []*runtimeapi.Mount{{
		Target: "/data",
		Type:   "erofs",
		Source: &runtimeapi.Mount_HostPath{HostPath: image},
	}}}
	var mountedSource, mountedTarget string
	originalUnmount := unmountRuncPath
	t.Cleanup(func() { unmountRuncPath = originalUnmount })
	var unmountedTarget string
	unmountRuncPath = func(target string) error {
		unmountedTarget = target
		return nil
	}

	cleanup, err := prepareRuncMounts(bundle, &config, func(source, target string) error {
		mountedSource, mountedTarget = source, target
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, image, mountedSource)
	assert.Equal(t, mountedTarget, config.Mounts[0].GetHostPath())
	assert.Equal(t, "bind", config.Mounts[0].Type)
	assert.ElementsMatch(t, []string{"ro", "rbind"}, config.Mounts[0].Options)
	require.NoError(t, cleanup())
	assert.Equal(t, mountedTarget, unmountedTarget)
}

func TestPrepareRuncMountsRejectsWritableEROFS(t *testing.T) {
	config := StartConfig{Mounts: []*runtimeapi.Mount{{
		Target:  "/data",
		Type:    "erofs",
		Options: []string{"rw"},
		Source:  &runtimeapi.Mount_HostPath{HostPath: t.TempDir()},
	}}}
	_, err := prepareRuncMounts(t.TempDir(), &config, func(string, string) error { return nil })
	assert.ErrorContains(t, err, "cannot be writable")
}

func TestEscapeOverlayPath(t *testing.T) {
	assert.Equal(t, `/path\:with\,parts\\tail`, escapeOverlayPath(`/path:with,parts\tail`))
}
