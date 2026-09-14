//go:build linux

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

package xpumanager

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatCharacterDevice(t *testing.T) {
	deviceType, major, minor, err := statCharacterDevice("/dev/null")
	require.NoError(t, err)
	require.Equal(t, "c", deviceType)
	require.Equal(t, int64(1), major)
	require.Equal(t, int64(3), minor)
}

func TestStatCharacterDeviceRejectsRegularFile(t *testing.T) {
	_, _, _, err := statCharacterDevice(t.TempDir())
	require.Error(t, err)
}
