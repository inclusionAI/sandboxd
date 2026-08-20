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

package runcshim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExitRecordRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", ExitFile)
	require.NoError(t, WriteExit(path, ExitRecord{Started: true, ExitCode: 23}))
	record, err := ReadExit(path)
	require.NoError(t, err)
	assert.Equal(t, ExitVersion, record.Version)
	assert.True(t, record.Started)
	assert.Equal(t, 23, record.ExitCode)
	assert.False(t, record.ExitedAt.IsZero())
}

func TestReadExitRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), ExitFile)
	require.NoError(t, os.WriteFile(path, []byte(`{"version":99}`), 0644))
	_, err := ReadExit(path)
	assert.ErrorContains(t, err, "unsupported")
}
