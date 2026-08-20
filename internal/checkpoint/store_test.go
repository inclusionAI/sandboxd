// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkpoint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanupStagingRemovesNestedStagingDirectory(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "tenant-a", "function-a")
	staging := filepath.Join(nested, ".snapshot.staging-123")
	committed := filepath.Join(nested, "snapshot")
	require.NoError(t, os.MkdirAll(staging, 0700))
	require.NoError(t, os.MkdirAll(committed, 0700))

	require.NoError(t, CleanupStaging(root))

	require.NoDirExists(t, staging)
	require.DirExists(t, committed)
}

func TestCleanupStagingDoesNotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	marker := filepath.Join(external, "marker")
	require.NoError(t, os.WriteFile(marker, []byte("keep"), 0600))
	symlink := filepath.Join(root, ".snapshot.staging-symlink")
	require.NoError(t, os.Symlink(external, symlink))

	require.NoError(t, CleanupStaging(root))

	require.FileExists(t, marker)
	info, err := os.Lstat(symlink)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
}

func TestCleanupStagingPreservesUnrelatedHiddenDirectories(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".staging-123", ".snapshot.staging-", "snapshot.staging-123", ".snapshot.deleting-123"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, name), 0700))
	}

	require.NoError(t, CleanupStaging(root))

	for _, name := range []string{".staging-123", ".snapshot.staging-", "snapshot.staging-123", ".snapshot.deleting-123"} {
		require.DirExists(t, filepath.Join(root, name))
	}
}

func TestCleanupStagingAcceptsMissingRoot(t *testing.T) {
	require.NoError(t, CleanupStaging(filepath.Join(t.TempDir(), "missing")))
}
