// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package cgroupmanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkloadsEmptyRequiresReadableUnpopulatedCgroups(t *testing.T) {
	mount := t.TempDir()
	c := &CgroupManager{ops: &cgroupV2{mountpoint: mount}, rootName: "/sandbox"}
	const sibling = "/checkpoint"
	writeEvents := func(group, data string) {
		t.Helper()
		dir := filepath.Join(mount, group)
		require.NoError(t, os.MkdirAll(dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cgroup.events"), []byte(data), 0600))
	}
	empty, err := c.WorkloadsEmpty(sibling)
	require.Error(t, err)
	require.False(t, empty)
	writeEvents(c.rootName, "populated 1\n")
	empty, err = c.WorkloadsEmpty(sibling)
	require.NoError(t, err)
	require.False(t, empty)
	writeEvents(c.rootName, "populated 0\n")
	empty, err = c.WorkloadsEmpty(sibling)
	require.NoError(t, err)
	require.True(t, empty)
	writeEvents(sibling, "frozen 0\n")
	empty, err = c.WorkloadsEmpty(sibling)
	require.Error(t, err)
	require.False(t, empty)
	writeEvents(sibling, "populated 1\n")
	empty, err = c.WorkloadsEmpty(sibling)
	require.NoError(t, err)
	require.False(t, empty)
	writeEvents(sibling, "populated 0\n")
	empty, err = c.WorkloadsEmpty(sibling)
	require.NoError(t, err)
	require.True(t, empty)
}
