// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package networkacl

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRestoreRetainingCancelsManagerLockWait(t *testing.T) {
	m := &Manager{}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := m.RestoreRetainingContext(ctx, nil, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, m.operations, "cancelled recovery must not begin reconciliation")
	require.True(t, m.lifecycleMu.TryRLock(), "cancelled writer must leave no queued wait")
	m.lifecycleMu.RUnlock()
}
