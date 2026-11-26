//go:build linux && networkacl_integration

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

package networkacl

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A rejected final activation transaction must leave both dispatchers blocked,
// the IPv6 drops installed and the kernel unaware of either generation chain.
func TestIntegrationIPTablesBatchActivationFailure(t *testing.T) {
	b, err := newIPTablesBackend(net.ParseIP("10.88.0.1"))
	require.NoError(t, err)
	require.NotNil(t, b.batch)
	entry := persistedEntry{IP: "10.88.0.213", HostVeth: "aclbatch213", Generation: 1, Policy: Policy{Traffic: &TrafficPolicy{DefaultAction: actionDeny}}}
	ip := net.ParseIP(entry.IP).To4()
	se, si, ge, gi := iptablesChainNames(ip, 1)
	restore := b.batch.v4.restore
	t.Setenv("ACL_TEST_REAL_RESTORE", restore)
	// Append an invalid command to the transaction immediately before COMMIT.
	tmp := t.TempDir()
	b.batch.v4.restore = filepath.Join(tmp, "restore")
	require.NoError(t, os.WriteFile(b.batch.v4.restore, []byte(`#!/bin/sh
awk '/^-N SD-G-/{fault=1} fault && /^COMMIT$/{print "-A missing-acl-chain -j DROP"} {print}' | "$ACL_TEST_REAL_RESTORE" "$@"
`), 0700))
	require.Error(t, b.apply(persistedEntry{}, entry))
	b.batch.v4.restore = restore
	for _, chain := range []string{se, si} {
		ok, err := b.stableIsCanonical(chain, dropBarrierChain)
		require.NoError(t, err)
		require.True(t, ok)
	}
	for _, h := range aclIP6TablesHooks(entry.HostVeth) {
		ok, err := b.ipv6Client.Exists(filterTable, h.chain, h.rule...)
		require.NoError(t, err)
		require.True(t, ok)
	}
	for _, chain := range []string{ge, gi} {
		ok, err := b.client.ChainExists(filterTable, chain)
		require.NoError(t, err)
		require.False(t, ok)
	}
	require.NoError(t, b.cleanup(entry))
	require.NoError(t, b.apply(persistedEntry{}, entry))
	ok, err := b.stableIsCanonical(se, ge)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = b.stableIsCanonical(si, gi)
	require.NoError(t, err)
	require.True(t, ok)
	// Loss of one IPv6 hook between cleanup attempts must remain idempotent.
	h := aclIP6TablesHooks(entry.HostVeth)[0]
	require.NoError(t, b.ipv6Client.Delete(filterTable, h.chain, h.rule...))
	require.NoError(t, b.cleanup(entry))
	require.NoError(t, b.cleanup(entry))
	for _, chain := range []string{se, si, ge, gi} {
		ok, err := b.client.ChainExists(filterTable, chain)
		require.NoError(t, err)
		require.False(t, ok)
	}
}
