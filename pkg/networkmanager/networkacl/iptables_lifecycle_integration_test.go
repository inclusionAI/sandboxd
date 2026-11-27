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
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

type lifecycleFaultStore struct {
	store.DbStore
	fail atomic.Bool
}

func (s *lifecycleFaultStore) StoreRaw(key string, value []byte) error {
	if s.fail.Swap(false) {
		return errors.New("injected final metadata write")
	}
	return s.DbStore.StoreRaw(key, value)
}

func TestIntegrationIPTablesLifecycleRestartAndOrphanRecovery(t *testing.T) {
	// The Make target runs this in a private container network namespace.
	names := []string{"acllife0", "acllife1"}
	for _, name := range names {
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
		require.NoError(t, netlink.LinkAdd(link))
		t.Cleanup(func() {
			if link, err := netlink.LinkByName(name); err == nil {
				_ = netlink.LinkDel(link)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "metadata.db")
	db, err := store.Open(path)
	require.NoError(t, err)
	wrapped := &lifecycleFaultStore{DbStore: db}
	config := Config{BridgeIP: net.ParseIP("10.88.0.1"), Store: wrapped, Backend: aclBackendIPTables, DisableProxy: true}
	m, err := New(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if m != nil {
			_ = m.Close()
		}
		if db != nil {
			_ = db.Close()
		}
	})
	bindings := map[string]Binding{"one": {SandboxID: "one", IP: net.ParseIP("10.88.0.2"), HostVeth: names[0]}, "peer": {SandboxID: "peer", IP: net.ParseIP("10.88.0.3"), HostVeth: names[1]}}
	for _, b := range bindings {
		require.NoError(t, m.Register(b, Policy{}))
	}
	require.NoError(t, m.SetPolicy("one", Policy{Traffic: &TrafficPolicy{DefaultAction: actionDeny}}))
	require.False(t, m.entries["one"].KernelPolicyAbsent)
	// Close/reopen keeps active rules and reloads both the shared database and
	// never-installed marker. Restore must preserve peer ownership.
	require.NoError(t, m.Close())
	require.NoError(t, db.Close())
	db, err = store.Open(path)
	require.NoError(t, err)
	wrapped.DbStore = db
	m, err = New(config)
	require.NoError(t, err)
	require.NoError(t, m.Restore(bindings))
	m.iptables.deleteConntrackForIP = func(ip net.IP) error {
		if err := deleteConntrackEndpoints([]net.IP{ip}); err != nil {
			return err
		}
		wrapped.fail.Store(true)
		return nil
	}
	require.ErrorContains(t, m.Remove("one"), "injected final metadata write")
	require.True(t, m.entries["one"].Orphaned)
	require.NoError(t, m.Close())
	require.NoError(t, db.Close())
	db, err = store.Open(path)
	require.NoError(t, err)
	wrapped.DbStore = db
	m, err = New(config)
	require.NoError(t, err)
	require.NoError(t, m.Restore(map[string]Binding{"peer": bindings["peer"]}))
	require.NotContains(t, m.entries, "one")
	require.Contains(t, m.entries, "peer")
	require.NoError(t, m.Register(bindings["one"], Policy{}))
	done := make(chan error, 2)
	go func() { done <- m.Remove("one") }()
	go func() { done <- m.Remove("peer") }()
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	require.Empty(t, m.entries)
	require.NoError(t, m.Close())
	require.NoError(t, db.Close())
}
