//go:build linux && networkacl_integration

// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// Exercise real shared kernel tables and the production record store. A private
// network/mount namespace is required by the networkacl-test runner.
func TestConcurrentEndpointLifecycleBackends(t *testing.T) {
	for _, backend := range []string{aclBackendIPTables, aclBackendBPFNAT} {
		t.Run(backend, func(t *testing.T) {
			db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
			require.NoError(t, err)
			defer db.Close()
			m, err := New(Config{Backend: backend, BridgeIP: net.ParseIP("10.89.0.1"), Store: db, DisableProxy: true})
			require.NoError(t, err)
			defer m.Close()
			const count = 8
			bindings := make([]Binding, count)
			for i := range bindings {
				link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("acl-con-%d", i)}}
				require.NoError(t, netlink.LinkAdd(link))
				defer netlink.LinkDel(link)
				require.NoError(t, netlink.LinkSetUp(link))
				bindings[i] = Binding{SandboxID: fmt.Sprint(i), IP: net.ParseIP(fmt.Sprintf("10.89.0.%d", i+2)), HostVeth: link.Attrs().Name}
			}
			var wg sync.WaitGroup
			results := make(chan error, count)
			for _, binding := range bindings {
				wg.Add(1)
				go func(binding Binding) {
					defer wg.Done()
					for round := 0; round < 3; round++ {
						if err := m.Register(binding, Policy{}); err != nil {
							results <- err
							return
						}
						if err := m.SetPolicy(binding.SandboxID, trafficPolicy(actionDeny, policyModeStateful)); err != nil {
							results <- err
							return
						}
						if err := m.SetPolicy(binding.SandboxID, Policy{}); err != nil {
							results <- err
							return
						}
						if err := m.Remove(binding.SandboxID); err != nil {
							results <- err
							return
						}
					}
					results <- nil
				}(binding)
			}
			wg.Wait()
			close(results)
			for err := range results {
				require.NoError(t, err)
			}
			require.NoError(t, m.Restore(map[string]Binding{}))
			records, err := db.LoadRecords(entryStoreKey)
			require.NoError(t, err)
			require.Empty(t, records)
			require.Empty(t, m.entries)
			require.Empty(t, m.sourceIndex)
		})
	}
}
