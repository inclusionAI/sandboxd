//go:build linux && networkacl_integration

// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"sync"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

type aclRecordGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *aclRecordGate) unblock() { g.once.Do(func() { close(g.release) }) }

func (g *aclRecordGate) wait(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("ACL operation did not reach its durable write")
	}
}

type blockedACLRecords struct {
	*store.BboltStoreImp
	mu    sync.Mutex
	gates map[string]*aclRecordGate
}

func (s *blockedACLRecords) block(t *testing.T, id string) *aclRecordGate {
	t.Helper()
	g := &aclRecordGate{entered: make(chan struct{}), release: make(chan struct{})}
	s.mu.Lock()
	s.gates[id] = g
	s.mu.Unlock()
	t.Cleanup(g.unblock)
	return g
}

func (s *blockedACLRecords) StoreRecords(bucket string, records map[string][]byte) error {
	// Pause only the next per-endpoint write, outside the bbolt transaction.
	// These fixtures retain multiple records during recovery, so whole-table
	// commits bypass the operation gates.
	if bucket == "networkACLEntries.v1" && len(records) == 1 {
		for id := range records {
			s.mu.Lock()
			g := s.gates[id]
			delete(s.gates, id)
			s.mu.Unlock()
			if g != nil {
				close(g.entered)
				<-g.release
			}
		}
	}
	return s.BboltStoreImp.StoreRecords(bucket, records)
}

func newACLLockFixture(t *testing.T, backend string) (*aclStartFixture, *blockedACLRecords) {
	t.Helper()
	var records *blockedACLRecords
	f := newACLStartFixtureWithStore(t, backend, func(db *store.BboltStoreImp) store.DbStore {
		records = &blockedACLRecords{BboltStoreImp: db, gates: make(map[string]*aclRecordGate)}
		return records
	})
	return f, records
}

func startPublishedACLSandbox(t *testing.T, f *aclStartFixture, id string) {
	t.Helper()
	call, done := f.start(t, id, config.RuntimeNameKata)
	call.finish <- nil
	require.NoError(t, <-done)
}

func runACLOperation(f *aclStartFixture, id, operation string) <-chan error {
	done := make(chan error, 1)
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		if operation == "remove" {
			done <- f.service.deleteSandbox(f.ctx, id)
			return
		}
		_, err := f.service.SetNetworkPolicy(f.ctx, &runtime.SetNetworkPolicyRequest{SandboxID: id})
		done <- err
	}()
	return done
}

func TestIntegrationACLRecoveryManagerDeadline(t *testing.T) {
	for _, backend := range []string{config.NatBackendIptables, config.NatBackendBpfnat} {
		t.Run(backend, func(t *testing.T) {
			f, records := newACLLockFixture(t, backend)
			const healthy = "sbox-lock-healthy"
			const registering = "sbox-lock-registering"
			startPublishedACLSandbox(t, f, healthy)
			g := records.block(t, registering)
			started := f.launch(t, registering, config.RuntimeNameKata)
			g.wait(t) // Register holds the manager's lifecycle read lock here.
			_, err := f.service.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, 50*time.Millisecond)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			updated := runACLOperation(f, healthy, "policy")
			select {
			case err := <-updated:
				require.NoError(t, err)
			case <-time.After(2 * time.Second):
				t.Fatal("expired recovery still blocked a healthy policy update behind the in-flight registration")
			}
			require.True(t, f.service.runscACLRecoveryPending.Load())
			require.Empty(t, f.restored, "expired lock wait must not reconcile ACL state")
			g.unblock()
			select {
			case call := <-f.handler.started:
				require.Equal(t, registering, call.config.ID)
				call.finish <- nil
			case <-time.After(5 * time.Second):
				t.Fatal("registration did not continue")
			}
			require.NoError(t, <-started)
			_, err = f.service.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, time.Second)
			require.NoError(t, err)
			require.False(t, f.service.runscACLRecoveryPending.Load())
		})
	}
}

func TestIntegrationACLRecoveryDuringPolicyAndRemoval(t *testing.T) {
	for _, backend := range []string{config.NatBackendIptables, config.NatBackendBpfnat} {
		for _, operation := range []string{"policy", "remove"} {
			t.Run(backend+"/"+operation, func(t *testing.T) {
				f, records := newACLLockFixture(t, backend)
				ids := []string{"sbox-lock-a", "sbox-lock-b", "sbox-lock-c"}
				for _, id := range ids {
					startPublishedACLSandbox(t, f, id)
				}
				// Keep recovery's whole-table write distinct from C's per-entry
				// write even after A and B have been completely removed.
				startPublishedACLSandbox(t, f, "sbox-lock-retained")
				first := records.block(t, ids[0])
				second := records.block(t, ids[1])
				later := records.block(t, ids[2])
				a := runACLOperation(f, ids[0], operation)
				first.wait(t)
				b := runACLOperation(f, ids[1], operation)
				second.wait(t)
				recovered := make(chan error, 1)
				f.wg.Add(1)
				go func() {
					defer f.wg.Done()
					_, err := f.service.sandboxManager.RuntimeInventory(config.RuntimeNameRunsc, 5*time.Second)
					recovered <- err
				}()
				// Both older operations still hold readers, so a failed probe proves
				// recovery has queued ahead of later readers, not acquired the lock.
				require.Eventually(t, func() bool {
					if f.service.aclRecoveryMu.TryRLock() {
						f.service.aclRecoveryMu.RUnlock()
						return false
					}
					return true
				}, 500*time.Millisecond, time.Millisecond, "recovery must queue ahead of new ACL operations")
				c := runACLOperation(f, ids[2], operation)
				first.unblock()
				require.NoError(t, <-a)
				select {
				case <-later.entered:
					t.Fatal("later ACL operation passed recovery while an older operation was still running")
				default:
				}
				second.unblock()
				require.NoError(t, <-b)
				require.NoError(t, <-recovered)
				later.wait(t)
				require.False(t, f.service.runscACLRecoveryPending.Load(), "recovery must precede the later operation")
				later.unblock()
				require.NoError(t, <-c)
			})
		}
	}
}
