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
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBPFKeyLayoutsRemainStable(t *testing.T) {
	var policy policyV2Value
	assert.Equal(t, 24, binary.Size(ruleKey{}))
	assert.Equal(t, 24, binary.Size(connectionKey{}))
	assert.Equal(t, 16, binary.Size(connectionValue{}))
	assert.Equal(t, 24, binary.Size(fragmentKey{}))
	assert.Equal(t, 24, binary.Size(policyV2Rule{}))
	assert.Equal(t, 6168, binary.Size(policyV2Value{}))
	assert.Equal(t, 24, binary.Size(domainPolicyRule{}))
	assert.Equal(t, 6152, binary.Size(domainPolicyValue{}))
	assert.Equal(t, uintptr(19), unsafe.Offsetof(policy.UpdateBarrier))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(policy.Rules))
}

func TestCompileBPFPolicyAndDomainGrants(t *testing.T) {
	policy := Policy{
		SchemaVersion: networkPolicySchemaV2,
		Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionDeny,
			Mode:                 policyModeStateful,
			Rules: []TrafficRule{
				{
					Action: actionAllow, Directions: []uint8{directionIngress, directionEgress},
					Protocol: 6, PeerIP: [4]byte{192, 0, 2, 0}, PeerPrefix: 24,
					PeerPortFirst: 443, PeerPortLast: 445, Priority: 300,
				},
				{
					Action: actionAllow, Directions: []uint8{directionEgress}, Protocol: 6,
					PeerDomain: "example.com", PeerPortFirst: 443, PeerPortLast: 443,
					Priority: 200,
				},
			},
		},
	}
	entry := persistedEntry{
		IP: "10.88.0.2", IfIndex: 7, Generation: 3, Policy: policy,
		DomainGrants: []persistedDomainGrant{
			{Question: "example.com", IP: "198.51.100.10", ExpiresAt: time.Now().Add(time.Minute).UnixNano(), RuleIndex: 1},
		},
	}
	compiled, err := compileBPFPolicy(entry)
	require.NoError(t, err)
	assert.Equal(t, ipv4Value(net.ParseIP(entry.IP)), compiled.SandboxIP)
	assert.Equal(t, uint16(1), compiled.RuleCount, "domain rules are materialized only from DNS responses")
	assert.Equal(t, uint8(directionIngress|directionEgress), compiled.Rules[0].Directions)
	assert.Equal(t, uint8(24), compiled.Rules[0].PeerPrefix)
	assert.Equal(t, uint16(443), compiled.Rules[0].PeerPortFirst)
	assert.Equal(t, uint16(445), compiled.Rules[0].PeerPortLast)
	assert.Equal(t, uint8(1), compiled.DNSEnabled)

	domains, err := compileDomainPolicies(entry)
	require.NoError(t, err)
	key := domainPolicyKey{Generation: 3, IfIndex: 7, PeerIP: ipv4Value(net.ParseIP("198.51.100.10"))}
	value, ok := domains[key]
	require.True(t, ok)
	assert.Equal(t, uint16(1), value.RuleCount)
	assert.Equal(t, uint32(200), value.Rules[0].Priority)
	assert.Equal(t, uint16(443), value.Rules[0].PeerPortFirst)
	assert.Greater(t, value.Rules[0].ExpiresAt, uint64(0))
}

func TestCompilePreviousDomainPoliciesRetainsExpiredKeysForCleanup(t *testing.T) {
	wallNow := time.Unix(100, 0)
	entry := persistedEntry{
		IP: "10.88.0.2", IfIndex: 7, Generation: 3,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionDeny,
			EgressDefaultAction:  actionDeny,
			Rules: []TrafficRule{{
				Action: actionAllow, Directions: []uint8{directionEgress},
				Protocol: 6, PeerDomain: "service.example", Priority: defaultRulePriority,
			}},
		}},
		DomainGrants: []persistedDomainGrant{{
			Question: "service.example", IP: "192.0.2.40",
			ExpiresAt: wallNow.Add(-time.Second).UnixNano(), RuleIndex: 0,
		}},
	}
	key := domainPolicyKey{
		Generation: 3, IfIndex: 7, PeerIP: ipv4Value(net.ParseIP("192.0.2.40")),
	}

	previous, err := compileDomainPoliciesAt(entry, wallNow, 500, true)
	require.NoError(t, err)
	require.Contains(t, previous, key)
	assert.Equal(t, uint64(0), previous[key].Rules[0].ExpiresAt)

	next, err := compileDomainPoliciesAt(entry, wallNow, 500, false)
	require.NoError(t, err)
	assert.NotContains(t, next, key)
}

func TestReconcilePersistsCleanupIntentBeforeKernelMutation(t *testing.T) {
	stateStore := &failNthStore{MockStore: store.NewMockStore()}
	entry := persistedEntry{
		IP: "10.88.0.2", HostVeth: "acl-old", IfIndex: 1234,
	}
	manager := &Manager{
		store:       stateStore,
		entries:     map[string]persistedEntry{"old": entry},
		sourceIndex: map[string]string{entry.IP: "old"},
	}
	require.NoError(t, manager.persistLocked())

	// With nil BPF objects any attempted kernel cleanup would panic. Failing the
	// intent write must return before cleanup is reached and leave durable state
	// describing the entry as active.
	stateStore.failAt = stateStore.writes + 1
	err := manager.reconcileOrphansLocked(map[string]persistedEntry{"old": entry})
	require.ErrorContains(t, err, "cleanup intent")

	inMemory := manager.entries["old"]
	assert.False(t, inMemory.Orphaned)
	assert.Equal(t, "old", manager.sourceIndex[entry.IP])

	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	var state persistedState
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.False(t, state.Entries["old"].Orphaned)
}

func TestLoadStateDropsLegacyCleanupFields(t *testing.T) {
	stateStore := store.NewMockStore()
	legacy := []byte(`{"entries":{"old":{"ip":"10.88.0.2","host_veth":"acl-old","ifindex":42,"generation":3,"policy":{},"orphaned":true,"link_mac":"02:00:00:00:00:01","kernel_cleaned":true}}}`)
	require.NoError(t, stateStore.StoreRaw(stateStoreKey, legacy))

	manager := &Manager{store: stateStore, entries: make(map[string]persistedEntry)}
	require.NoError(t, manager.loadState())
	entry, exists := manager.entries["old"]
	require.True(t, exists)
	assert.True(t, entry.Orphaned)
	assert.Equal(t, 42, entry.IfIndex)
	assert.Equal(t, uint64(3), entry.Generation)

	require.NoError(t, manager.persistLocked())
	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "link_mac")
	assert.NotContains(t, string(raw), "kernel_cleaned")
}

func TestCleanupRefusesIfIndexOwnedByActiveSandbox(t *testing.T) {
	orphan := persistedEntry{
		IP: "10.88.0.2", HostVeth: "acl-old", IfIndex: 42, Orphaned: true,
	}
	active := persistedEntry{
		IP: "10.88.0.3", HostVeth: "acl-new", IfIndex: 42,
	}
	manager := &Manager{entries: map[string]persistedEntry{
		"old": orphan,
		"new": active,
	}}

	err := manager.cleanupEntryLocked("old", orphan)
	require.ErrorContains(t, err, "owned by active sandbox new")
}

func TestReconcileRetriesAfterRemovalPersistFailure(t *testing.T) {
	stateStore := &failNthStore{MockStore: store.NewMockStore()}
	entry := persistedEntry{
		IP: "10.88.0.2", HostVeth: "acl-old", Orphaned: true,
	}
	manager := &Manager{
		store:       stateStore,
		entries:     map[string]persistedEntry{"old": entry},
		sourceIndex: map[string]string{entry.IP: "old"},
	}
	require.NoError(t, manager.persistLocked())

	// The cleanup intent is already durable, but removing the cleaned entry from
	// the store fails. The orphan must remain durable and in memory for an
	// idempotent retry. IfIndex zero keeps this unit test independent of kernel
	// BPF state.
	stateStore.failAt = stateStore.writes + 1
	err := manager.reconcileOrphansLocked(map[string]persistedEntry{"old": entry})
	require.ErrorContains(t, err, "removal of cleaned network ACL state")
	retained, exists := manager.entries["old"]
	require.True(t, exists)
	assert.True(t, retained.Orphaned)
	assert.NotContains(t, manager.sourceIndex, entry.IP)

	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	var state persistedState
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.True(t, state.Entries["old"].Orphaned)

	stateStore.failAt = 0
	require.NoError(t, manager.reconcileOrphansLocked(map[string]persistedEntry{"old": retained}))
	assert.NotContains(t, manager.entries, "old")
	raw, err = stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	state = persistedState{}
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.Empty(t, state.Entries)
}

func TestObserveDNSRechecksCurrentDNSPolicyBeforeGranting(t *testing.T) {
	source := net.ParseIP("10.88.0.2")
	manager := &Manager{
		entries: map[string]persistedEntry{
			"sandbox": {
				IP: source.String(), Generation: 2,
				Policy: Policy{
					Traffic: &TrafficPolicy{Rules: []TrafficRule{{
						Action: actionAllow, Directions: []uint8{directionEgress},
						PeerDomain: "blocked.example", Priority: 100,
					}}},
					DNS: &DNSPolicy{DefaultAction: actionDeny},
				},
			},
		},
		sourceIndex: map[string]string{source.String(): "sandbox"},
	}

	_, err := manager.observeDNS(
		source,
		[]string{"blocked.example."},
		[]string{"blocked.example"},
		[]byte("response is not inspected after authorization changes"),
	)
	require.ErrorContains(t, err, "network policy changed")
}

type failNthStore struct {
	*store.MockStore
	writes int
	failAt int
}

func (s *failNthStore) StoreRaw(key string, data []byte) error {
	s.writes++
	if s.failAt != 0 && s.writes == s.failAt {
		return errors.New("injected raw store failure")
	}
	return s.MockStore.StoreRaw(key, data)
}
