//go:build linux && networkacl_integration

// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package networkacl

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	aclHelperEnabled = "SANDBOXD_ACL_CONFORMANCE_HELPER"
	aclHelperMode    = "SANDBOXD_ACL_HELPER_MODE"
	aclHelperAddress = "SANDBOXD_ACL_HELPER_ADDRESS"
	aclHelperSize    = "SANDBOXD_ACL_HELPER_SIZE"
	aclHelperSource  = "SANDBOXD_ACL_HELPER_SOURCE"

	aclHelperReady     = "ACL_HELPER_READY"
	aclHelperConnected = "ACL_HELPER_CONNECTED"
	aclHelperSent      = "ACL_HELPER_SENT"
	aclHelperReceived  = "ACL_HELPER_RECEIVED"
	aclHelperBlocked   = "ACL_HELPER_BLOCKED"
)

var aclTopologySequence atomic.Uint32

// TestACLBackendConformance owns the behavior contract for every ACL backend.
// Scenario functions contain no backend branches: iptables and bpfnat must
// produce the same externally visible verdict for every vector.
func TestACLBackendConformance(t *testing.T) {
	requireCommand(t, "ip")
	requireCommand(t, "iptables")
	requireCommand(t, "ip6tables")
	requireCommand(t, "ipset")
	requireCommand(t, "ping")

	for _, backend := range []string{aclBackendIPTables, aclBackendBPFNAT} {
		t.Run(backend, func(t *testing.T) {
			fixture := newACLConformanceFixture(t, backend)
			for _, scenario := range aclConformanceScenarios() {
				t.Run(scenario.name, func(t *testing.T) {
					scenario.run(t, fixture)
				})
			}
		})
	}
}

type aclConformanceScenario struct {
	name string
	run  func(*testing.T, *aclConformanceFixture)
}

func aclConformanceScenarios() []aclConformanceScenario {
	return []aclConformanceScenario{
		{name: "unrestricted fast path", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, Policy{})
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
			f.assertTCPFromSandboxSource(
				t, f.topology.sandboxSpoofIP, f.topology.remoteIP, 18080, true,
			)
			f.assertUDP(t, f.topology.remoteIP, 19090, 64, true)
			f.assertTCP(t, f.topology.gatewayIPv6, 18082, true)
			f.assertTCPFromNode(t, f.topology.sandboxIP, 50090, true)
			f.assertTCPFromNode(t, f.topology.sandboxSpoofIP, 50090, true)
			f.assertTCPFromNode(t, f.topology.sandboxIPv6, 50093, true)
			f.assertTCPFromRemote(t, f.topology.sandboxIPv6, 50093, true)
		}},
		{name: "active policy rejects IPv6", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, Policy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &TrafficPolicy{
					IngressDefaultAction: actionAllow,
					EgressDefaultAction:  actionAllow,
					Mode:                 policyModeStateful,
				},
			})
			f.assertTCP(t, f.topology.gatewayIPv6, 18082, false)
			f.assertTCPFromNode(t, f.topology.sandboxIPv6, 50093, false)
			f.assertTCPFromRemote(t, f.topology.sandboxIPv6, 50093, false)
		}},
		{name: "active policy rejects endpoint address spoofing", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, Policy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &TrafficPolicy{
					IngressDefaultAction: actionAllow,
					EgressDefaultAction:  actionAllow,
					Mode:                 policyModeStateful,
				},
			})
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
			f.assertTCPFromSandboxSource(
				t, f.topology.sandboxSpoofIP, f.topology.remoteIP, 18080, false,
			)
			f.assertTCPFromNode(t, f.topology.sandboxSpoofIP, 50090, false)
		}},
		{name: "default deny blocks both directions", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful))
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
			f.assertTCPFromRemote(t, f.topology.sandboxIP, 50090, false)
			f.assertTCPFromNode(t, f.topology.sandboxIP, 50090, false)
		}},
		{name: "independent direction defaults", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, Policy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &TrafficPolicy{
					IngressDefaultAction: actionAllow,
					EgressDefaultAction:  actionDeny,
					Mode:                 policyModeStateful,
				},
			})
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
			f.assertTCPFromRemote(t, f.topology.sandboxIP, 50090, true)
		}},
		{name: "CIDR port ranges and priority", run: func(t *testing.T, f *aclConformanceFixture) {
			var network [4]byte
			copy(network[:], f.topology.remoteIP.Mask(net.CIDRMask(24, 32)))
			allowRange := TrafficRule{
				Action: actionAllow, Directions: []uint8{directionEgress}, Protocol: 6,
				PeerIP: network, PeerPrefix: 24, PeerPortFirst: 18080, PeerPortLast: 18081,
				Priority: 200,
			}
			var exact [4]byte
			copy(exact[:], f.topology.remoteIP.To4())
			lowDeny := TrafficRule{
				Action: actionDeny, Directions: []uint8{directionEgress}, Protocol: 6,
				PeerIP: exact, PeerPrefix: 32, PeerPortFirst: 18080, PeerPortLast: 18080,
				Priority: 100,
			}
			f.setPolicy(t, Policy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &TrafficPolicy{
					IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
					Mode: policyModeStateful, Rules: []TrafficRule{allowRange, lowDeny},
				},
			})
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
			f.assertTCP(t, f.topology.remoteAliasIP, 18081, true)
			lowDeny.Priority = allowRange.Priority
			f.setPolicy(t, Policy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &TrafficPolicy{
					IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
					Mode: policyModeStateful, Rules: []TrafficRule{allowRange, lowDeny},
				},
			})
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
			f.assertTCP(t, f.topology.remoteAliasIP, 18081, true)
		}},
		{name: "sandbox port range", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, Policy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &TrafficPolicy{
					IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
					Mode: policyModeStateful,
					Rules: []TrafficRule{{
						Action: actionAllow, Directions: []uint8{directionIngress}, Protocol: 6,
						PeerAny: true, SandboxPortFirst: 50090, SandboxPortLast: 50091,
						Priority: defaultRulePriority,
					}},
				},
			})
			f.assertTCPFromRemote(t, f.topology.sandboxIP, 50090, true)
			f.assertTCPFromRemote(t, f.topology.sandboxIP, 50091, true)
			f.assertTCPFromNode(t, f.topology.sandboxIP, 50090, true)
			f.assertTCPFromNode(t, f.topology.sandboxIP, 50091, true)
		}},
		{name: "exact peer protocol and port", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 6, f.topology.remoteIP, 18080, 0),
			))
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
			f.assertTCP(t, f.topology.remoteIP, 18081, false)
			f.assertTCP(t, f.topology.remoteAliasIP, 18080, false)
			f.assertUDP(t, f.topology.remoteIP, 19090, 64, false)
		}},
		{name: "deny wins over broader allow", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				anyPeerRule(actionAllow, directionEgress, 6, 18080, 0),
				peerRule(actionDeny, directionEgress, 6, f.topology.remoteIP, 18080, 0),
			))
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
			f.assertTCP(t, f.topology.remoteAliasIP, 18080, true)
		}},
		{name: "default allow supports a denylist", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionAllow, policyModeStateful,
				peerRule(actionDeny, directionEgress, 6, f.topology.remoteIP, 18080, 0),
			))
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
			f.assertTCP(t, f.topology.remoteAliasIP, 18080, true)
			f.assertUDP(t, f.topology.remoteIP, 19090, 64, true)
		}},
		{name: "any protocol still scopes the peer", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 0, f.topology.remoteIP, 0, 0),
			))
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
			f.assertUDP(t, f.topology.remoteIP, 19090, 64, true)
			f.assertTCP(t, f.topology.remoteAliasIP, 18080, false)
		}},
		{name: "published TCP sandbox port", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				anyPeerRule(actionAllow, directionIngress, 6, 0, 50090),
			))
			f.assertTCPFromRemote(t, f.topology.sandboxIP, 50090, true)
			f.assertTCPFromRemote(t, f.topology.sandboxIP, 50091, false)
		}},
		{name: "published UDP sandbox port", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				anyPeerRule(actionAllow, directionIngress, 17, 0, 50092),
			))
			f.assertUDPFromRemote(t, f.topology.sandboxIP, 50092, 64, true)
		}},
		{name: "stateless TCP requires an explicit reverse rule", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateless,
				peerRule(actionAllow, directionEgress, 6, f.topology.remoteIP, 18080, 0),
			))
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
		}},
		{name: "stateful UDP admits replies", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 17, f.topology.remoteIP, 19090, 0),
			))
			f.assertUDP(t, f.topology.remoteIP, 19090, 64, true)
		}},
		{name: "stateful flow crosses two managed policy generations", run: func(t *testing.T, f *aclConformanceFixture) {
			peerPolicy := trafficPolicy(actionDeny, policyModeStateful,
				anyPeerRule(actionAllow, directionIngress, 6, 0, 50094),
			)
			require.NoError(t, f.manager.SetPolicy(f.peerBinding.SandboxID, peerPolicy))
			defer func() {
				require.NoError(t, f.manager.SetPolicy(f.peerBinding.SandboxID, Policy{}))
			}()

			primaryPolicy := trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 6, f.topology.peerSandboxIP, 50094, 0),
			)
			// Advance the primary endpoint twice so the test never depends on both
			// endpoints receiving the same initial generation number.
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful))
			f.setPolicy(t, primaryPolicy)
			f.manager.mu.RLock()
			primaryGeneration := f.manager.entries[f.binding.SandboxID].Generation
			peerGeneration := f.manager.entries[f.peerBinding.SandboxID].Generation
			f.manager.mu.RUnlock()
			require.NotEqual(t, primaryGeneration, peerGeneration)
			f.assertTCP(t, f.topology.peerSandboxIP, 50094, true)
		}},
		{name: "source authorization cannot bypass managed peer policy", run: func(t *testing.T, f *aclConformanceFixture) {
			peerPolicy := trafficPolicy(actionDeny, policyModeStateful)
			require.NoError(t, f.manager.SetPolicy(f.peerBinding.SandboxID, peerPolicy))
			defer func() {
				require.NoError(t, f.manager.SetPolicy(f.peerBinding.SandboxID, Policy{}))
			}()

			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 6, f.topology.peerSandboxIP, 50094, 0),
			))
			f.assertTCP(t, f.topology.peerSandboxIP, 50094, false)
		}},
		{name: "managed peer cannot borrow source state for a reverse packet", run: func(t *testing.T, f *aclConformanceFixture) {
			peerPolicy := trafficPolicy(actionDeny, policyModeStateless,
				peerRule(actionAllow, directionIngress, 17, f.topology.sandboxIP, 32000, 50095),
				peerRule(actionAllow, directionIngress, 17, f.topology.sandboxIP, 32001, 50096),
				peerRule(actionAllow, directionEgress, 17, f.topology.sandboxIP, 32001, 50096),
			)
			require.NoError(t, f.manager.SetPolicy(f.peerBinding.SandboxID, peerPolicy))
			defer func() {
				require.NoError(t, f.manager.SetPolicy(f.peerBinding.SandboxID, Policy{}))
			}()

			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 17, f.topology.peerSandboxIP, 50095, 32000),
				peerRule(actionAllow, directionEgress, 17, f.topology.peerSandboxIP, 50096, 32001),
			))
			f.assertManagedReverseUDP(t, 32000, 50095, false)
			f.assertManagedReverseUDP(t, 32001, 50096, true)
		}},
		{name: "stateless UDP requires an explicit reverse rule", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateless,
				peerRule(actionAllow, directionEgress, 17, f.topology.remoteIP, 19090, 0),
			))
			f.assertUDP(t, f.topology.remoteIP, 19090, 64, false)
		}},
		{name: "stateful ICMP echo admits replies", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 1, f.topology.remoteIP, 0, 0),
			))
			f.assertPing(t, f.topology.remoteIP, true)
		}},
		{name: "stateless ICMP echo requires a reverse rule", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateless,
				peerRule(actionAllow, directionEgress, 1, f.topology.remoteIP, 0, 0),
			))
			f.assertPing(t, f.topology.remoteIP, false)
		}},
		{name: "fragmented UDP follows connection state", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 17, f.topology.remoteIP, 19090, 0),
			))
			f.assertUDP(t, f.topology.remoteIP, 19090, 4096, true)
		}},
		{name: "related ICMP errors follow UDP state", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 17, f.topology.remoteIP, 19999, 0),
			))
			f.assertUDPUnreachable(t, f.topology.remoteIP, 19999)
		}},
		{name: "DNS policy reserves only the bridge proxy", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, Policy{DNS: &DNSPolicy{}})
			f.assertTCP(t, f.topology.gatewayIP, 53, true)
			f.assertUDP(t, f.topology.gatewayIP, 53, 64, true)
			f.assertTCP(t, f.topology.remoteIP, 53, false)
			f.assertUDP(t, f.topology.remoteIP, 53, 64, false)
			f.assertTCP(t, f.topology.gatewayIPv6, 18082, false)
		}},
		{name: "domain grants replace resolved addresses", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, Policy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &TrafficPolicy{
					IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
					Mode: policyModeStateful,
					Rules: []TrafficRule{{
						Action: actionAllow, Directions: []uint8{directionEgress}, Protocol: 6,
						PeerDomain: "service.example", PeerPortFirst: 18080,
						PeerPortLast: 18080, Priority: defaultRulePriority,
					}},
				},
			})
			f.setDomainGrants(t, []persistedDomainGrant{{
				Question: "service.example", IP: f.topology.remoteIP.String(),
				ExpiresAt: time.Now().Add(time.Minute).UnixNano(), RuleIndex: 0,
			}})
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
			f.assertTCP(t, f.topology.remoteAliasIP, 18080, false)
			f.assertActiveTCPInvalidated(t, func() {
				f.setDomainGrants(t, []persistedDomainGrant{{
					Question: "service.example", IP: f.topology.remoteAliasIP.String(),
					ExpiresAt: time.Now().Add(time.Minute).UnixNano(), RuleIndex: 0,
				}})
			})
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
			f.assertTCP(t, f.topology.remoteAliasIP, 18080, true)
			f.restart(t)
			f.assertTCP(t, f.topology.remoteAliasIP, 18080, true)
		}},
		{name: "domain TTL expiry invalidates an active flow", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, Policy{
				SchemaVersion: networkPolicySchemaV2,
				Traffic: &TrafficPolicy{
					IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
					Mode: policyModeStateful,
					Rules: []TrafficRule{{
						Action: actionAllow, Directions: []uint8{directionEgress}, Protocol: 6,
						PeerDomain: "service.example", PeerPortFirst: 18080,
						PeerPortLast: 18080, Priority: defaultRulePriority,
					}},
				},
			})
			f.setDomainGrants(t, []persistedDomainGrant{{
				Question: "service.example", IP: f.topology.remoteIP.String(),
				ExpiresAt: time.Now().Add(2 * time.Second).UnixNano(), RuleIndex: 0,
			}})
			f.assertActiveTCPInvalidated(t, func() {
				require.Eventually(t, func() bool {
					f.manager.mu.RLock()
					defer f.manager.mu.RUnlock()
					return len(f.manager.entries[f.binding.SandboxID].DomainGrants) == 0
				}, 5*time.Second, 50*time.Millisecond, "domain grant was not swept after TTL expiry")
			})
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
		}},
		{name: "policy replacement invalidates an active flow", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 6, f.topology.remoteIP, 18080, 0),
			))
			f.assertActiveTCPInvalidated(t, func() {
				f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful))
			})
		}},
		{name: "restart restores the active policy", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful,
				peerRule(actionAllow, directionEgress, 6, f.topology.remoteIP, 18080, 0),
			))
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
			f.restart(t)
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
			f.assertTCP(t, f.topology.remoteIP, 18081, false)
		}},
		{name: "clearing policy restores unrestricted traffic", run: func(t *testing.T, f *aclConformanceFixture) {
			f.setPolicy(t, trafficPolicy(actionDeny, policyModeStateful))
			f.assertTCP(t, f.topology.remoteIP, 18080, false)
			f.setPolicy(t, Policy{})
			f.assertTCP(t, f.topology.remoteIP, 18080, true)
		}},
	}
}

type aclConformanceFixture struct {
	backend     string
	manager     *Manager
	config      Config
	store       *store.MockStore
	binding     Binding
	peerBinding Binding
	topology    *aclConformanceTopology
}

func newACLConformanceFixture(t *testing.T, backend string) *aclConformanceFixture {
	t.Helper()
	topology := newACLConformanceTopology(t)
	topology.startServers(t)
	if backend == aclBackendBPFNAT {
		require.NoError(t, ensureBPFFS())
		require.NoError(t, os.RemoveAll(pinRoot))
	}
	stateStore := store.NewMockStore()
	config := Config{
		Backend: backend, BridgeIP: topology.gatewayIP, Store: stateStore,
		DisableProxy: true,
	}
	manager, err := New(config)
	require.NoError(t, err)
	binding := Binding{
		SandboxID: "conformance-" + backend,
		IP:        topology.sandboxIP, HostVeth: topology.sandboxHostVeth,
	}
	require.NoError(t, manager.Register(binding, Policy{}))
	peerBinding := Binding{
		SandboxID: "conformance-peer-" + backend,
		IP:        topology.peerSandboxIP, HostVeth: topology.peerSandboxHostVeth,
	}
	require.NoError(t, manager.Register(peerBinding, Policy{}))
	fixture := &aclConformanceFixture{
		backend: backend, manager: manager, config: config, store: stateStore,
		binding: binding, peerBinding: peerBinding, topology: topology,
	}
	t.Cleanup(func() {
		if fixture.manager != nil {
			assert.NoError(t, fixture.manager.Remove(binding.SandboxID))
			assert.NoError(t, fixture.manager.Remove(peerBinding.SandboxID))
			assert.NoError(t, fixture.manager.Close())
		}
		if backend == aclBackendBPFNAT {
			assert.NoError(t, os.RemoveAll(pinRoot))
		}
	})
	return fixture
}

func (f *aclConformanceFixture) setPolicy(t *testing.T, policy Policy) {
	t.Helper()
	require.NoError(t, f.manager.SetPolicy(f.binding.SandboxID, policy))
}

func (f *aclConformanceFixture) setDomainGrants(t *testing.T, grants []persistedDomainGrant) {
	t.Helper()
	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()
	previous := f.manager.entries[f.binding.SandboxID]
	next := previous
	next.DomainGrants = deduplicateDomainGrants(grants)
	require.NoError(t, f.manager.applyDomainGrantsLocked(previous, next))
	f.manager.entries[f.binding.SandboxID] = next
	require.NoError(t, f.manager.persistLocked())
}

func (f *aclConformanceFixture) restart(t *testing.T) {
	t.Helper()
	require.NoError(t, f.manager.Close())
	f.manager = nil
	manager, err := New(f.config)
	require.NoError(t, err)
	f.manager = manager
	require.NoError(t, manager.Restore(map[string]Binding{
		f.binding.SandboxID:     f.binding,
		f.peerBinding.SandboxID: f.peerBinding,
	}))
}

func (f *aclConformanceFixture) assertTCP(t *testing.T, destination net.IP, port int, want bool) {
	t.Helper()
	f.assertProbe(t, f.topology.sandboxNamespace, "tcp-probe", destination, port, 64, want)
}

func (f *aclConformanceFixture) assertTCPFromSandboxSource(
	t *testing.T, source, destination net.IP, port int, want bool,
) {
	t.Helper()
	f.assertProbeWithSource(
		t, f.topology.sandboxNamespace, "tcp-probe", source, destination, port, 64, want,
	)
}

func (f *aclConformanceFixture) assertTCPFromRemote(
	t *testing.T, destination net.IP, port int, want bool,
) {
	t.Helper()
	f.assertProbe(t, f.topology.remoteNamespace, "tcp-probe", destination, port, 64, want)
}

func (f *aclConformanceFixture) assertTCPFromNode(
	t *testing.T, destination net.IP, port int, want bool,
) {
	t.Helper()
	f.assertProbe(t, "", "tcp-probe", destination, port, 64, want)
}

func (f *aclConformanceFixture) assertUDP(
	t *testing.T, destination net.IP, port, size int, want bool,
) {
	t.Helper()
	f.assertProbe(t, f.topology.sandboxNamespace, "udp-probe", destination, port, size, want)
}

func (f *aclConformanceFixture) assertUDPFromRemote(
	t *testing.T, destination net.IP, port, size int, want bool,
) {
	t.Helper()
	f.assertProbe(t, f.topology.remoteNamespace, "udp-probe", destination, port, size, want)
}

func (f *aclConformanceFixture) assertProbe(
	t *testing.T, namespace, mode string, destination net.IP, port, size int, want bool,
) {
	t.Helper()
	f.assertProbeWithSource(t, namespace, mode, nil, destination, port, size, want)
}

func (f *aclConformanceFixture) assertProbeWithSource(
	t *testing.T, namespace, mode string, source, destination net.IP, port, size int, want bool,
) {
	t.Helper()
	address := net.JoinHostPort(destination.String(), strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	command := aclHelperCommand(ctx, namespace, mode, address, size)
	if source != nil {
		command.Env = append(command.Env, aclHelperSource+"="+source.String())
	}
	output, err := command.CombinedOutput()
	if want {
		require.NoError(t, err, "probe %s failed: %s", address, output)
		return
	}
	assert.Error(t, err, "probe %s unexpectedly succeeded: %s", address, output)
}

func (f *aclConformanceFixture) assertPing(t *testing.T, destination net.IP, want bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "ip", "netns", "exec", f.topology.sandboxNamespace,
		"ping", "-n", "-c", "1", "-W", "1", destination.String())
	output, err := command.CombinedOutput()
	if want {
		require.NoError(t, err, "ping failed: %s", output)
		return
	}
	assert.Error(t, err, "ping unexpectedly succeeded: %s", output)
}

func (f *aclConformanceFixture) assertUDPUnreachable(t *testing.T, destination net.IP, port int) {
	t.Helper()
	address := net.JoinHostPort(destination.String(), strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	output, err := aclHelperCommand(
		ctx, f.topology.sandboxNamespace, "udp-unreachable", address, 64,
	).CombinedOutput()
	require.NoError(t, err, "related ICMP error was not delivered: %s", output)
}

func (f *aclConformanceFixture) assertActiveTCPInvalidated(t *testing.T, update func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	address := net.JoinHostPort(f.topology.remoteIP.String(), "18080")
	command := aclHelperCommand(ctx, f.topology.sandboxNamespace, "tcp-session", address, 64)
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	require.NoError(t, command.Start())
	lines := scanACLHelperLines(stdout)
	require.NoError(t, waitForACLHelperMarker(lines, aclHelperConnected, 3*time.Second), stderr.String())
	update()
	_, err = io.WriteString(stdin, "continue\n")
	require.NoError(t, err)
	require.NoError(t, waitForACLHelperMarker(lines, aclHelperBlocked, 3*time.Second), stderr.String())
	require.NoError(t, command.Wait(), stderr.String())
}

func (f *aclConformanceFixture) assertManagedReverseUDP(
	t *testing.T, sandboxPort, peerPort int, want bool,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	initialDestination := net.JoinHostPort(f.topology.peerSandboxIP.String(), strconv.Itoa(peerPort))
	localAddress := net.JoinHostPort(f.topology.sandboxIP.String(), strconv.Itoa(sandboxPort))
	command := aclHelperCommand(
		ctx, f.topology.sandboxNamespace, "udp-session", initialDestination, 64,
	)
	command.Env = append(command.Env, aclHelperSource+"="+localAddress)
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	require.NoError(t, command.Start())
	lines := scanACLHelperLines(stdout)
	require.NoError(t, waitForACLHelperMarker(lines, aclHelperSent, 3*time.Second), stderr.String())
	_, err = io.WriteString(stdin, "continue\n")
	require.NoError(t, err)
	marker := aclHelperBlocked
	if want {
		marker = aclHelperReceived
	}
	require.NoError(t, waitForACLHelperMarker(lines, marker, 3*time.Second), stderr.String())
	require.NoError(t, command.Wait(), stderr.String())
}

type aclConformanceTopology struct {
	sandboxNamespace     string
	peerSandboxNamespace string
	remoteNamespace      string
	sandboxBridge        string
	sandboxHostVeth      string
	peerSandboxHostVeth  string
	remoteHostVeth       string
	sandboxIP            net.IP
	peerSandboxIP        net.IP
	sandboxSpoofIP       net.IP
	gatewayIP            net.IP
	remoteIP             net.IP
	remoteAliasIP        net.IP
	sandboxIPv6          net.IP
	gatewayIPv6          net.IP
	remoteIPv6           net.IP
	remoteGatewayIPv6    net.IP
}

func newACLConformanceTopology(t *testing.T) *aclConformanceTopology {
	t.Helper()
	sequence := aclTopologySequence.Add(1)
	suffix := fmt.Sprintf("%05x", (uint32(os.Getpid())+sequence)&0xfffff)
	octet := 100 + int(sequence%100)
	topology := &aclConformanceTopology{
		sandboxNamespace:     "sd-acl-s-" + suffix,
		peerSandboxNamespace: "sd-acl-p-" + suffix,
		remoteNamespace:      "sd-acl-r-" + suffix,
		sandboxBridge:        "ab" + suffix,
		sandboxHostVeth:      "ash" + suffix,
		peerSandboxHostVeth:  "aph" + suffix,
		remoteHostVeth:       "arh" + suffix,
		sandboxIP:            net.ParseIP(fmt.Sprintf("10.240.%d.2", octet)).To4(),
		peerSandboxIP:        net.ParseIP(fmt.Sprintf("10.240.%d.3", octet)).To4(),
		sandboxSpoofIP:       net.ParseIP(fmt.Sprintf("10.240.%d.99", octet)).To4(),
		gatewayIP:            net.ParseIP(fmt.Sprintf("10.240.%d.1", octet)).To4(),
		remoteIP:             net.ParseIP(fmt.Sprintf("198.18.%d.2", octet)).To4(),
		remoteAliasIP:        net.ParseIP(fmt.Sprintf("198.18.%d.3", octet)).To4(),
		sandboxIPv6:          net.ParseIP(fmt.Sprintf("fd42:%x::2", octet)),
		gatewayIPv6:          net.ParseIP(fmt.Sprintf("fd42:%x::1", octet)),
		remoteIPv6:           net.ParseIP(fmt.Sprintf("fd43:%x::2", octet)),
		remoteGatewayIPv6:    net.ParseIP(fmt.Sprintf("fd43:%x::1", octet)),
	}
	sandboxPeer := "asp" + suffix
	peerSandboxPeer := "app" + suffix
	remotePeer := "arp" + suffix

	runACLCommand(t, "ip", "netns", "add", topology.sandboxNamespace)
	t.Cleanup(func() { _ = runACLCommandError("ip", "netns", "del", topology.sandboxNamespace) })
	runACLCommand(t, "ip", "netns", "add", topology.peerSandboxNamespace)
	t.Cleanup(func() { _ = runACLCommandError("ip", "netns", "del", topology.peerSandboxNamespace) })
	runACLCommand(t, "ip", "netns", "add", topology.remoteNamespace)
	t.Cleanup(func() { _ = runACLCommandError("ip", "netns", "del", topology.remoteNamespace) })
	runACLCommand(t, "ip", "link", "add", topology.sandboxBridge, "type", "bridge")
	t.Cleanup(func() { _ = runACLCommandError("ip", "link", "del", topology.sandboxBridge) })
	runACLCommand(t, "ip", "addr", "add", topology.gatewayIP.String()+"/24",
		"dev", topology.sandboxBridge)
	runACLCommand(t, "ip", "-6", "addr", "add", topology.gatewayIPv6.String()+"/64",
		"dev", topology.sandboxBridge, "nodad")
	runACLCommand(t, "ip", "link", "set", topology.sandboxBridge, "up")

	runACLCommand(t, "ip", "link", "add", topology.sandboxHostVeth,
		"type", "veth", "peer", "name", sandboxPeer)
	runACLCommand(t, "ip", "link", "set", sandboxPeer, "netns", topology.sandboxNamespace)
	runACLCommand(t, "ip", "link", "set", topology.sandboxHostVeth,
		"master", topology.sandboxBridge)
	runACLCommand(t, "ip", "link", "set", topology.sandboxHostVeth, "up")
	runACLCommand(t, "ip", "-n", topology.sandboxNamespace, "link", "set", "lo", "up")
	runACLCommand(t, "ip", "-n", topology.sandboxNamespace, "addr", "add",
		topology.sandboxIP.String()+"/24", "dev", sandboxPeer)
	runACLCommand(t, "ip", "-n", topology.sandboxNamespace, "addr", "add",
		topology.sandboxSpoofIP.String()+"/24", "dev", sandboxPeer)
	runACLCommand(t, "ip", "-n", topology.sandboxNamespace, "-6", "addr", "add",
		topology.sandboxIPv6.String()+"/64", "dev", sandboxPeer, "nodad")
	runACLCommand(t, "ip", "-n", topology.sandboxNamespace, "link", "set", sandboxPeer, "up")
	runACLCommand(t, "ip", "-n", topology.sandboxNamespace, "route", "add", "default",
		"via", topology.gatewayIP.String())
	runACLCommand(t, "ip", "-n", topology.sandboxNamespace, "-6", "route", "add", "default",
		"via", topology.gatewayIPv6.String())

	runACLCommand(t, "ip", "link", "add", topology.peerSandboxHostVeth,
		"type", "veth", "peer", "name", peerSandboxPeer)
	runACLCommand(t, "ip", "link", "set", peerSandboxPeer, "netns", topology.peerSandboxNamespace)
	runACLCommand(t, "ip", "link", "set", topology.peerSandboxHostVeth,
		"master", topology.sandboxBridge)
	runACLCommand(t, "ip", "link", "set", topology.peerSandboxHostVeth, "up")
	runACLCommand(t, "ip", "-n", topology.peerSandboxNamespace, "link", "set", "lo", "up")
	runACLCommand(t, "ip", "-n", topology.peerSandboxNamespace, "addr", "add",
		topology.peerSandboxIP.String()+"/24", "dev", peerSandboxPeer)
	runACLCommand(t, "ip", "-n", topology.peerSandboxNamespace, "link", "set", peerSandboxPeer, "up")
	runACLCommand(t, "ip", "-n", topology.peerSandboxNamespace, "route", "add", "default",
		"via", topology.gatewayIP.String())

	remoteGateway := net.ParseIP(fmt.Sprintf("198.18.%d.1", octet)).To4()
	runACLCommand(t, "ip", "link", "add", topology.remoteHostVeth,
		"type", "veth", "peer", "name", remotePeer)
	runACLCommand(t, "ip", "link", "set", remotePeer, "netns", topology.remoteNamespace)
	runACLCommand(t, "ip", "addr", "add", remoteGateway.String()+"/24",
		"dev", topology.remoteHostVeth)
	runACLCommand(t, "ip", "-6", "addr", "add", topology.remoteGatewayIPv6.String()+"/64",
		"dev", topology.remoteHostVeth, "nodad")
	runACLCommand(t, "ip", "link", "set", topology.remoteHostVeth, "up")
	runACLCommand(t, "ip", "-n", topology.remoteNamespace, "link", "set", "lo", "up")
	runACLCommand(t, "ip", "-n", topology.remoteNamespace, "addr", "add",
		topology.remoteIP.String()+"/24", "dev", remotePeer)
	runACLCommand(t, "ip", "-n", topology.remoteNamespace, "addr", "add",
		topology.remoteAliasIP.String()+"/24", "dev", remotePeer)
	runACLCommand(t, "ip", "-n", topology.remoteNamespace, "-6", "addr", "add",
		topology.remoteIPv6.String()+"/64", "dev", remotePeer, "nodad")
	runACLCommand(t, "ip", "-n", topology.remoteNamespace, "link", "set", remotePeer, "up")
	runACLCommand(t, "ip", "-n", topology.remoteNamespace, "route", "add", "default",
		"via", remoteGateway.String())
	runACLCommand(t, "ip", "-n", topology.remoteNamespace, "-6", "route", "add",
		topology.sandboxIPv6.String()+"/64", "via", topology.remoteGatewayIPv6.String())

	runACLCommand(t, "iptables", "-P", "INPUT", "ACCEPT")
	runACLCommand(t, "iptables", "-P", "OUTPUT", "ACCEPT")
	runACLCommand(t, "iptables", "-P", "FORWARD", "ACCEPT")
	runACLCommand(t, "ip6tables", "-P", "INPUT", "ACCEPT")
	runACLCommand(t, "ip6tables", "-P", "OUTPUT", "ACCEPT")
	runACLCommand(t, "ip6tables", "-P", "FORWARD", "ACCEPT")
	return topology
}

func (topology *aclConformanceTopology) startServers(t *testing.T) {
	t.Helper()
	for _, server := range []struct {
		namespace string
		mode      string
		address   string
	}{
		{topology.remoteNamespace, "tcp-server", ":18080"},
		{topology.remoteNamespace, "tcp-server", ":18081"},
		{topology.remoteNamespace, "udp-server", ":19090"},
		{topology.remoteNamespace, "tcp-server", ":53"},
		{topology.remoteNamespace, "udp-server", ":53"},
		{topology.sandboxNamespace, "tcp-server", ":50090"},
		{topology.sandboxNamespace, "tcp-server", ":50091"},
		{topology.sandboxNamespace, "udp-server", ":50092"},
		{topology.peerSandboxNamespace, "tcp-server", net.JoinHostPort(topology.peerSandboxIP.String(), "50094")},
		{topology.peerSandboxNamespace, "udp-server", net.JoinHostPort(topology.peerSandboxIP.String(), "50095")},
		{topology.peerSandboxNamespace, "udp-server", net.JoinHostPort(topology.peerSandboxIP.String(), "50096")},
		{topology.sandboxNamespace, "tcp-server", net.JoinHostPort(topology.sandboxIPv6.String(), "50093")},
		{"", "tcp-server", net.JoinHostPort(topology.gatewayIP.String(), "53")},
		{"", "udp-server", net.JoinHostPort(topology.gatewayIP.String(), "53")},
		{"", "tcp-server", net.JoinHostPort(topology.gatewayIPv6.String(), "18082")},
	} {
		startACLHelperServer(t, server.namespace, server.mode, server.address)
	}
}

func startACLHelperServer(t *testing.T, namespace, mode, address string) {
	t.Helper()
	command := aclHelperCommand(context.Background(), namespace, mode, address, 64)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	require.NoError(t, command.Start())
	lines := scanACLHelperLines(stdout)
	require.NoError(t, waitForACLHelperMarker(lines, aclHelperReady, 3*time.Second), stderr.String())
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	})
}

func aclHelperCommand(
	ctx context.Context, namespace, mode, address string, size int,
) *exec.Cmd {
	executable, err := os.Executable()
	if err != nil {
		panic(err)
	}
	arguments := []string{"-test.run=^TestACLConformanceHelper$"}
	var command *exec.Cmd
	if namespace == "" {
		command = exec.CommandContext(ctx, executable, arguments...)
	} else {
		arguments = append([]string{"netns", "exec", namespace, executable}, arguments...)
		command = exec.CommandContext(ctx, "ip", arguments...)
	}
	command.Env = append(os.Environ(),
		aclHelperEnabled+"=1",
		aclHelperMode+"="+mode,
		aclHelperAddress+"="+address,
		aclHelperSize+"="+strconv.Itoa(size),
	)
	return command
}

func scanACLHelperLines(reader io.Reader) <-chan string {
	lines := make(chan string, 16)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	return lines
}

func waitForACLHelperMarker(lines <-chan string, marker string, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var observed []string
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return fmt.Errorf("helper exited before %s; output=%q", marker, observed)
			}
			observed = append(observed, line)
			if strings.Contains(line, marker) {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("timed out waiting for %s; output=%q", marker, observed)
		}
	}
}

func runACLCommand(t *testing.T, name string, arguments ...string) {
	t.Helper()
	output, err := exec.Command(name, arguments...).CombinedOutput()
	require.NoError(t, err, "%s %s: %s", name, strings.Join(arguments, " "), output)
}

func runACLCommandError(name string, arguments ...string) error {
	output, err := exec.Command(name, arguments...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(arguments, " "), err, output)
	}
	return nil
}

func requireCommand(t *testing.T, name string) {
	t.Helper()
	_, err := exec.LookPath(name)
	require.NoError(t, err, "network ACL conformance requires %s", name)
}

func trafficPolicy(defaultAction, mode uint8, rules ...TrafficRule) Policy {
	return Policy{Traffic: &TrafficPolicy{
		DefaultAction: defaultAction,
		Mode:          mode,
		Rules:         rules,
	}}
}

func peerRule(
	action, direction, protocol uint8, peer net.IP, peerPort, sandboxPort uint16,
) TrafficRule {
	var peerIP [4]byte
	copy(peerIP[:], peer.To4())
	return TrafficRule{
		Action: action, Directions: []uint8{direction}, Protocol: protocol,
		PeerIP: peerIP, PeerPort: peerPort, SandboxPort: sandboxPort,
	}
}

func anyPeerRule(
	action, direction, protocol uint8, peerPort, sandboxPort uint16,
) TrafficRule {
	return TrafficRule{
		Action: action, Directions: []uint8{direction}, Protocol: protocol,
		PeerAny: true, PeerPort: peerPort, SandboxPort: sandboxPort,
	}
}

// TestACLConformanceHelper is executed in the topology namespaces as a child
// process. Keeping traffic generation in this test binary avoids depending on
// netcat variants and gives every backend byte-identical probes.
func TestACLConformanceHelper(t *testing.T) {
	if os.Getenv(aclHelperEnabled) != "1" {
		return
	}
	mode := os.Getenv(aclHelperMode)
	address := os.Getenv(aclHelperAddress)
	size, err := strconv.Atoi(os.Getenv(aclHelperSize))
	require.NoError(t, err)
	if size <= 0 {
		size = 64
	}
	switch mode {
	case "tcp-server":
		runACLTCPEchoServer(t, address)
	case "udp-server":
		runACLUDPEchoServer(t, address)
	case "tcp-probe":
		runACLTCPProbe(t, address, size)
	case "udp-probe":
		runACLUDPProbe(t, address, size)
	case "udp-unreachable":
		runACLUDPUnreachableProbe(t, address, size)
	case "udp-session":
		runACLUDPReverseSession(t, address, size)
	case "tcp-session":
		runACLTCPInvalidationSession(t, address, size)
	default:
		t.Fatalf("unknown ACL helper mode %q", mode)
	}
}

func runACLTCPEchoServer(t *testing.T, address string) {
	listener, err := net.Listen(aclAddressNetwork("tcp", address), address)
	require.NoError(t, err)
	defer listener.Close()
	fmt.Fprintln(os.Stdout, aclHelperReady)
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		go func() {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func runACLUDPEchoServer(t *testing.T, address string) {
	endpoint, err := net.ResolveUDPAddr("udp4", address)
	require.NoError(t, err)
	connection, err := net.ListenUDP("udp4", endpoint)
	require.NoError(t, err)
	defer connection.Close()
	fmt.Fprintln(os.Stdout, aclHelperReady)
	buffer := make([]byte, 65535)
	for {
		n, source, readErr := connection.ReadFromUDP(buffer)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, writeErr := connection.WriteToUDP(buffer[:n], source); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
}

func runACLTCPProbe(t *testing.T, address string, size int) {
	dialer := net.Dialer{Timeout: 1200 * time.Millisecond}
	if source := os.Getenv(aclHelperSource); source != "" {
		ip := net.ParseIP(source).To4()
		require.NotNil(t, ip, "invalid ACL helper source %q", source)
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	connection, err := dialer.Dial(aclAddressNetwork("tcp", address), address)
	require.NoError(t, err)
	defer connection.Close()
	require.NoError(t, connection.SetDeadline(time.Now().Add(1200*time.Millisecond)))
	require.NoError(t, aclTCPRoundTrip(connection, size))
}

func aclAddressNetwork(protocol, address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() == nil {
			return protocol + "6"
		}
	}
	return protocol + "4"
}

func runACLUDPProbe(t *testing.T, address string, size int) {
	connection, err := net.DialTimeout("udp4", address, 1200*time.Millisecond)
	require.NoError(t, err)
	defer connection.Close()
	require.NoError(t, connection.SetDeadline(time.Now().Add(1200*time.Millisecond)))
	payload := bytes.Repeat([]byte{0xa5}, size)
	_, err = connection.Write(payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	n, err := io.ReadFull(connection, response)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, payload, response)
}

func runACLUDPUnreachableProbe(t *testing.T, address string, size int) {
	connection, err := net.DialTimeout("udp4", address, 1200*time.Millisecond)
	require.NoError(t, err)
	defer connection.Close()
	require.NoError(t, connection.SetDeadline(time.Now().Add(1200*time.Millisecond)))
	_, err = connection.Write(bytes.Repeat([]byte{0x5a}, size))
	require.NoError(t, err)
	_, err = connection.Read(make([]byte, size))
	require.Error(t, err)
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		t.Fatalf("related ICMP error was blocked: %v", err)
	}
}

func runACLUDPReverseSession(t *testing.T, address string, size int) {
	remote, err := net.ResolveUDPAddr("udp4", address)
	require.NoError(t, err)
	local, err := net.ResolveUDPAddr("udp4", os.Getenv(aclHelperSource))
	require.NoError(t, err)
	connection, err := net.DialUDP("udp4", local, remote)
	require.NoError(t, err)
	defer connection.Close()
	payload := bytes.Repeat([]byte{0x6d}, size)
	require.NoError(t, connection.SetWriteDeadline(time.Now().Add(1200*time.Millisecond)))
	_, err = connection.Write(payload)
	require.NoError(t, err)
	fmt.Fprintln(os.Stdout, aclHelperSent)

	scanner := bufio.NewScanner(os.Stdin)
	require.True(t, scanner.Scan(), "parent closed UDP session control pipe")
	require.NoError(t, connection.SetReadDeadline(time.Now().Add(1200*time.Millisecond)))
	received := make([]byte, len(payload))
	n, err := connection.Read(received)
	if err != nil {
		fmt.Fprintln(os.Stdout, aclHelperBlocked)
		return
	}
	require.Equal(t, len(payload), n)
	require.Equal(t, payload, received)
	fmt.Fprintln(os.Stdout, aclHelperReceived)
}

func runACLTCPInvalidationSession(t *testing.T, address string, size int) {
	connection, err := net.DialTimeout("tcp4", address, 1200*time.Millisecond)
	require.NoError(t, err)
	defer connection.Close()
	require.NoError(t, connection.SetDeadline(time.Now().Add(1200*time.Millisecond)))
	require.NoError(t, aclTCPRoundTrip(connection, size))
	fmt.Fprintln(os.Stdout, aclHelperConnected)
	scanner := bufio.NewScanner(os.Stdin)
	require.True(t, scanner.Scan(), "parent closed session control pipe")
	require.NoError(t, connection.SetDeadline(time.Now().Add(1200*time.Millisecond)))
	if err := aclTCPRoundTrip(connection, size); err != nil {
		fmt.Fprintln(os.Stdout, aclHelperBlocked)
		return
	}
	t.Fatal("connection admitted by the previous policy remained usable")
}

func aclTCPRoundTrip(connection net.Conn, size int) error {
	payload := bytes.Repeat([]byte{0x3c}, size)
	if _, err := connection.Write(payload); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if !bytes.Equal(payload, response) {
		return errors.New("TCP echo payload mismatch")
	}
	return nil
}
