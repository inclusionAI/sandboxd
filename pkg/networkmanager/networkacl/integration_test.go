//go:build linux && networkacl_integration

// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package networkacl

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

func TestIntegrationV2IgnoresLegacyConnectionMapABI(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	require.NoError(t, rlimit.RemoveMemlock())
	require.NoError(t, os.RemoveAll(pinRoot))
	require.NoError(t, os.MkdirAll(pinRoot, 0700))
	t.Cleanup(func() { _ = os.RemoveAll(pinRoot) })

	legacy, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "CONNECTION_MAP",
		Type:       ebpf.LRUHash,
		KeySize:    uint32(binary.Size(connectionKey{})),
		ValueSize:  uint32(binary.Size(uint64(0))),
		MaxEntries: 131072,
	})
	require.NoError(t, err)
	defer legacy.Close()
	require.NoError(t, legacy.Pin(pinRoot+"/CONNECTION_MAP"))

	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), DisableProxy: true, DisableAttach: true,
	})
	require.NoError(t, err)
	require.NoError(t, manager.Close())
	_, err = os.Stat(pinRoot + "/CONNECTION_MAP")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestIntegrationDataplane(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := loadNetworkacl()
	require.NoError(t, err)
	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "networkacl-test-")
	require.NoError(t, err)
	defer os.RemoveAll(pinPath)
	var objects bpfObjects
	require.NoError(t, spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}))
	defer objects.close()

	sandboxIP := net.ParseIP("10.88.0.2").To4()
	proxyIP := net.ParseIP("10.88.0.1").To4()
	remoteIP := net.ParseIP("192.0.2.10").To4()
	configKey := uint32(0)
	configValue := ipv4Value(proxyIP)
	require.NoError(t, objects.Config.Update(&configKey, &configValue, ebpf.UpdateAny))

	ifindex := uint32(1) // SCHED_CLS test-run uses the initial netns loopback.
	policy := policyV2Value{
		Generation: 1, SandboxIP: ipv4Value(sandboxIP),
		TrafficEnabled: 1, IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
	}
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	policy.RuleCount = 1
	policy.Rules[0] = policyV2Rule{
		PeerIP: ipv4Value(proxyIP), PeerPrefix: 32, Priority: defaultRulePriority,
		PeerPortFirst: 8080, PeerPortLast: 8080, Directions: directionEgress,
		Protocol: 6, Action: actionAllow,
	}
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))

	ret, _, err := objects.EgressProgram.Test(makeTCPPacket(sandboxIP, proxyIP, 32000, 8080))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, remoteIP, 32000, 443))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)

	// A broader deny wins over the exact allow.
	policy.RuleCount = 2
	policy.Rules[1] = policyV2Rule{
		PeerIP: ipv4Value(proxyIP), PeerPrefix: 32, Priority: defaultRulePriority,
		Directions: directionEgress, Protocol: 6, Action: actionDeny,
	}
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, proxyIP, 32000, 8080))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)

	// DNS policy reserves only the sandbox0 proxy endpoint.
	policy.DNSEnabled = 1
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeUDPPacket(sandboxIP, proxyIP, 32000, 53))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	ret, _, err = objects.EgressProgram.Test(makeUDPPacket(sandboxIP, remoteIP, 32000, 53))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
	policy.UpdateBarrier = 1
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeUDPPacket(sandboxIP, proxyIP, 32000, 53))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "the derived-domain update barrier fails closed")
	policy.UpdateBarrier = 0

	// CIDR and port ranges honor explicit priority. A higher-priority allow
	// beats a narrower deny; DENY wins after the priorities are tied.
	policy.DNSEnabled = 0
	policy.RuleCount = 2
	policy.Rules[0] = policyV2Rule{
		PeerIP: ipv4Value(net.ParseIP("192.0.2.0")), PeerPrefix: 24,
		PeerPortFirst: 440, PeerPortLast: 450, Priority: 200,
		Directions: directionEgress, Protocol: 6, Action: actionAllow,
	}
	policy.Rules[1] = policyV2Rule{
		PeerIP: ipv4Value(remoteIP), PeerPrefix: 32,
		PeerPortFirst: 443, PeerPortLast: 443, Priority: 100,
		Directions: directionEgress, Protocol: 6, Action: actionDeny,
	}
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, remoteIP, 32000, 443))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	policy.Rules[1].Priority = 200
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, remoteIP, 32000, 443))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)

	// DNS-derived grants expire in the dataplane even when userspace has not
	// yet swept the persisted record.
	policy.RuleCount = 0
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	now, err := monotonicNanoseconds()
	require.NoError(t, err)
	domainKey := domainPolicyKey{Generation: policy.Generation, IfIndex: ifindex, PeerIP: ipv4Value(remoteIP)}
	domainValue := domainPolicyValue{RuleCount: 1}
	domainValue.Rules[0] = domainPolicyRule{
		ExpiresAt: now + uint64(time.Second), Priority: 300,
		PeerPortFirst: 443, PeerPortLast: 443, Protocol: 6, Action: actionAllow,
	}
	require.NoError(t, objects.DomainPolicies.Update(&domainKey, &domainValue, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, remoteIP, 32000, 443))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	domainValue.Rules[0].ExpiresAt = now - 1
	require.NoError(t, objects.DomainPolicies.Update(&domainKey, &domainValue, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, remoteIP, 32000, 443))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)

	// A stateful connection created by a domain grant remains capped by that
	// grant. Refreshing traffic cannot extend it past DNS expiry, including
	// while userspace is unavailable to run the grant sweeper.
	policy.Mode = policyModeStateful
	policy.Generation++
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	now, err = monotonicNanoseconds()
	require.NoError(t, err)
	domainKey.Generation = policy.Generation
	domainValue.Rules[0].ExpiresAt = now + uint64(50*time.Millisecond)
	require.NoError(t, objects.DomainPolicies.Update(&domainKey, &domainValue, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, remoteIP, 32001, 443))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	time.Sleep(75 * time.Millisecond)
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, remoteIP, 32001, 443))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)

	// DNS-only policy must fail closed for IPv6 rather than allowing a direct
	// query to an IPv6 resolver that bypasses sandbox0:53.
	policy.TrafficEnabled = 0
	policy.DNSEnabled = 1
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeIPv6Packet(17))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
}

func TestIntegrationStatefulConnectionsAndFragments(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := loadNetworkacl()
	require.NoError(t, err)
	pinPath, err := os.MkdirTemp("/sys/fs/bpf", "networkacl-stateful-test-")
	require.NoError(t, err)
	defer os.RemoveAll(pinPath)
	var objects bpfObjects
	require.NoError(t, spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}))
	defer objects.close()

	sandboxIP := net.ParseIP("10.88.0.2").To4()
	remoteIP := net.ParseIP("192.0.2.10").To4()
	ifindex := uint32(1)
	policy := policyV2Value{
		Generation: 1, SandboxIP: ipv4Value(sandboxIP), TrafficEnabled: 1,
		IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
		Mode: policyModeStateful,
	}
	policy.RuleCount = 2
	policy.Rules[0] = policyV2Rule{
		Priority: defaultRulePriority, Directions: directionIngress, Protocol: 6,
		SandboxPortFirst: 50090, SandboxPortLast: 50090,
		MatchFlags: ruleMatchPeerAny, Action: actionAllow,
	}
	policy.Rules[1] = policyV2Rule{
		PeerIP: ipv4Value(remoteIP), PeerPrefix: 32, Priority: defaultRulePriority,
		PeerPortFirst: 443, PeerPortLast: 443, Directions: directionEgress,
		Protocol: 6, Action: actionAllow,
	}
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))

	syn := makeTCPPacketWithFlags(remoteIP, sandboxIP, 32000, 50090, 0x02)
	ret, _, err := objects.IngressProgram.Test(syn)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	synACK := makeTCPPacketWithFlags(sandboxIP, remoteIP, 50090, 32000, 0x12)
	ret, _, err = objects.EgressProgram.Test(synACK)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret, "state permits the reverse leg")

	unrelated := makeTCPPacketWithFlags(sandboxIP, remoteIP, 50091, 32000, 0x12)
	ret, _, err = objects.EgressProgram.Test(unrelated)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)

	outboundSYN := makeTCPPacketWithFlags(sandboxIP, remoteIP, 50091, 443, 0x02)
	ret, _, err = objects.EgressProgram.Test(outboundSYN)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	pathMTU := makeICMPError(remoteIP, sandboxIP, 3, 4, outboundSYN)
	ret, _, err = objects.IngressProgram.Test(pathMTU)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret, "related ICMP accepts the minimum quoted TCP header")

	policy.Generation = 2
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(synACK)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "a policy generation change invalidates old state")

	policy.Generation = 3
	policy.RuleCount = 1
	policy.Rules[0] = policyV2Rule{
		PeerIP: ipv4Value(remoteIP), PeerPrefix: 32, Priority: defaultRulePriority,
		PeerPortFirst: 9000, PeerPortLast: 9000, Directions: directionEgress,
		Protocol: 17, Action: actionAllow,
	}
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	first := makeUDPFragment(sandboxIP, remoteIP, 32000, 9000, 77, 0, true)
	ret, _, err = objects.EgressProgram.Test(first)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	second := makeUDPFragment(sandboxIP, remoteIP, 0, 0, 77, 1, false)
	ret, _, err = objects.EgressProgram.Test(second)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret, "a later fragment follows its allowed first fragment")
	unknown := makeUDPFragment(sandboxIP, remoteIP, 0, 0, 78, 1, false)
	ret, _, err = objects.EgressProgram.Test(unknown)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret, "an out-of-order fragment fails closed")
}

func TestIntegrationStagesV2PolicyBeforePartialAttach(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "aclstage0"},
		PeerName:  "aclstage1",
	}
	require.NoError(t, netlink.LinkAdd(veth))
	t.Cleanup(func() {
		if link, err := netlink.LinkByName("aclstage0"); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	host, err := netlink.LinkByName("aclstage0")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(host))

	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), DisableProxy: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })

	entry := persistedEntry{
		IP:         "10.88.0.2",
		HostVeth:   "aclstage0",
		IfIndex:    host.Attrs().Index,
		Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionDeny,
			EgressDefaultAction:  actionDeny,
			Mode:                 policyModeStateful,
		}},
	}
	// Force the second FilterReplace to fail after the egress program has
	// attached. The partially attached v2 program must still find a staged
	// policy rather than taking the unrestricted no-policy path.
	require.NoError(t, manager.objects.IngressProgram.Close())
	require.Error(t, manager.applyLocked(persistedEntry{}, entry))
	var active policyV2Value
	require.NoError(t, manager.objects.Policies.Lookup(uint32(entry.IfIndex), &active))
	assert.Equal(t, actionDeny, active.EgressDefaultAction)

	require.NoError(t, manager.removePolicyMapLocked(entry.IfIndex))
	require.NoError(t, manager.detachLocked(entry))
	require.NoError(t, manager.deleteDynamicStateLocked(entry.IfIndex, 0))
}

func TestIntegrationFailedV2StagingPreservesLegacyPolicy(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), DisableProxy: true, DisableAttach: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })

	ifindex := uint32(4242)
	legacy := policyValue{
		Generation: 1, SandboxIP: ipv4Value(net.ParseIP("10.88.0.2")),
		TrafficEnabled: 1, TrafficDefault: actionDeny,
	}
	require.NoError(t, manager.objects.LegacyPolicies.Update(&ifindex, &legacy, ebpf.UpdateAny))
	require.NoError(t, manager.objects.DomainPolicies.Close())

	now := time.Now()
	next := persistedEntry{
		IP: "10.88.0.2", IfIndex: int(ifindex), Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionDeny,
			Mode:                 policyModeStateful,
			Rules: []TrafficRule{{
				Action: actionAllow, Directions: []uint8{directionEgress},
				Protocol: 6, PeerDomain: "example.com", Priority: defaultRulePriority,
			}},
		}},
		DomainGrants: []persistedDomainGrant{{
			Question: "example.com", IP: "192.0.2.10",
			ExpiresAt: now.Add(time.Minute).UnixNano(), RuleIndex: 0,
		}},
	}
	require.Error(t, manager.applyLocked(persistedEntry{}, next))

	var activeV2 policyV2Value
	err = manager.objects.Policies.Lookup(&ifindex, &activeV2)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	var activeLegacy policyValue
	require.NoError(t, manager.objects.LegacyPolicies.Lookup(&ifindex, &activeLegacy))
	assert.Equal(t, actionDeny, activeLegacy.TrafficDefault)
	require.NoError(t, manager.removeLegacyPolicyMapLocked(int(ifindex)))
}

func TestIntegrationStagesDomainDeniesBeforePolicyActivation(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), DisableProxy: true, DisableAttach: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })

	ifindex := uint32(4343)
	active := policyV2Value{
		Generation: 1, SandboxIP: ipv4Value(net.ParseIP("10.88.0.2")),
		TrafficEnabled: 1, IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
	}
	require.NoError(t, manager.objects.Policies.Update(&ifindex, &active, ebpf.UpdateAny))

	// Make derived-state staging fail. The active policy map must remain on the
	// old fail-closed generation; activating generation 2 first would expose a
	// default-allow window for the domain DENY below.
	require.NoError(t, manager.objects.DomainPolicies.Close())
	now := time.Now()
	next := persistedEntry{
		IP: "10.88.0.2", IfIndex: int(ifindex), Generation: 2,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionAllow,
			Mode:                 policyModeStateful,
			Rules: []TrafficRule{{
				Action: actionDeny, Directions: []uint8{directionEgress},
				Protocol: 6, PeerDomain: "blocked.example", Priority: defaultRulePriority,
			}},
		}},
		DomainGrants: []persistedDomainGrant{{
			Question: "blocked.example", IP: "192.0.2.20",
			ExpiresAt: now.Add(time.Minute).UnixNano(), RuleIndex: 0,
		}},
	}
	require.Error(t, manager.applyLocked(persistedEntry{Generation: 1}, next))

	var retained policyV2Value
	require.NoError(t, manager.objects.Policies.Lookup(&ifindex, &retained))
	assert.Equal(t, uint64(1), retained.Generation)
	assert.Equal(t, actionDeny, retained.EgressDefaultAction)
	require.NoError(t, manager.removeV2PolicyMapLocked(int(ifindex)))
}

func TestIntegrationDomainUpdateFailureKeepsBarrier(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), DisableProxy: true, DisableAttach: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })

	ifindex := uint32(4393)
	active := policyV2Value{
		Generation: 1, SandboxIP: ipv4Value(net.ParseIP("10.88.0.2")),
		TrafficEnabled: 1, IngressDefaultAction: actionAllow, EgressDefaultAction: actionAllow,
	}
	require.NoError(t, manager.objects.Policies.Update(&ifindex, &active, ebpf.UpdateAny))
	require.NoError(t, manager.objects.DomainPolicies.Close())
	entry := persistedEntry{
		IP: "10.88.0.2", IfIndex: int(ifindex), Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionAllow,
			EgressDefaultAction:  actionAllow,
			Rules: []TrafficRule{{
				Action: actionDeny, Directions: []uint8{directionEgress},
				Protocol: 6, PeerDomain: "blocked.example", Priority: defaultRulePriority,
			}},
		}},
		DomainGrants: []persistedDomainGrant{{
			Question: "blocked.example", IP: "192.0.2.21",
			ExpiresAt: time.Now().Add(time.Minute).UnixNano(), RuleIndex: 0,
		}},
	}
	empty := entry
	empty.DomainGrants = nil
	require.Error(t, manager.applyDomainGrantsLocked(empty, entry))

	var retained policyV2Value
	require.NoError(t, manager.objects.Policies.Lookup(&ifindex, &retained))
	assert.Equal(t, uint8(1), retained.UpdateBarrier)
	assert.Equal(t, uint64(1), retained.Generation)
	require.NoError(t, manager.removeV2PolicyMapLocked(int(ifindex)))
}

func TestIntegrationSuccessfulRecoveryClearsExistingDomainBarrier(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), DisableProxy: true, DisableAttach: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })

	ifindex := uint32(4394)
	active := policyV2Value{
		Generation: 1, SandboxIP: ipv4Value(net.ParseIP("10.88.0.2")),
		TrafficEnabled: 1, IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
		UpdateBarrier: 1,
	}
	require.NoError(t, manager.objects.Policies.Update(&ifindex, &active, ebpf.UpdateAny))
	entry := persistedEntry{
		IP: "10.88.0.2", IfIndex: int(ifindex), Generation: 1,
		Policy: Policy{SchemaVersion: networkPolicySchemaV2, Traffic: &TrafficPolicy{
			IngressDefaultAction: actionDeny,
			EgressDefaultAction:  actionDeny,
		}},
	}
	require.NoError(t, manager.applyDomainGrantsLocked(entry, entry))

	var recovered policyV2Value
	require.NoError(t, manager.objects.Policies.Lookup(&ifindex, &recovered))
	assert.Zero(t, recovered.UpdateBarrier)
	assert.Equal(t, uint64(1), recovered.Generation)
	require.NoError(t, manager.removeV2PolicyMapLocked(int(ifindex)))
}

func TestIntegrationExpiredDomainGrantDeletesDataplaneKey(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), DisableProxy: true, DisableAttach: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })

	ifindex := uint32(4401)
	const generation = uint64(3)
	active := policyV2Value{
		Generation: generation, SandboxIP: ipv4Value(net.ParseIP("10.88.0.2")),
		TrafficEnabled: 1, IngressDefaultAction: actionDeny, EgressDefaultAction: actionDeny,
	}
	require.NoError(t, manager.objects.Policies.Update(&ifindex, &active, ebpf.UpdateAny))
	previous := persistedEntry{
		IP: "10.88.0.2", IfIndex: int(ifindex), Generation: generation,
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
			ExpiresAt: time.Now().Add(-time.Second).UnixNano(), RuleIndex: 0,
		}},
	}
	key := domainPolicyKey{
		Generation: generation, IfIndex: ifindex,
		PeerIP: ipv4Value(net.ParseIP("192.0.2.40")),
	}
	stale := domainPolicyValue{RuleCount: 1}
	stale.Rules[0] = domainPolicyRule{
		ExpiresAt: 1, Priority: defaultRulePriority, Protocol: 6, Action: actionAllow,
	}
	require.NoError(t, manager.objects.DomainPolicies.Update(&key, &stale, ebpf.UpdateAny))

	next := previous
	next.DomainGrants = nil
	require.NoError(t, manager.applyDomainGrantsLocked(previous, next))

	var retained domainPolicyValue
	err = manager.objects.DomainPolicies.Lookup(&key, &retained)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	require.NoError(t, manager.removeV2PolicyMapLocked(int(ifindex)))
}

func TestIntegrationDomainGrantChangeDeletesPeerDynamicState(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), DisableProxy: true, DisableAttach: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })

	const (
		ifindex    = uint32(4444)
		generation = uint64(5)
	)
	sandboxIP := ipv4Value(net.ParseIP("10.88.0.2"))
	changedPeer := ipv4Value(net.ParseIP("192.0.2.30"))
	otherPeer := ipv4Value(net.ParseIP("192.0.2.31"))
	changedConnection := connectionKey{
		Generation: generation, IfIndex: ifindex, PeerIP: changedPeer,
		PeerPort: networkPort(443), SandboxPort: networkPort(32000), Protocol: 6,
	}
	otherConnection := changedConnection
	otherConnection.PeerIP = otherPeer
	connectionState := connectionValue{ExpiresAt: ^uint64(0)}
	require.NoError(t, manager.objects.Connections.Update(&changedConnection, &connectionState, ebpf.UpdateAny))
	require.NoError(t, manager.objects.Connections.Update(&otherConnection, &connectionState, ebpf.UpdateAny))

	changedFragment := fragmentKey{
		Generation: generation, IfIndex: ifindex, SourceIP: sandboxIP,
		DestinationIP: changedPeer, Identification: 10, Protocol: 17,
		Direction: directionEgress,
	}
	otherFragment := changedFragment
	otherFragment.DestinationIP = otherPeer
	fragmentState := ^uint64(0)
	require.NoError(t, manager.objects.Fragments.Update(&changedFragment, &fragmentState, ebpf.UpdateAny))
	require.NoError(t, manager.objects.Fragments.Update(&otherFragment, &fragmentState, ebpf.UpdateAny))

	require.NoError(t, manager.deleteConnectionsForPeersLocked(
		int(ifindex), generation, map[uint32]struct{}{changedPeer: {}},
	))
	var retainedConnection connectionValue
	err = manager.objects.Connections.Lookup(&changedConnection, &retainedConnection)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	require.NoError(t, manager.objects.Connections.Lookup(&otherConnection, &retainedConnection))
	var retainedFragment uint64
	err = manager.objects.Fragments.Lookup(&changedFragment, &retainedFragment)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	require.NoError(t, manager.objects.Fragments.Lookup(&otherFragment, &retainedFragment))
}

func TestIntegrationManagerLifecycle(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "acltest0"},
		PeerName:  "acltest1",
	}
	require.NoError(t, netlink.LinkAdd(veth))
	defer func() {
		if link, err := netlink.LinkByName("acltest0"); err == nil {
			_ = netlink.LinkDel(link)
		}
	}()
	host, err := netlink.LinkByName("acltest0")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(host))

	stateStore := &failNthStore{MockStore: store.NewMockStore()}
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), Store: stateStore,
		DisableProxy: true,
	})
	require.NoError(t, err)
	policy := Policy{Traffic: &TrafficPolicy{DefaultAction: actionDeny}}
	require.NoError(t, manager.Register(Binding{
		SandboxID: "sandbox-1", IP: net.ParseIP("10.88.0.2"), HostVeth: "acltest0",
	}, policy))
	assertACLFilterCount(t, host, 2)

	// Closing with an active sandbox must preserve TC and pinned maps. This is
	// also the state left by a killed daemon: the replacement manager reopens
	// and reconciles it rather than creating a fail-open window.
	require.NoError(t, manager.Close())
	assertACLFilterCount(t, host, 2)
	restarted, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), Store: stateStore,
		DisableProxy: true,
	})
	require.NoError(t, err)
	manager = restarted
	defer manager.Close()
	require.NoError(t, manager.Restore(map[string]Binding{
		"sandbox-1": {
			SandboxID: "sandbox-1", IP: net.ParseIP("10.88.0.2"), HostVeth: "acltest0",
		},
	}))
	assertACLFilterCount(t, host, 2)
	assert.Equal(t, uint64(2), manager.entries["sandbox-1"].Generation)
	var restoredPolicy policyV2Value
	require.NoError(t, manager.objects.Policies.Lookup(uint32(host.Attrs().Index), &restoredPolicy))
	assert.Equal(t, uint64(2), restoredPolicy.Generation)

	// A failed Start rollback keeps an orphan entry. Reusing the same link is
	// allowed only after that orphan's kernel state has been cleaned and its
	// metadata has been removed durably.
	manager.mu.Lock()
	orphan := manager.entries["sandbox-1"]
	orphan.Orphaned = true
	manager.entries["sandbox-1"] = orphan
	delete(manager.sourceIndex, orphan.IP)
	persistErr := manager.persistLocked()
	manager.mu.Unlock()
	require.NoError(t, persistErr)

	// Fail the metadata-removal write after kernel cleanup. The cleanup intent
	// remains both durable and in memory for a safe retry.
	stateStore.failAt = stateStore.writes + 1
	err = manager.Register(Binding{
		SandboxID: "sandbox-2", IP: net.ParseIP("10.88.0.2"), HostVeth: "acltest0",
	}, policy)
	require.Error(t, err)
	assertACLFilterCount(t, host, 0)
	orphan = manager.entries["sandbox-1"]
	assert.True(t, orphan.Orphaned)
	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	var state persistedState
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.True(t, state.Entries["sandbox-1"].Orphaned)

	// Retry the idempotent cleanup, then fail persistence of the replacement
	// entry. The old orphan has already been removed durably and must not be
	// resurrected by the registration rollback.
	stateStore.failAt = stateStore.writes + 2
	err = manager.Register(Binding{
		SandboxID: "sandbox-2", IP: net.ParseIP("10.88.0.2"), HostVeth: "acltest0",
	}, policy)
	require.Error(t, err)
	_, oldExists := manager.entries["sandbox-1"]
	_, newExists := manager.entries["sandbox-2"]
	assert.False(t, oldExists)
	assert.False(t, newExists)
	raw, err = stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	state = persistedState{}
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.Empty(t, state.Entries)

	stateStore.failAt = 0
	require.NoError(t, manager.Register(Binding{
		SandboxID: "sandbox-2", IP: net.ParseIP("10.88.0.2"), HostVeth: "acltest0",
	}, policy))
	assertACLFilterCount(t, host, 2)

	// An empty replacement returns the sandbox to the zero-overhead path.
	require.NoError(t, manager.SetPolicy("sandbox-2", Policy{}))
	assertACLFilterCount(t, host, 0)
	var value policyV2Value
	err = manager.objects.Policies.Lookup(uint32(host.Attrs().Index), &value)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	require.NoError(t, manager.Remove("sandbox-2"))
}

func TestIntegrationCleanupIntentRetriesAfterLinkReuse(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	t.Cleanup(func() { _ = os.RemoveAll(pinRoot) })
	t.Cleanup(func() {
		if link, err := netlink.LinkByName("aclreuse0"); err == nil {
			_ = netlink.LinkDel(link)
		}
	})

	addVeth := func() netlink.Link {
		t.Helper()
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "aclreuse0"},
			PeerName:  "aclreuse1",
		}
		require.NoError(t, netlink.LinkAdd(veth))
		link, err := netlink.LinkByName("aclreuse0")
		require.NoError(t, err)
		return link
	}

	original := addVeth()
	require.NoError(t, netlink.LinkSetUp(original))
	stateStore := &failNthStore{MockStore: store.NewMockStore()}
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), Store: stateStore,
		DisableProxy: true,
	})
	require.NoError(t, err)
	managerOpen := true
	t.Cleanup(func() {
		if managerOpen {
			_ = manager.Close()
		}
	})

	policy := Policy{Traffic: &TrafficPolicy{DefaultAction: actionDeny}}
	require.NoError(t, manager.Register(Binding{
		SandboxID: "sandbox-old", IP: net.ParseIP("10.88.0.2"), HostVeth: "aclreuse0",
	}, policy))
	assertACLFilterCount(t, original, 2)

	// The cleanup intent write succeeds and kernel cleanup completes, but
	// removing the entry from durable state fails.
	stateStore.failAt = stateStore.writes + 2
	err = manager.Remove("sandbox-old")
	require.ErrorContains(t, err, "removal of cleaned network ACL state")
	assertACLFilterCount(t, original, 0)
	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	var state persistedState
	require.NoError(t, json.Unmarshal(raw, &state))
	stored := state.Entries["sandbox-old"]
	assert.True(t, stored.Orphaned)

	require.NoError(t, manager.Close())
	managerOpen = false
	stateStore.failAt = 0
	require.NoError(t, netlink.LinkDel(original))

	replacement := addVeth()
	require.NoError(t, netlink.LinkSetUp(replacement))
	replacement, err = netlink.LinkByName("aclreuse0")
	require.NoError(t, err)

	// Model kernel ifindex reuse in durable ACL state.
	stored.IfIndex = replacement.Attrs().Index
	state.Entries["sandbox-old"] = stored
	raw, err = json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, stateStore.StoreRaw(stateStoreKey, raw))

	manager, err = New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), Store: stateStore,
		DisableProxy: true,
	})
	require.NoError(t, err)
	managerOpen = true

	// A replacement veth may already carry unrelated TC state. Reconciliation
	// must remove only sandboxd's reserved filters, leaving foreign filters
	// untouched while it idempotently retries map and rule cleanup.
	_, err = ensureClsact(replacement)
	require.NoError(t, err)
	foreign := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: replacement.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 0xd1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority + 1,
		},
		Fd:           manager.objects.EgressProgram.FD(),
		Name:         "foreign_filter",
		DirectAction: true,
	}
	require.NoError(t, netlink.FilterReplace(foreign))
	assertNamedFilterCount(t, replacement, netlink.HANDLE_MIN_INGRESS, "foreign_filter", 1)

	require.NoError(t, manager.Restore(map[string]Binding{}))
	assertNamedFilterCount(t, replacement, netlink.HANDLE_MIN_INGRESS, "foreign_filter", 1)
	raw, err = stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	state = persistedState{}
	require.NoError(t, json.Unmarshal(raw, &state))
	assert.Empty(t, state.Entries)
}

func TestIntegrationRestorePreservesOrphanWhenKernelCleanupFails(t *testing.T) {
	require.NoError(t, ensureBPFFS())
	_ = os.RemoveAll(pinRoot)
	stateStore := store.NewMockStore()
	manager, err := New(Config{
		BridgeIP: net.ParseIP("10.88.0.1"), Store: stateStore,
		DisableProxy: true, DisableAttach: true,
	})
	require.NoError(t, err)
	defer func() {
		_ = manager.Close()
		_ = os.RemoveAll(pinRoot)
	}()

	manager.mu.Lock()
	manager.entries["orphan"] = persistedEntry{
		IP: "10.88.0.2", HostVeth: "acl-orphan", IfIndex: 123456,
		Orphaned: true,
	}
	require.NoError(t, manager.persistLocked())
	manager.mu.Unlock()

	// A closed rule map deterministically makes cleanup fail without relying on
	// a particular netlink error. Restore must keep the orphan both in memory
	// and in the store so a later startup can retry.
	require.NoError(t, manager.objects.LegacyRules.Close())
	require.Error(t, manager.Restore(map[string]Binding{}))

	manager.mu.RLock()
	orphan, exists := manager.entries["orphan"]
	manager.mu.RUnlock()
	require.True(t, exists)
	assert.True(t, orphan.Orphaned)

	raw, err := stateStore.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	var state persistedState
	require.NoError(t, json.Unmarshal(raw, &state))
	stored, exists := state.Entries["orphan"]
	require.True(t, exists)
	assert.True(t, stored.Orphaned)
}

func assertACLFilterCount(t *testing.T, link netlink.Link, expected int) {
	t.Helper()
	count := 0
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		require.NoError(t, err)
		for _, candidate := range filters {
			if filter, ok := candidate.(*netlink.BpfFilter); ok &&
				(filter.Name == "sd_acl_out" || filter.Name == "sd_acl_in") {
				count++
			}
		}
	}
	assert.Equal(t, expected, count)
}

func assertNamedFilterCount(t *testing.T, link netlink.Link, parent uint32, name string, expected int) {
	t.Helper()
	filters, err := netlink.FilterList(link, parent)
	require.NoError(t, err)
	count := 0
	for _, candidate := range filters {
		if filter, ok := candidate.(*netlink.BpfFilter); ok && filter.Name == name {
			count++
		}
	}
	assert.Equal(t, expected, count)
}

func TestIntegrationDNSProxy(t *testing.T) {
	upstreamUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})
	require.NoError(t, err)
	defer upstreamUDP.Close()
	upstreamTCP, err := net.Listen("tcp4", "127.0.0.1:53")
	require.NoError(t, err)
	defer upstreamTCP.Close()
	var upstreamCalls atomic.Int32
	go serveTestDNSUDP(upstreamUDP, &upstreamCalls)
	go serveTestDNSTCP(upstreamTCP, &upstreamCalls)

	resolver, err := os.CreateTemp("", "networkacl-resolv-")
	require.NoError(t, err)
	defer os.Remove(resolver.Name())
	_, err = resolver.WriteString("nameserver 127.0.0.1\n")
	require.NoError(t, err)
	require.NoError(t, resolver.Close())
	proxy, err := newDNSProxy(
		net.ParseIP("127.0.0.2"),
		resolver.Name(),
		1,
		1,
		func(source net.IP, names []string) bool {
			if !source.Equal(net.ParseIP("127.0.0.1")) {
				return false
			}
			for _, name := range names {
				if name == "blocked.example." {
					return false
				}
			}
			return true
		},
		nil,
	)
	require.NoError(t, err)
	defer proxy.close()

	allowed := makeDNSQuery(t, "allowed.example.")
	for range 2 {
		response := exchangeTestDNSUDP(t, allowed)
		header, _, _, err := parseDNSQuestions(response)
		require.NoError(t, err)
		assert.True(t, header.Response)
		assert.Equal(t, dnsmessage.RCodeSuccess, header.RCode)
	}
	assert.Equal(t, int32(2), upstreamCalls.Load(), "proxy must not cache DNS answers")

	blocked := exchangeTestDNSUDP(t, makeDNSQuery(t, "blocked.example."))
	header, _, _, err := parseDNSQuestions(blocked)
	require.NoError(t, err)
	assert.Equal(t, dnsmessage.RCodeRefused, header.RCode)
	assert.Equal(t, int32(2), upstreamCalls.Load(), "blocked query must not reach upstream")

	connection, err := net.DialTimeout("tcp4", "127.0.0.2:53", time.Second)
	require.NoError(t, err)
	defer connection.Close()
	require.NoError(t, writeDNSFrame(connection, allowed))
	_, err = readDNSFrame(connection)
	require.NoError(t, err)
	assert.Equal(t, int32(3), upstreamCalls.Load())

	// The open TCP session owns the single concurrency slot, so UDP overload
	// is rejected without allocating an upstream socket.
	overloaded := exchangeTestDNSUDP(t, allowed)
	header, _, _, err = parseDNSQuestions(overloaded)
	require.NoError(t, err)
	assert.Equal(t, dnsmessage.RCodeServerFailure, header.RCode)
	assert.Equal(t, int32(3), upstreamCalls.Load())
}

func makeDNSQuery(t *testing.T, name string) []byte {
	t.Helper()
	dnsName, err := dnsmessage.NewName(name)
	require.NoError(t, err)
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	payload, err := message.Pack()
	require.NoError(t, err)
	return payload
}

func exchangeTestDNSUDP(t *testing.T, payload []byte) []byte {
	t.Helper()
	connection, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 53})
	require.NoError(t, err)
	defer connection.Close()
	require.NoError(t, connection.SetDeadline(time.Now().Add(time.Second)))
	_, err = connection.Write(payload)
	require.NoError(t, err)
	response := make([]byte, 65535)
	n, err := connection.Read(response)
	require.NoError(t, err)
	return response[:n]
}

func serveTestDNSUDP(connection *net.UDPConn, calls *atomic.Int32) {
	buffer := make([]byte, 65535)
	for {
		n, source, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		calls.Add(1)
		response := append([]byte(nil), buffer[:n]...)
		response[2] |= 0x80
		_, _ = connection.WriteToUDP(response, source)
	}
}

func serveTestDNSTCP(listener net.Listener, calls *atomic.Int32) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			reader := bufio.NewReader(connection)
			request, err := readDNSFrame(reader)
			if err != nil {
				return
			}
			calls.Add(1)
			request[2] |= 0x80
			_ = writeDNSFrame(connection, request)
		}()
	}
}

func makeTCPPacket(source, destination net.IP, sourcePort, destinationPort uint16) []byte {
	return makeTCPPacketWithFlags(source, destination, sourcePort, destinationPort, 0)
}

func makeTCPPacketWithFlags(source, destination net.IP, sourcePort, destinationPort uint16, flags byte) []byte {
	packet := makeIPv4Packet(source, destination, 6, 20)
	binary.BigEndian.PutUint16(packet[34:36], sourcePort)
	binary.BigEndian.PutUint16(packet[36:38], destinationPort)
	packet[46] = 0x50 // TCP data offset.
	packet[47] = flags
	return packet
}

func makeUDPFragment(source, destination net.IP, sourcePort, destinationPort, id, offset uint16, more bool) []byte {
	packet := makeUDPPacket(source, destination, sourcePort, destinationPort)
	binary.BigEndian.PutUint16(packet[18:20], id)
	fragment := offset & 0x1fff
	if more {
		fragment |= 0x2000
	}
	binary.BigEndian.PutUint16(packet[20:22], fragment)
	return packet
}

func makeUDPPacket(source, destination net.IP, sourcePort, destinationPort uint16) []byte {
	packet := makeIPv4Packet(source, destination, 17, 8)
	binary.BigEndian.PutUint16(packet[34:36], sourcePort)
	binary.BigEndian.PutUint16(packet[36:38], destinationPort)
	binary.BigEndian.PutUint16(packet[38:40], 8)
	return packet
}

func makeIPv4Packet(source, destination net.IP, protocol uint8, transportSize int) []byte {
	packet := make([]byte, 14+20+transportSize)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14] = 0x45
	binary.BigEndian.PutUint16(packet[16:18], uint16(20+transportSize))
	packet[22] = 64
	packet[23] = protocol
	copy(packet[26:30], source.To4())
	copy(packet[30:34], destination.To4())
	return packet
}

func makeIPv6Packet(nextHeader uint8) []byte {
	packet := make([]byte, 14+40)
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	packet[14] = 0x60
	packet[20] = nextHeader
	packet[21] = 64
	return packet
}

func makeICMPError(source, destination net.IP, kind, code byte, quoted []byte) []byte {
	const quotedSize = 20 + 8
	packet := makeIPv4Packet(source, destination, 1, 8+quotedSize)
	packet[34] = kind
	packet[35] = code
	copy(packet[42:], quoted[14:14+quotedSize])
	return packet
}
