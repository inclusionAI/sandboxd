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
	policy := policyValue{
		Generation: 1, SandboxIP: ipv4Value(sandboxIP),
		TrafficEnabled: 1, TrafficDefault: actionDeny,
	}
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	allowProxy := ruleKey{
		Generation: 1, IfIndex: ifindex, PeerIP: ipv4Value(proxyIP),
		PeerPort: networkPort(8080), Direction: directionEgress, Protocol: 6,
	}
	allow := actionAllow
	require.NoError(t, objects.Rules.Update(&allowProxy, &allow, ebpf.UpdateAny))

	ret, _, err := objects.EgressProgram.Test(makeTCPPacket(sandboxIP, proxyIP, 32000, 8080))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	ret, _, err = objects.EgressProgram.Test(makeTCPPacket(sandboxIP, remoteIP, 32000, 443))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)

	// A broader deny wins over the exact allow.
	denyProxy := allowProxy
	denyProxy.PeerPort = 0
	deny := actionDeny
	require.NoError(t, objects.Rules.Update(&denyProxy, &deny, ebpf.UpdateAny))
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

	// DNS-only policy must fail closed for IPv6 rather than allowing a direct
	// query to an IPv6 resolver that bypasses sandbox0:53.
	policy.TrafficEnabled = 0
	require.NoError(t, objects.Policies.Update(&ifindex, &policy, ebpf.UpdateAny))
	ret, _, err = objects.EgressProgram.Test(makeIPv6Packet(17))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), ret)
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
	var value policyValue
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
	require.NoError(t, manager.objects.Rules.Close())
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
	packet := makeIPv4Packet(source, destination, 6, 20)
	binary.BigEndian.PutUint16(packet[34:36], sourcePort)
	binary.BigEndian.PutUint16(packet[36:38], destinationPort)
	packet[46] = 0x50 // TCP data offset.
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
