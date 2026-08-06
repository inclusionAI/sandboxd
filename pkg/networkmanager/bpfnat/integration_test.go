//go:build linux && bpfnat_integration

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

package bpfnat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	testEthernetHeaderSize = 14
	testIPv4HeaderSize     = 20
	testUDPHeaderSize      = 8
	testTCActionShot       = 2
)

func TestIntegrationDataplane(t *testing.T) {
	for _, mode := range []gcMode{gcModeUserspace, gcModeBPFTimer} {
		t.Run(string(mode), func(t *testing.T) {
			testIntegrationDataplane(t, mode)
		})
	}
}

func testIntegrationDataplane(t *testing.T, mode gcMode) {
	requireBPFFS(t)
	require.NoError(t, rlimit.RemoveMemlock())

	pins := integrationPinPath("dataplane-" + string(mode))
	objects := loadIntegrationObjects(t, pins, mode)
	defer cleanupIntegrationObjects(t, &objects, pins)

	sandboxIP := [4]byte{10, 250, 0, 2}
	secondSandboxIP := [4]byte{10, 250, 0, 3}
	nodeIP := [4]byte{192, 0, 2, 1}
	remoteIP := [4]byte{203, 0, 113, 2}
	policy, err := makeEgressPolicy("10.250.0.0/16")
	require.NoError(t, err)
	require.NoError(t, objects.EgressPolicies.Put(policy, nodeIP))
	configureTestPortRange(t, objects.SNATConfig, 30001, 65536)

	bypass := makeUDPPacket([4]byte{172, 16, 0, 2}, remoteIP, 32000, 53)
	_, bypassOut, err := objects.EgressProgram.Test(bypass)
	require.NoError(t, err)
	assert.Equal(t, bypass, bypassOut[:len(bypass)])
	assert.Equal(t, 0, mappingCount(t, objects.SNATMappings))

	outbound := makeUDPPacket(sandboxIP, remoteIP, 32000, 53)
	ret, translated, err := objects.EgressProgram.Test(outbound)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	assert.Equal(t, nodeIP[:], translated[26:30])
	assert.Equal(t, uint16(32000), binary.BigEndian.Uint16(translated[34:36]))
	assert.Equal(t, 2, mappingCount(t, objects.SNATMappings))

	reply := makeUDPPacket(remoteIP, nodeIP, 53, 32000)
	ret, restored, err := objects.IngressProgram.Test(reply)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	assert.Equal(t, sandboxIP[:], restored[30:34])
	assert.Equal(t, uint16(32000), binary.BigEndian.Uint16(restored[36:38]))

	reservedPortKey := uint32(32001)<<16 | uint32(protocolUDP)
	one := uint8(1)
	require.NoError(t, objects.HostPorts.Put(reservedPortKey, one))
	reservedOutbound := makeUDPPacket(sandboxIP, remoteIP, 32001, 53)
	_, reservedTranslated, err := objects.EgressProgram.Test(reservedOutbound)
	require.NoError(t, err)
	allocatedPort := binary.BigEndian.Uint16(reservedTranslated[34:36])
	assert.NotEqual(t, uint16(32001), allocatedPort)
	assert.GreaterOrEqual(t, allocatedPort, uint16(30001))
	assert.Equal(t, nodeIP[:], reservedTranslated[26:30])

	reservedReply := makeUDPPacket(remoteIP, nodeIP, 53, allocatedPort)
	_, reservedRestored, err := objects.IngressProgram.Test(reservedReply)
	require.NoError(t, err)
	assert.Equal(t, sandboxIP[:], reservedRestored[30:34])
	assert.Equal(t, uint16(32001), binary.BigEndian.Uint16(reservedRestored[36:38]))

	dnatKey, dnatValue, err := makeDNATRule("udp", 8080, net.IP(secondSandboxIP[:]).String(), 8081)
	require.NoError(t, err)
	require.NoError(t, objects.DNATRules.Put(dnatKey, dnatValue))
	incoming := makeUDPPacket(remoteIP, nodeIP, 40000, 8080)
	_, dnatTranslated, err := objects.IngressProgram.Test(incoming)
	require.NoError(t, err)
	assert.Equal(t, secondSandboxIP[:], dnatTranslated[30:34])
	assert.Equal(t, uint16(8081), binary.BigEndian.Uint16(dnatTranslated[36:38]))

	dnatReply := makeUDPPacket(secondSandboxIP, remoteIP, 8081, 40000)
	_, dnatRestored, err := objects.EgressProgram.Test(dnatReply)
	require.NoError(t, err)
	assert.Equal(t, nodeIP[:], dnatRestored[26:30])
	assert.Equal(t, uint16(8080), binary.BigEndian.Uint16(dnatRestored[34:36]))
	assert.Equal(t, 6, mappingCount(t, objects.SNATMappings))

	// Exhaust the only configured allocation port. The packet must be
	// rejected without leaving a half-created mapping.
	configureTestPortRange(t, objects.SNATConfig, 40000, 40001)
	exhaustedPortKey := uint32(40000)<<16 | uint32(protocolUDP)
	require.NoError(t, objects.HostPorts.Put(exhaustedPortKey, one))
	exhausted := makeUDPPacket(sandboxIP, [4]byte{203, 0, 113, 3}, 40000, 53)
	ret, _, err = objects.EgressProgram.Test(exhausted)
	require.NoError(t, err)
	assert.Equal(t, uint32(testTCActionShot), ret)
	assert.Equal(t, 6, mappingCount(t, objects.SNATMappings))

	// Use a complete IPv6-sized frame. Newer kernels reject undersized
	// SCHED_CLS test-run packets before the program can exercise its
	// non-IPv4 bypass path.
	nonIPv4 := make([]byte, testEthernetHeaderSize+40)
	binary.BigEndian.PutUint16(nonIPv4[12:14], unix.ETH_P_IPV6)
	nonIPv4[testEthernetHeaderSize] = 0x60
	_, nonIPv4Out, err := objects.EgressProgram.Test(nonIPv4)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(nonIPv4, nonIPv4Out[:len(nonIPv4)]))
	assert.Equal(t, 6, mappingCount(t, objects.SNATMappings))
}

func TestIntegrationBPFTimerExpiry(t *testing.T) {
	mode, err := selectGCMode(nil)
	require.NoError(t, err)
	if mode != gcModeBPFTimer {
		t.Skip("running kernel does not support the required BPF timer helpers")
	}
	requireBPFFS(t)
	require.NoError(t, rlimit.RemoveMemlock())

	pins := integrationPinPath("timer-expiry")
	objects := loadIntegrationObjects(t, pins, gcModeBPFTimer)
	defer cleanupIntegrationObjects(t, &objects, pins)

	sandboxIP := [4]byte{10, 250, 0, 2}
	nodeIP := [4]byte{192, 0, 2, 1}
	remoteIP := [4]byte{203, 0, 113, 2}
	policy, err := makeEgressPolicy("10.250.0.0/16")
	require.NoError(t, err)
	require.NoError(t, objects.EgressPolicies.Put(policy, nodeIP))
	configureTestPortRange(t, objects.SNATConfig, 30001, 65536)
	timeoutKey, timeout := uint32(0), uint32(1)
	require.NoError(t, objects.SNATConfig.Put(timeoutKey, timeout))

	packet := makeUDPPacket(sandboxIP, remoteIP, 32000, 53)
	ret, _, err := objects.EgressProgram.Test(packet)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)

	dnatKey, dnatValue, err := makeDNATRule("udp", 8080, "10.250.0.3", 8081)
	require.NoError(t, err)
	require.NoError(t, objects.DNATRules.Put(dnatKey, dnatValue))
	incoming := makeUDPPacket(remoteIP, nodeIP, 40000, 8080)
	ret, _, err = objects.IngressProgram.Test(incoming)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), ret)
	assert.Equal(t, 4, mappingCount(t, objects.SNATMappings))
	require.Eventually(t, func() bool {
		return mappingCount(t, objects.SNATMappings) == 0
	}, 5*time.Second, 20*time.Millisecond)
}

func TestIntegrationUserspaceGC(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())
	mappings := newIntegrationMap(t, &ebpf.MapSpec{
		Name:       "sd_gc_test",
		Type:       ebpf.Hash,
		KeySize:    uint32(binary.Size(ipv4Tuple{})),
		ValueSize:  uint32(binary.Size(ipv4NATEntry{})),
		MaxEntries: 16,
	})
	defer mappings.Close()
	cfg := newIntegrationMap(t, &ebpf.MapSpec{
		Name:       "sd_gc_cfg",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4,
	})
	defer cfg.Close()

	timeoutKey, timeout := uint32(0), uint32(2)
	require.NoError(t, cfg.Put(timeoutKey, timeout))
	now, err := bootTimeSeconds()
	require.NoError(t, err)

	staleUDP := ipv4Tuple{SourceAddr: 1, DestAddr: 2, SourcePort: 31000, DestPort: 53, Protocol: protocolUDP, Flags: natDirEgress}
	putMappingPair(t, mappings, staleUDP, ipv4NATEntry{TargetAddr: 3, TargetPort: 61000, LastAccessTime: now - timeout - 1, Type: natTypeSNAT})
	staleClosedTCP := ipv4Tuple{SourceAddr: 1, DestAddr: 4, SourcePort: 31001, DestPort: 443, Protocol: protocolTCP, Flags: natDirEgress}
	putMappingPair(t, mappings, staleClosedTCP, ipv4NATEntry{TargetAddr: 3, TargetPort: 61001, LastAccessTime: now - defaultTimeoutTCPClose - 1, Status: ctClose, Type: natTypeSNAT})
	freshUDP := ipv4Tuple{SourceAddr: 1, DestAddr: 5, SourcePort: 31002, DestPort: 53, Protocol: protocolUDP, Flags: natDirEgress}
	freshEntry := ipv4NATEntry{TargetAddr: 3, TargetPort: 61002, LastAccessTime: now, Type: natTypeSNAT}
	putMappingPair(t, mappings, freshUDP, freshEntry)
	assert.Equal(t, 6, mappingCount(t, mappings))

	stop := make(chan struct{})
	done := make(chan struct{})
	go (&Manager{}).runGCWithInterval(stop, done, mappings, cfg, 20*time.Millisecond)
	defer func() {
		close(stop)
		<-done
	}()

	require.Eventually(t, func() bool {
		return !mappingExists(t, mappings, staleUDP) && !mappingExists(t, mappings, staleClosedTCP)
	}, 2*time.Second, 20*time.Millisecond)
	assert.False(t, mappingExists(t, mappings, reverseTuple(staleUDP, ipv4NATEntry{TargetAddr: 3, TargetPort: 61000, Type: natTypeSNAT})))
	assert.False(t, mappingExists(t, mappings, reverseTuple(staleClosedTCP, ipv4NATEntry{TargetAddr: 3, TargetPort: 61001, Type: natTypeSNAT})))
	assert.True(t, mappingExists(t, mappings, freshUDP))
	assert.True(t, mappingExists(t, mappings, reverseTuple(freshUDP, freshEntry)))
	assert.Equal(t, 2, mappingCount(t, mappings))
}

func TestIntegrationPinnedMapReload(t *testing.T) {
	requireBPFFS(t)
	require.NoError(t, rlimit.RemoveMemlock())
	pins := integrationPinPath("reload")
	first := loadIntegrationObjects(t, pins, gcModeUserspace)

	now, err := bootTimeSeconds()
	require.NoError(t, err)
	original := ipv4Tuple{SourceAddr: 1, DestAddr: 2, SourcePort: 31000, DestPort: 53, Protocol: protocolUDP, Flags: natDirEgress}
	entry := ipv4NATEntry{TargetAddr: 3, TargetPort: 61000, LastAccessTime: now - defaultTimeoutNonTCP - 1, Type: natTypeSNAT}
	putMappingPair(t, first.SNATMappings, original, entry)
	require.NoError(t, first.close())

	second := loadIntegrationObjects(t, pins, gcModeUserspace)
	defer cleanupIntegrationObjects(t, &second, pins)
	assert.True(t, mappingExists(t, second.SNATMappings, original))
	require.NoError(t, collectExpired(second.SNATMappings, second.SNATConfig))
	assert.False(t, mappingExists(t, second.SNATMappings, original))
	assert.False(t, mappingExists(t, second.SNATMappings, reverseTuple(original, entry)))
}

func TestIntegrationManagerLifecycle(t *testing.T) {
	requireBPFFS(t)
	require.NoError(t, rlimit.RemoveMemlock())
	require.NoError(t, os.RemoveAll(filepath.Dir(pinRoot)))

	external := addIntegrationDummy(t, "sd-bpf-ext0", "192.0.2.1/24")
	bridge := addIntegrationBridge(t, networkmanager.BridgeName, "10.250.0.1/16")
	loopback, err := netlink.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(loopback))

	expectedMode, err := selectGCMode(nil)
	require.NoError(t, err)
	t.Run("automatic", func(t *testing.T) {
		testIntegrationManagerLifecycle(t, external, bridge, loopback, nil, expectedMode)
	})
	t.Run("userspace-fallback", func(t *testing.T) {
		testIntegrationManagerLifecycle(t, external, bridge, loopback,
			func(ebpf.ProgramType, asm.BuiltinFunc) error { return ebpf.ErrNotSupported },
			gcModeUserspace)
	})

	require.NoError(t, netlink.LinkDel(bridge))
	rollback := &Manager{
		probeProgramHelper: func(ebpf.ProgramType, asm.BuiltinFunc) error {
			return ebpf.ErrNotSupported
		},
	}
	require.NoError(t, rollback.Configure(networkmanager.BackendConfig{Device: external.Attrs().Name, EnableLocalDNAT: true}))
	err = rollback.SetupSNATRules("10.250.0.1/16")
	require.ErrorContains(t, err, "find sandbox bridge")
	assert.False(t, rollback.initialized)
	_, statErr := os.Stat(pinPathForMode(gcModeUserspace))
	require.ErrorIs(t, statErr, os.ErrNotExist)
	assertFilterMissing(t, external, netlink.HANDLE_MIN_INGRESS, physicalIngressHandle)
	assertFilterMissing(t, external, netlink.HANDLE_MIN_EGRESS, physicalEgressHandle)
}

func testIntegrationManagerLifecycle(
	t *testing.T,
	external, bridge, loopback netlink.Link,
	probe programHelperProbe,
	expectedMode gcMode,
) {
	t.Helper()
	manager := &Manager{probeProgramHelper: probe}
	require.NoError(t, manager.Configure(networkmanager.BackendConfig{Device: external.Attrs().Name, EnableLocalDNAT: true}))
	require.NoError(t, manager.SetupSNATRules("10.250.0.1/16"))
	assert.True(t, manager.initialized)
	assert.Equal(t, expectedMode, manager.gcMode)
	assert.Equal(t, pinPathForMode(expectedMode), manager.pinPath)
	if expectedMode == gcModeUserspace {
		assert.NotNil(t, manager.gcStop)
		assert.NotNil(t, manager.gcDone)
	} else {
		assert.Nil(t, manager.gcStop)
		assert.Nil(t, manager.gcDone)
	}
	assert.Len(t, manager.attachments, 4)
	for _, name := range []string{"SNAT_MAPPING_IPV4", "EGRESS_POLICY_MAP", "DNAT_RULES_MAP", "SNAT_CONFIG_MAP", "POD_PORT_MAP", "LOCAL_REDIRECT_MAP"} {
		_, err := os.Stat(filepath.Join(manager.pinPath, name))
		require.NoError(t, err)
	}

	redirectKey := uint32(0)
	var redirectIfindex uint32
	require.NoError(t, manager.objects.LocalRedirect.Lookup(redirectKey, &redirectIfindex))
	assert.Equal(t, uint32(bridge.Attrs().Index), redirectIfindex)
	require.NoError(t, manager.SetupSNATRules("10.250.0.1/16"))
	require.ErrorContains(t, manager.SetupSNATRules("10.251.0.1/16"), "already manages IP range")
	require.ErrorContains(t, manager.Configure(networkmanager.BackendConfig{Device: external.Attrs().Name}), "different configuration")

	require.NoError(t, manager.SetupDNATRule("tcp", 21008, "10.250.0.2", 50090))
	require.NoError(t, manager.SetupDNATRule("tcp", 21008, "10.250.0.2", 50090))
	require.ErrorContains(t, manager.SetupDNATRule("tcp", 21008, "10.250.0.3", 50090), "already targets")
	require.NoError(t, manager.SetupLocalDNATRule("tcp", 21008, "10.250.0.2", 50090))
	require.NoError(t, manager.CleanupDNATRule("tcp", 21008, "10.250.0.3", 50090))
	dnatKey, _, err := makeDNATRule("tcp", 21008, "10.250.0.2", 50090)
	require.NoError(t, err)
	var dnatValue [8]byte
	require.NoError(t, manager.objects.DNATRules.Lookup(dnatKey, &dnatValue))
	require.NoError(t, manager.CleanupDNATRule("tcp", 21008, "10.250.0.2", 50090))
	require.ErrorIs(t, manager.objects.DNATRules.Lookup(dnatKey, &dnatValue), ebpf.ErrKeyNotExist)

	pins := manager.pinPath
	require.NoError(t, manager.CleanupSNATRules("10.250.0.1/16"))
	assert.False(t, manager.initialized)
	_, err = os.Stat(pins)
	require.ErrorIs(t, err, os.ErrNotExist)
	assertFilterMissing(t, external, netlink.HANDLE_MIN_INGRESS, physicalIngressHandle)
	assertFilterMissing(t, external, netlink.HANDLE_MIN_EGRESS, physicalEgressHandle)
	assertFilterMissing(t, bridge, netlink.HANDLE_MIN_INGRESS, bridgeIngressHandle)
	assertFilterMissing(t, loopback, netlink.HANDLE_MIN_INGRESS, localIngressHandle)
	require.NoError(t, manager.CleanupSNATRules("10.250.0.1/16"))
}

func requireBPFFS(t *testing.T) {
	t.Helper()
	require.NoError(t, ensureBPFFS())
}

func integrationPinPath(name string) string {
	return filepath.Join(bpffsRoot, fmt.Sprintf("sandboxd-test-%d-%s", os.Getpid(), name))
}

func loadIntegrationObjects(t *testing.T, pins string, mode gcMode) bpfObjects {
	t.Helper()
	require.NoError(t, os.MkdirAll(pins, 0700))
	spec, err := loadEmbeddedSpec(mode)
	require.NoError(t, err)
	var objects bpfObjects
	require.NoError(t, spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pins}}))
	return objects
}

func cleanupIntegrationObjects(t *testing.T, objects *bpfObjects, pins string) {
	t.Helper()
	for _, m := range []*ebpf.Map{objects.SNATMappings, objects.EgressPolicies, objects.DNATRules, objects.SNATConfig, objects.HostPorts, objects.LocalRedirect} {
		if m != nil {
			require.NoError(t, m.Unpin())
		}
	}
	require.NoError(t, objects.close())
	require.NoError(t, os.RemoveAll(pins))
}

func configureTestPortRange(t *testing.T, cfg *ebpf.Map, min, max uint32) {
	t.Helper()
	minKey, maxKey := uint32(1), uint32(2)
	require.NoError(t, cfg.Put(minKey, min))
	require.NoError(t, cfg.Put(maxKey, max))
}

func newIntegrationMap(t *testing.T, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(spec)
	require.NoError(t, err)
	return m
}

func putMappingPair(t *testing.T, mappings *ebpf.Map, tuple ipv4Tuple, entry ipv4NATEntry) {
	t.Helper()
	require.NoError(t, mappings.Put(tuple, entry))
	require.NoError(t, mappings.Put(reverseTuple(tuple, entry), ipv4NATEntry{Type: entry.Type}))
}

func mappingExists(t *testing.T, mappings *ebpf.Map, tuple ipv4Tuple) bool {
	t.Helper()
	var entry ipv4NATEntry
	err := mappings.Lookup(tuple, &entry)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	require.NoError(t, err)
	return true
}

func mappingCount(t *testing.T, mappings *ebpf.Map) int {
	t.Helper()
	iter := mappings.Iterate()
	var tuple ipv4Tuple
	entry := make([]byte, mappings.ValueSize())
	count := 0
	for iter.Next(&tuple, &entry) {
		count++
	}
	require.NoError(t, iter.Err())
	return count
}

func addIntegrationDummy(t *testing.T, name, cidr string) netlink.Link {
	t.Helper()
	deleteIntegrationLink(name)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	require.NoError(t, netlink.LinkAdd(link))
	t.Cleanup(func() { deleteIntegrationLink(name) })
	require.NoError(t, addIntegrationAddress(link, cidr))
	require.NoError(t, netlink.LinkSetUp(link))
	return link
}

func addIntegrationBridge(t *testing.T, name, cidr string) netlink.Link {
	t.Helper()
	deleteIntegrationLink(name)
	link := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}
	require.NoError(t, netlink.LinkAdd(link))
	t.Cleanup(func() { deleteIntegrationLink(name) })
	require.NoError(t, addIntegrationAddress(link, cidr))
	require.NoError(t, netlink.LinkSetUp(link))
	return link
}

func addIntegrationAddress(link netlink.Link, cidr string) error {
	address, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(link, address)
}

func deleteIntegrationLink(name string) {
	link, err := netlink.LinkByName(name)
	if err == nil {
		_ = netlink.LinkDel(link)
	}
}

func assertFilterMissing(t *testing.T, link netlink.Link, parent uint32, handle uint16) {
	t.Helper()
	filters, err := netlink.FilterList(link, parent)
	require.NoError(t, err)
	wanted := netlink.MakeHandle(0, handle)
	for _, filter := range filters {
		assert.NotEqual(t, wanted, filter.Attrs().Handle)
	}
}

func makeUDPPacket(source, destination [4]byte, sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, testEthernetHeaderSize+testIPv4HeaderSize+testUDPHeaderSize)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)

	ip := packet[testEthernetHeaderSize : testEthernetHeaderSize+testIPv4HeaderSize]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], testIPv4HeaderSize+testUDPHeaderSize)
	ip[8] = 64
	ip[9] = protocolUDP
	copy(ip[12:16], source[:])
	copy(ip[16:20], destination[:])
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))

	udp := packet[testEthernetHeaderSize+testIPv4HeaderSize:]
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], testUDPHeaderSize)
	return packet
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
