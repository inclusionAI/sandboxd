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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireSysctlAcceptsExpectedValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl")
	require.NoError(t, os.WriteFile(path, []byte("1\n"), 0644))

	require.NoError(t, requireSysctl(path, "net.ipv4.ip_forward", "1"))
}

func TestRequireSysctlReportsHostPrerequisite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl")
	require.NoError(t, os.WriteFile(path, []byte("0\n"), 0644))

	err := requireSysctl(path, "net.ipv4.ip_forward", "1")
	require.ErrorContains(t, err, "requires net.ipv4.ip_forward=1")
	require.ErrorContains(t, err, `got "0"`)
	require.ErrorContains(t, err, "before starting sandboxd")
}

func TestSetSysctlIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl")
	require.NoError(t, os.WriteFile(path, []byte("1\n"), 0644))

	require.NoError(t, setSysctl(path, "net.ipv4.conf.sandbox0.rp_filter", "0"))
	require.NoError(t, setSysctl(path, "net.ipv4.conf.sandbox0.rp_filter", "0"))
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "0\n", string(actual))
}

func TestEmbeddedObjectsContainDataplane(t *testing.T) {
	for _, mode := range []gcMode{gcModeUserspace, gcModeBPFTimer} {
		t.Run(string(mode), func(t *testing.T) {
			spec, err := loadEmbeddedSpec(mode)
			require.NoError(t, err)
			for _, name := range []string{
				"sandboxd_egress_bpfnat",
				"sandboxd_ingress_bpfnat",
				"sandboxd_local_ingress_bpfnat",
				"sandboxd_bridge_ingress_bpfnat",
			} {
				assert.Contains(t, spec.Programs, name)
			}
			for _, name := range []string{
				"SNAT_MAPPING_IPV4",
				"EGRESS_POLICY_MAP",
				"DNAT_RULES_MAP",
				"SNAT_CONFIG_MAP",
				"POD_PORT_MAP",
				"LOCAL_REDIRECT_MAP",
			} {
				assert.Contains(t, spec.Maps, name)
			}
		})
	}
}

func TestEmbeddedObjectsUseDistinctMappingLayouts(t *testing.T) {
	legacy, err := loadEmbeddedSpec(gcModeUserspace)
	require.NoError(t, err)
	timer, err := loadEmbeddedSpec(gcModeBPFTimer)
	require.NoError(t, err)

	assert.Equal(t, uint32(binary.Size(ipv4NATEntry{})), legacy.Maps["SNAT_MAPPING_IPV4"].ValueSize)
	assert.Greater(t, timer.Maps["SNAT_MAPPING_IPV4"].ValueSize, legacy.Maps["SNAT_MAPPING_IPV4"].ValueSize)
	assert.NotEqual(t, pinPathForMode(gcModeUserspace), pinPathForMode(gcModeBPFTimer))
}

func TestSelectGCModePrefersBPFTimers(t *testing.T) {
	var helpers []asm.BuiltinFunc
	mode, err := selectGCMode(func(programType ebpf.ProgramType, helper asm.BuiltinFunc) error {
		assert.Equal(t, ebpf.SchedCLS, programType)
		helpers = append(helpers, helper)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, gcModeBPFTimer, mode)
	assert.Equal(t, []asm.BuiltinFunc{asm.FnTimerInit, asm.FnTimerSetCallback, asm.FnTimerStart}, helpers)
}

func TestSelectGCModeFallsBackWhenTimerHelperIsUnavailable(t *testing.T) {
	mode, err := selectGCMode(func(_ ebpf.ProgramType, helper asm.BuiltinFunc) error {
		if helper == asm.FnTimerSetCallback {
			return fmt.Errorf("timer callback: %w", ebpf.ErrNotSupported)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, gcModeUserspace, mode)
}

func TestSelectGCModeDoesNotHideProbeFailures(t *testing.T) {
	probeErr := errors.New("permission denied")
	mode, err := selectGCMode(func(ebpf.ProgramType, asm.BuiltinFunc) error {
		return probeErr
	})
	assert.Empty(t, mode)
	require.ErrorIs(t, err, probeErr)
	require.ErrorContains(t, err, "probe bpfnat BPF timer helper")
}

func TestMakeEgressPolicy(t *testing.T) {
	key, err := makeEgressPolicy("10.88.4.37/20")
	require.NoError(t, err)
	assert.Equal(t, uint32(20), key.PrefixLen)
	assert.Equal(t, [4]byte{10, 88, 0, 0}, key.Source)
	assert.Equal(t, [4]byte{}, key.Dest)
	assert.Equal(t, 12, binary.Size(key))
}

func TestMakeEgressPolicyRejectsIPv6(t *testing.T) {
	_, err := makeEgressPolicy("fd00::/64")
	require.ErrorContains(t, err, "only supports IPv4")
}

func TestMakeDNATRule(t *testing.T) {
	key, value, err := makeDNATRule("tcp", 21008, "10.88.2.17", 50090)
	require.NoError(t, err)
	assert.Equal(t, [4]byte{0x52, 0x10, protocolTCP, 0}, key)
	assert.Equal(t, [8]byte{10, 88, 2, 17, 0xc3, 0xaa, 0, 0}, value)
}

func TestMakeDNATRuleValidatesInput(t *testing.T) {
	_, _, err := makeDNATRule("sctp", 21008, "10.88.2.17", 50090)
	require.ErrorContains(t, err, "unsupported bpfnat protocol")

	_, _, err = makeDNATRule("udp", 21008, "not-an-ip", 50090)
	require.ErrorContains(t, err, "must be IPv4")
}

func TestNATStructLayoutMatchesBPF(t *testing.T) {
	assert.Equal(t, 16, binary.Size(ipv4Tuple{}))
	assert.Equal(t, 56, binary.Size(ipv4NATEntry{}))
}

func TestReverseTupleForSNAT(t *testing.T) {
	original := ipv4Tuple{
		SourceAddr: 0x1102580a,
		DestAddr:   0x08080808,
		SourcePort: 0x3412,
		DestPort:   0x5000,
		Protocol:   protocolTCP,
		Flags:      natDirEgress,
	}
	entry := ipv4NATEntry{
		TargetAddr: 0x47ee14ac,
		TargetPort: 0x7856,
		Type:       natTypeSNAT,
	}

	reverse := reverseTuple(original, entry)
	assert.Equal(t, entry.TargetAddr, reverse.DestAddr)
	assert.Equal(t, original.DestAddr, reverse.SourceAddr)
	assert.Equal(t, entry.TargetPort, reverse.DestPort)
	assert.Equal(t, original.DestPort, reverse.SourcePort)
	assert.Equal(t, uint8(natDirIngress), reverse.Flags)
}

func TestReverseTupleForDNAT(t *testing.T) {
	original := ipv4Tuple{
		SourceAddr: 0x0100007f,
		DestAddr:   0x47ee14ac,
		SourcePort: 0x3412,
		DestPort:   0x1052,
		Protocol:   protocolTCP,
		Flags:      natDirIngress,
	}
	entry := ipv4NATEntry{
		TargetAddr: 0x1102580a,
		TargetPort: 0xaac3,
		Type:       natTypeDNAT,
	}

	reverse := reverseTuple(original, entry)
	assert.Equal(t, original.SourceAddr, reverse.DestAddr)
	assert.Equal(t, entry.TargetAddr, reverse.SourceAddr)
	assert.Equal(t, original.SourcePort, reverse.DestPort)
	assert.Equal(t, entry.TargetPort, reverse.SourcePort)
	assert.Equal(t, uint8(natDirEgress), reverse.Flags)
}

func TestConnectionTimeout(t *testing.T) {
	tcp := ipv4Tuple{Protocol: protocolTCP}
	udp := ipv4Tuple{Protocol: protocolUDP}

	assert.Equal(t, uint32(defaultTimeoutTCPSYN), connectionTimeout(tcp, ipv4NATEntry{Status: ctCreate}, 99))
	assert.Equal(t, uint32(99), connectionTimeout(tcp, ipv4NATEntry{Status: ctEstablish}, 99))
	assert.Equal(t, uint32(defaultTimeoutTCPClose), connectionTimeout(tcp, ipv4NATEntry{Status: ctClose}, 99))
	assert.Equal(t, uint32(99), connectionTimeout(udp, ipv4NATEntry{}, 99))
	assert.Equal(t, uint32(defaultTimeoutNonTCP), connectionTimeout(udp, ipv4NATEntry{}, 0))
}

func TestProtocolNumber(t *testing.T) {
	for input, expected := range map[string]uint8{
		"tcp":  protocolTCP,
		"6":    protocolTCP,
		"UDP":  protocolUDP,
		"17":   protocolUDP,
		"icmp": protocolICMP,
		"1":    protocolICMP,
	} {
		actual, err := protocolNumber(input)
		require.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}
