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
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	aclBackendIPTables = "iptables"
	aclBackendBPFNAT   = "bpfnat"

	filterTable                 = "filter"
	forwardChain                = "FORWARD"
	inputChain                  = "INPUT"
	outputChain                 = "OUTPUT"
	dropBarrierChain            = "SD-ACL-DROP"
	ipv4ProbeChain              = "SD-ACL4-PROBE"
	ipv6ProbeChain              = "SD-ACL6-PROBE"
	ipsetProbeName              = "SDACLPROBE"
	aclConnectionMark           = uint32(0xa5c10000)
	aclConnectionMarkMask       = uint32(0xffff0000)
	aclConnectionSourceBit      = uint32(0x00000001)
	aclConnectionDestinationBit = uint32(0x00000002)
)

type iptablesHook struct {
	chain string
	rule  []string
}

type iptablesClient interface {
	Append(table, chain string, rulespec ...string) error
	Insert(table, chain string, pos int, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	DeleteIfExists(table, chain string, rulespec ...string) error
	Exists(table, chain string, rulespec ...string) (bool, error)
	ChainExists(table, chain string) (bool, error)
	NewChain(table, chain string) error
	ClearChain(table, chain string) error
	DeleteChain(table, chain string) error
	List(table, chain string) ([]string, error)
	ListChains(table string) ([]string, error)
}

var newACLIPTablesClient = func() (iptablesClient, error) {
	return iptables.New()
}

var newACLIP6TablesClient = func() (iptablesClient, error) {
	return iptables.NewWithProtocol(iptables.ProtocolIPv6)
}

type iptablesBackend struct {
	client               iptablesClient
	ipv6Client           iptablesClient
	bridgeIP             net.IP
	ipset                ipsetClient
	deleteConntrackForIP func(net.IP) error
}

type ipsetClient interface {
	Run(args ...string) error
	Output(args ...string) (string, error)
}

type commandIPSet struct {
	path string
}

func (c commandIPSet) Run(args ...string) error {
	output, err := exec.Command(c.path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (c commandIPSet) Output(args ...string) (string, error) {
	output, err := exec.Command(c.path, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ipset %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func newIPTablesBackend(bridgeIP net.IP) (*iptablesBackend, error) {
	if err := ensureBridgeNetfilter(); err != nil {
		return nil, err
	}
	client, err := newACLIPTablesClient()
	if err != nil {
		return nil, fmt.Errorf("open iptables: %w", err)
	}
	ipv6Client, err := newACLIP6TablesClient()
	if err != nil {
		return nil, fmt.Errorf("open ip6tables: %w", err)
	}
	ipsetPath, err := exec.LookPath("ipset")
	if err != nil {
		return nil, fmt.Errorf("iptables ACL requires ipset: %w", err)
	}
	backend := &iptablesBackend{
		client: client, ipv6Client: ipv6Client,
		bridgeIP: append(net.IP(nil), bridgeIP.To4()...),
		ipset:    commandIPSet{path: ipsetPath},
	}
	if err := backend.validatePrerequisites(); err != nil {
		return nil, err
	}
	if err := backend.ensureDropBarrier(); err != nil {
		return nil, err
	}
	return backend, nil
}

func (b *iptablesBackend) validatePrerequisites() error {
	// Probe the exact IPv4 physdev and negated-address syntax used to bind
	// policy ownership to a sandbox endpoint and reject spoofed addresses.
	if exists, err := b.client.ChainExists(filterTable, ipv4ProbeChain); err != nil {
		return fmt.Errorf("inspect iptables ACL prerequisite probe: %w", err)
	} else if exists {
		if err := b.client.ClearChain(filterTable, ipv4ProbeChain); err != nil {
			return fmt.Errorf("clear stale iptables ACL prerequisite probe: %w", err)
		}
		if err := b.client.DeleteChain(filterTable, ipv4ProbeChain); err != nil {
			return fmt.Errorf("delete stale iptables ACL prerequisite probe: %w", err)
		}
	}
	if err := b.client.NewChain(filterTable, ipv4ProbeChain); err != nil {
		return fmt.Errorf("create iptables ACL prerequisite probe: %w", err)
	}
	cleanupIPv4 := func() error {
		return errors.Join(
			b.client.ClearChain(filterTable, ipv4ProbeChain),
			b.client.DeleteChain(filterTable, ipv4ProbeChain),
		)
	}
	if err := b.client.Append(
		filterTable, ipv4ProbeChain,
		"-m", "physdev", "--physdev-in", "sd-acl-probe", "!", "-s", "192.0.2.1", "-j", "DROP",
	); err != nil {
		return errors.Join(
			fmt.Errorf("iptables ACL requires IPv4 physdev anti-spoof matching: %w", err),
			cleanupIPv4(),
		)
	}
	if err := b.client.Append(
		filterTable, ipv4ProbeChain,
		"-m", "conntrack", "--ctstate", "NEW",
		"-j", "CONNMARK", "--set-xmark", aclConnectionMarkSpec(aclConnectionSourceBit),
	); err != nil {
		return errors.Join(
			fmt.Errorf("iptables ACL requires conntrack and the CONNMARK target: %w", err),
			cleanupIPv4(),
		)
	}
	if err := b.client.Append(
		filterTable, ipv4ProbeChain,
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctdir", "REPLY",
		"-m", "connmark", "--mark", aclConnectionMarkSpec(aclConnectionSourceBit), "-j", "RETURN",
	); err != nil {
		return errors.Join(
			fmt.Errorf("iptables ACL requires the connmark match: %w", err),
			cleanupIPv4(),
		)
	}
	ipv4OutputProbe := []string{
		"-m", "physdev", "--physdev-is-bridged", "--physdev-out", "sd-acl-probe",
		"!", "-d", "192.0.2.1", "-j", "DROP",
	}
	if err := b.client.Insert(filterTable, outputChain, 1, ipv4OutputProbe...); err != nil {
		return errors.Join(
			fmt.Errorf("iptables ACL requires IPv4 bridged OUTPUT matching: %w", err),
			cleanupIPv4(),
		)
	}
	if err := b.client.Delete(filterTable, outputChain, ipv4OutputProbe...); err != nil {
		return errors.Join(
			fmt.Errorf("remove IPv4 bridged OUTPUT prerequisite probe: %w", err),
			cleanupIPv4(),
		)
	}
	if err := cleanupIPv4(); err != nil {
		return fmt.Errorf("remove iptables ACL prerequisite probe: %w", err)
	}

	// Exercise the exact IPv6 filter-table match used by per-sandbox hooks.
	// Merely constructing an ip6tables client is lazy and would otherwise let
	// an incapable node report ready until the first policy is created.
	if exists, err := b.ipv6Client.ChainExists(filterTable, ipv6ProbeChain); err != nil {
		return fmt.Errorf("inspect ip6tables ACL prerequisite probe: %w", err)
	} else if exists {
		if err := b.ipv6Client.ClearChain(filterTable, ipv6ProbeChain); err != nil {
			return fmt.Errorf("clear stale ip6tables ACL prerequisite probe: %w", err)
		}
		if err := b.ipv6Client.DeleteChain(filterTable, ipv6ProbeChain); err != nil {
			return fmt.Errorf("delete stale ip6tables ACL prerequisite probe: %w", err)
		}
	}
	if err := b.ipv6Client.NewChain(filterTable, ipv6ProbeChain); err != nil {
		return fmt.Errorf("create ip6tables ACL prerequisite probe: %w", err)
	}
	cleanupIPv6 := func() error {
		return errors.Join(
			b.ipv6Client.ClearChain(filterTable, ipv6ProbeChain),
			b.ipv6Client.DeleteChain(filterTable, ipv6ProbeChain),
		)
	}
	if err := b.ipv6Client.Append(
		filterTable, ipv6ProbeChain,
		"-m", "physdev", "--physdev-is-bridged", "-j", "RETURN",
	); err != nil {
		return errors.Join(
			fmt.Errorf("iptables ACL requires the IPv6 physdev match: %w", err),
			cleanupIPv6(),
		)
	}
	ipv6OutputProbe := []string{
		"-m", "physdev", "--physdev-is-bridged", "--physdev-out", "sd-acl-probe", "-j", "RETURN",
	}
	if err := b.ipv6Client.Insert(filterTable, outputChain, 1, ipv6OutputProbe...); err != nil {
		return errors.Join(
			fmt.Errorf("iptables ACL requires IPv6 bridged OUTPUT matching: %w", err),
			cleanupIPv6(),
		)
	}
	if err := b.ipv6Client.Delete(filterTable, outputChain, ipv6OutputProbe...); err != nil {
		return errors.Join(
			fmt.Errorf("remove IPv6 bridged OUTPUT prerequisite probe: %w", err),
			cleanupIPv6(),
		)
	}
	if err := cleanupIPv6(); err != nil {
		return fmt.Errorf("remove ip6tables ACL prerequisite probe: %w", err)
	}

	// Domain rules depend on timeout-capable IPv4 hash sets. Probe the kernel
	// modules at startup instead of failing a sandbox request later.
	_ = b.ipset.Run("destroy", ipsetProbeName)
	if err := b.ipset.Run(
		"create", ipsetProbeName, "hash:ip", "family", "inet",
		"timeout", "1", "maxelem", "1",
	); err != nil {
		return fmt.Errorf("iptables ACL requires timeout-capable hash:ip sets: %w", err)
	}
	if err := b.ipset.Run("destroy", ipsetProbeName); err != nil {
		return fmt.Errorf("remove ipset ACL prerequisite probe: %w", err)
	}
	return nil
}

func ensureBridgeNetfilter() error {
	for _, path := range []string{
		"/proc/sys/net/bridge/bridge-nf-call-iptables",
		"/proc/sys/net/bridge/bridge-nf-call-ip6tables",
	} {
		value, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("iptables ACL requires br_netfilter and %s=1: %w", path, err)
		}
		if strings.TrimSpace(string(value)) == "1" {
			continue
		}
		if err := os.WriteFile(path, []byte("1\n"), 0); err != nil {
			return fmt.Errorf("enable bridge netfilter at %s: %w", path, err)
		}
	}
	return nil
}

func (b *iptablesBackend) ensureDropBarrier() error {
	exists, err := b.client.ChainExists(filterTable, dropBarrierChain)
	if err != nil {
		return fmt.Errorf("inspect network ACL drop barrier: %w", err)
	}
	if !exists {
		if err := b.client.NewChain(filterTable, dropBarrierChain); err != nil {
			return fmt.Errorf("create network ACL drop barrier: %w", err)
		}
		if err := b.client.Append(filterTable, dropBarrierChain, "-j", "DROP"); err != nil {
			return fmt.Errorf("populate network ACL drop barrier: %w", err)
		}
		return nil
	}
	rules, err := b.client.List(filterTable, dropBarrierChain)
	if err != nil {
		return fmt.Errorf("read network ACL drop barrier: %w", err)
	}
	if len(rules) >= 2 {
		if target, canonical := stableRuleTarget(rules[1], dropBarrierChain); canonical && target == "DROP" {
			return nil
		}
	}
	if err := b.client.Insert(filterTable, dropBarrierChain, 1, "-j", "DROP"); err != nil {
		return fmt.Errorf("populate network ACL drop barrier: %w", err)
	}
	return nil
}

func aclIPTablesHooks(ip net.IP, hostVeth, stableEgress, stableIngress string) []iptablesHook {
	return []iptablesHook{
		{chain: forwardChain, rule: []string{
			"-s", ip.String(), "-j", stableEgress,
		}},
		{chain: forwardChain, rule: []string{
			"-m", "physdev", "--physdev-in", hostVeth, "!", "-s", ip.String(), "-j", "DROP",
		}},
		{chain: inputChain, rule: []string{
			"-s", ip.String(), "-j", stableEgress,
		}},
		{chain: inputChain, rule: []string{
			"-m", "physdev", "--physdev-in", hostVeth, "!", "-s", ip.String(), "-j", "DROP",
		}},
		{chain: forwardChain, rule: []string{
			"-d", ip.String(), "-j", stableIngress,
		}},
		{chain: forwardChain, rule: []string{
			"-m", "physdev", "--physdev-out", hostVeth, "!", "-d", ip.String(), "-j", "DROP",
		}},
		{chain: outputChain, rule: []string{
			"-d", ip.String(), "-j", stableIngress,
		}},
		{chain: outputChain, rule: []string{
			"-m", "physdev", "--physdev-is-bridged", "--physdev-out", hostVeth,
			"!", "-d", ip.String(), "-j", "DROP",
		}},
	}
}

// IPv4 policy matching cannot safely interpret IPv6 packets. Drop them on
// the sandbox's physical bridge port whenever an ACL is active, matching the
// IPv6 verdict of the TC eBPF backend. physdev is required because the L3
// interface observed by ip6tables is sandbox0 rather than the enslaved veth.
func aclIP6TablesHooks(hostVeth string) []iptablesHook {
	return []iptablesHook{
		{chain: forwardChain, rule: []string{"-m", "physdev", "--physdev-in", hostVeth, "-j", "DROP"}},
		{chain: inputChain, rule: []string{"-m", "physdev", "--physdev-in", hostVeth, "-j", "DROP"}},
		{chain: forwardChain, rule: []string{"-m", "physdev", "--physdev-out", hostVeth, "-j", "DROP"}},
		{chain: outputChain, rule: []string{
			"-m", "physdev", "--physdev-is-bridged", "--physdev-out", hostVeth, "-j", "DROP",
		}},
	}
}

func iptablesChainNames(ip net.IP, generation uint64) (stableEgress, stableIngress, genEgress, genIngress string) {
	v4 := ip.To4()
	ipHex := fmt.Sprintf("%02X%02X%02X%02X", v4[0], v4[1], v4[2], v4[3])
	stableEgress = "SD-A-" + ipHex + "-E"
	stableIngress = "SD-A-" + ipHex + "-I"
	generationHex := fmt.Sprintf("%08X", uint32(generation))
	genEgress = "SD-G-" + ipHex + "-" + generationHex + "-E"
	genIngress = "SD-G-" + ipHex + "-" + generationHex + "-I"
	return
}

func (b *iptablesBackend) apply(old, next persistedEntry) error {
	if next.Policy.Empty() {
		if old.IfIndex == 0 {
			return nil
		}
		return b.cleanup(old)
	}
	ip := net.ParseIP(next.IP).To4()
	if ip == nil {
		return fmt.Errorf("iptables ACL sandbox IP %q is not IPv4", next.IP)
	}
	stableEgress, stableIngress, nextEgress, nextIngress := iptablesChainNames(ip, next.Generation)
	stableEgressExists := false
	stableIngressExists := false
	if old.Policy.Empty() {
		// A previous failed activation can leave a stable dispatcher and hook
		// behind even though durable policy state is still empty. Move every
		// such dispatcher to the drop barrier before touching generation-scoped
		// chains or domain sets, so a retry can never rebuild an active chain.
		var egressErr, ingressErr error
		stableEgressExists, egressErr = b.forceStableBarrierIfExists(stableEgress)
		stableIngressExists, ingressErr = b.forceStableBarrierIfExists(stableIngress)
		if egressErr != nil || ingressErr != nil {
			return errors.Join(egressErr, ingressErr)
		}
	}
	if !old.Policy.Empty() {
		oldIP := net.ParseIP(old.IP).To4()
		_, _, oldEgress, oldIngress := iptablesChainNames(ip, old.Generation)
		egressExists, egressErr := b.client.ChainExists(filterTable, stableEgress)
		ingressExists, ingressErr := b.client.ChainExists(filterTable, stableIngress)
		if egressErr != nil || ingressErr != nil {
			return errors.Join(egressErr, ingressErr)
		}
		if oldIP == nil || !oldIP.Equal(ip) || old.HostVeth != next.HostVeth ||
			!egressExists || !ingressExists {
			if err := b.cleanup(old); err != nil {
				return fmt.Errorf("clean incomplete iptables ACL before restore: %w", err)
			}
			old = persistedEntry{}
		} else {
			egressCanonical, egressErr := b.stableIsCanonical(stableEgress, oldEgress)
			ingressCanonical, ingressErr := b.stableIsCanonical(stableIngress, oldIngress)
			if egressErr != nil || ingressErr != nil {
				return errors.Join(egressErr, ingressErr)
			}
			generationNameCollision := old.Generation != next.Generation &&
				(oldEgress == nextEgress || oldIngress == nextIngress)
			if !egressCanonical || !ingressCanonical || generationNameCollision {
				// A failed rollback or interrupted daemon restore can leave an
				// unexpected generation reachable from a stable dispatcher. Put
				// both directions behind a canonical drop barrier before any
				// generation chain is rebuilt.
				if err := errors.Join(
					b.forceStableBarrier(stableEgress),
					b.forceStableBarrier(stableIngress),
				); err != nil {
					return fmt.Errorf("repair incomplete network ACL dispatchers: %w", err)
				}
			}
		}
	}
	// Generation-specific domain sets are not referenced by the active
	// dispatchers yet. Fill and atomically swap them before installing or
	// switching the generation chains so a default-allow domain DENY policy
	// never becomes active with empty derived state.
	if err := b.stageDomainGrants(next); err != nil {
		return err
	}
	if err := b.installGeneration(nextEgress, next.Policy, directionEgress, next.Generation, ip); err != nil {
		_ = b.deleteDomainSets(ip, next.Generation, next.Policy)
		return err
	}
	if err := b.installGeneration(nextIngress, next.Policy, directionIngress, next.Generation, ip); err != nil {
		_ = b.deleteChain(nextEgress)
		_ = b.deleteDomainSets(ip, next.Generation, next.Policy)
		return err
	}
	installedIPv6, err := b.ensureHooks(b.ipv6Client, aclIP6TablesHooks(next.HostVeth))
	if err != nil {
		_ = b.deleteChain(nextEgress)
		_ = b.deleteChain(nextIngress)
		_ = b.deleteDomainSets(ip, next.Generation, next.Policy)
		return fmt.Errorf("install fail-closed IPv6 ACL hooks: %w", err)
	}

	if old.Policy.Empty() {
		if !stableEgressExists {
			if err := b.installStable(stableEgress, dropBarrierChain); err != nil {
				b.deleteHooks(b.ipv6Client, installedIPv6)
				_ = b.deleteChain(nextEgress)
				_ = b.deleteChain(nextIngress)
				return err
			}
		}
		if !stableIngressExists {
			if err := b.installStable(stableIngress, dropBarrierChain); err != nil {
				b.deleteHooks(b.ipv6Client, installedIPv6)
				if !stableEgressExists {
					_ = b.deleteChain(stableEgress)
				}
				_ = b.deleteChain(nextEgress)
				_ = b.deleteChain(nextIngress)
				return err
			}
		}
		var installed []iptablesHook
		for _, hook := range aclIPTablesHooks(ip, next.HostVeth, stableEgress, stableIngress) {
			added, err := b.insertHook(b.client, hook)
			if err != nil {
				b.deleteHooks(b.client, installed)
				b.deleteHooks(b.ipv6Client, installedIPv6)
				_ = b.deleteChain(nextEgress)
				_ = b.deleteChain(nextIngress)
				return err
			}
			if added {
				installed = append(installed, hook)
			}
		}
		// All paths owned by this endpoint now hit a drop dispatcher. Remove
		// state created before the hooks were complete, then atomically expose
		// each direction's prepared generation.
		if err := b.deleteConntrack(ip); err != nil {
			return err
		}
		if err := b.activateStable(stableEgress, nextEgress); err != nil {
			barrierErr := errors.Join(
				b.forceStableBarrier(stableEgress),
				b.forceStableBarrier(stableIngress),
			)
			return errors.Join(err, barrierErr)
		}
		if err := b.activateStable(stableIngress, nextIngress); err != nil {
			barrierErr := errors.Join(
				b.forceStableBarrier(stableEgress),
				b.forceStableBarrier(stableIngress),
			)
			return errors.Join(err, barrierErr)
		}
		return nil
	}

	_, _, oldEgress, oldIngress := iptablesChainNames(net.ParseIP(old.IP), old.Generation)
	if err := b.replaceStable(stableEgress, dropBarrierChain); err != nil {
		return err
	}
	if err := b.replaceStable(stableIngress, dropBarrierChain); err != nil {
		return err
	}
	if err := b.deleteConntrack(ip); err != nil {
		return err
	}
	if err := b.activateStable(stableEgress, nextEgress); err != nil {
		barrierErr := errors.Join(
			b.forceStableBarrier(stableEgress),
			b.forceStableBarrier(stableIngress),
		)
		return errors.Join(err, barrierErr)
	}
	if err := b.activateStable(stableIngress, nextIngress); err != nil {
		barrierErr := errors.Join(
			b.forceStableBarrier(stableEgress),
			b.forceStableBarrier(stableIngress),
		)
		return errors.Join(err, barrierErr)
	}
	if oldEgress != nextEgress {
		_ = b.deleteChain(oldEgress)
	}
	if oldIngress != nextIngress {
		_ = b.deleteChain(oldIngress)
	}
	if old.Generation != 0 && old.Generation != next.Generation {
		_ = b.deleteDomainSets(net.ParseIP(old.IP), old.Generation, old.Policy)
	}
	return nil
}

// rollback restores the policy that was active before a failed replacement.
// It first canonicalizes both stable chains behind a drop barrier, which makes
// rebuilding either generation chain safe even after an interrupted previous
// rollback left duplicate dispatcher targets.
func (b *iptablesBackend) rollback(old, attempted persistedEntry) error {
	if old.Policy.Empty() {
		return b.cleanup(attempted)
	}
	if attempted.Policy.Empty() {
		// Treat the old policy as a fresh activation. cleanup keeps reachable
		// dispatchers behind the drop barrier on every pre-commit failure, and
		// a fresh apply repairs missing hooks or generation chains without first
		// exposing the endpoint as unrestricted.
		return b.apply(persistedEntry{}, old)
	}

	ip := net.ParseIP(old.IP).To4()
	if ip == nil {
		return fmt.Errorf("iptables ACL sandbox IP %q is not IPv4", old.IP)
	}
	stableEgress, stableIngress, oldEgress, oldIngress := iptablesChainNames(ip, old.Generation)
	_, _, attemptedEgress, attemptedIngress := iptablesChainNames(ip, attempted.Generation)

	// Stop and canonicalize both directions before rebuilding the old
	// generation. The emergency direct-DROP step in forceStableBarrier means
	// even a chain containing duplicate targets remains restrictive throughout
	// repair.
	if err := errors.Join(
		b.forceStableBarrier(stableEgress),
		b.forceStableBarrier(stableIngress),
	); err != nil {
		return fmt.Errorf("install network ACL rollback barrier: %w", err)
	}
	if err := b.stageDomainGrants(old); err != nil {
		return fmt.Errorf("restore network ACL domain grants: %w", err)
	}
	if err := b.installGeneration(oldEgress, old.Policy, directionEgress, old.Generation, ip); err != nil {
		return fmt.Errorf("restore egress network ACL generation: %w", err)
	}
	if err := b.installGeneration(oldIngress, old.Policy, directionIngress, old.Generation, ip); err != nil {
		return fmt.Errorf("restore ingress network ACL generation: %w", err)
	}
	if err := b.deleteConntrack(ip); err != nil {
		return fmt.Errorf("delete connection state during network ACL rollback: %w", err)
	}
	if err := b.activateStable(stableEgress, oldEgress); err != nil {
		return fmt.Errorf("restore egress network ACL dispatcher: %w", err)
	}
	if err := b.activateStable(stableIngress, oldIngress); err != nil {
		barrierErr := errors.Join(
			b.forceStableBarrier(stableEgress),
			b.forceStableBarrier(stableIngress),
		)
		return errors.Join(
			fmt.Errorf("restore ingress network ACL dispatcher: %w", err),
			wrapOptionalError("restore egress rollback barrier", barrierErr),
		)
	}

	var errs []error
	if attemptedEgress != oldEgress {
		if err := b.deleteChain(attemptedEgress); err != nil {
			errs = append(errs, err)
		}
	}
	if attemptedIngress != oldIngress {
		if err := b.deleteChain(attemptedIngress); err != nil {
			errs = append(errs, err)
		}
	}
	if attempted.Generation != old.Generation {
		if err := b.deleteDomainSets(ip, attempted.Generation, attempted.Policy); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (b *iptablesBackend) installGeneration(
	chain string, policy Policy, direction uint8, generation uint64, sandboxIP net.IP,
) error {
	exists, err := b.client.ChainExists(filterTable, chain)
	if err != nil {
		return fmt.Errorf("inspect network ACL chain %s: %w", chain, err)
	}
	if exists {
		if err := b.client.ClearChain(filterTable, chain); err != nil {
			return fmt.Errorf("clear network ACL chain %s: %w", chain, err)
		}
	} else if err := b.client.NewChain(filterTable, chain); err != nil {
		return fmt.Errorf("create network ACL chain %s: %w", chain, err)
	}
	for _, rule := range b.compileRulesForSandbox(policy, direction, generation, sandboxIP) {
		if err := b.client.Append(filterTable, chain, rule...); err != nil {
			_ = b.deleteChain(chain)
			return fmt.Errorf("populate network ACL chain %s: %w", chain, err)
		}
	}
	return nil
}

func (b *iptablesBackend) compileRules(policy Policy, direction uint8, generation uint64) [][]string {
	return b.compileRulesForSandbox(policy, direction, generation, nil)
}

func aclConnectionMarkSpec(role uint32) string {
	return fmt.Sprintf(
		"0x%08x/0x%08x",
		aclConnectionMark|role,
		aclConnectionMarkMask|role,
	)
}

func aclConnectionRoles(direction uint8) (original, reply uint32) {
	if direction == directionIngress {
		return aclConnectionDestinationBit, aclConnectionSourceBit
	}
	return aclConnectionSourceBit, aclConnectionDestinationBit
}

func (b *iptablesBackend) compileRulesForSandbox(
	policy Policy, direction uint8, generation uint64, sandboxIP net.IP,
) [][]string {
	var rules [][]string
	stateful := policy.Traffic != nil && policy.Traffic.Mode == policyModeStateful
	// One conntrack entry can cross two managed endpoints. Keep independent
	// source and destination authorization bits under a shared owner prefix.
	// ORIGINAL traffic consumes the bit written by that endpoint's initial
	// direction; REPLY traffic consumes the same endpoint's opposite direction.
	// This prevents either sandbox from lending state to the other while still
	// allowing a reply across different policy generations.
	originalRole, replyRole := aclConnectionRoles(direction)
	originalMark := aclConnectionMarkSpec(originalRole)
	replyMark := aclConnectionMarkSpec(replyRole)
	if policy.NeedsDNSProxy() {
		for _, protocol := range []string{"tcp", "udp"} {
			if direction == directionEgress {
				rules = append(rules,
					[]string{"-p", protocol, "-d", b.bridgeIP.String(), "--dport", "53", "-j", "RETURN"},
					[]string{"-p", protocol, "--dport", "53", "-j", "DROP"},
				)
			} else {
				rules = append(rules,
					[]string{"-p", protocol, "-s", b.bridgeIP.String(), "--sport", "53", "-j", "RETURN"},
					[]string{"-p", protocol, "--sport", "53", "-j", "DROP"},
				)
			}
		}
	}
	if policy.Traffic == nil {
		return append(rules, []string{"-j", "RETURN"})
	}
	if stateful {
		rules = append(rules,
			[]string{"-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"},
			[]string{
				"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
				"--ctdir", "ORIGINAL", "-m", "connmark", "--mark", originalMark,
				"-j", "RETURN",
			},
			[]string{
				"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
				"--ctdir", "REPLY", "-m", "connmark", "--mark", replyMark,
				"-j", "RETURN",
			},
		)
	}
	type indexedRule struct {
		index int
		rule  TrafficRule
	}
	ordered := make([]indexedRule, 0, len(policy.Traffic.Rules))
	for index, rule := range policy.Traffic.Rules {
		ordered = append(ordered, indexedRule{index: index, rule: rule})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].rule.Priority != ordered[j].rule.Priority {
			return ordered[i].rule.Priority > ordered[j].rule.Priority
		}
		return ordered[i].rule.Action == actionDeny && ordered[j].rule.Action != actionDeny
	})
	for _, indexed := range ordered {
		rule := indexed.rule
		if !containsDirection(rule.Directions, direction) {
			continue
		}
		compiled := make([]string, 0, 14)
		protocol := protocolName(rule.Protocol)
		if protocol != "" {
			compiled = append(compiled, "-p", protocol)
		}
		if rule.PeerDomain != "" {
			if sandboxIP == nil || direction != directionEgress {
				continue
			}
			compiled = append(compiled, "-m", "set", "--match-set",
				domainSetName(sandboxIP, generation, indexed.index, false), "dst")
		} else if !rule.PeerAny {
			peerFlag := "-d"
			if direction == directionIngress {
				peerFlag = "-s"
			}
			prefix := rule.PeerPrefix
			if prefix == 0 && policy.SchemaVersion != networkPolicySchemaV2 {
				prefix = 32
			}
			peerNetwork := net.IP(rule.PeerIP[:]).String()
			if prefix != 32 {
				peerNetwork = (&net.IPNet{IP: net.IP(rule.PeerIP[:]), Mask: net.CIDRMask(int(prefix), 32)}).String()
			}
			compiled = append(compiled, peerFlag, peerNetwork)
		}
		peerFirst, peerLast := rule.PeerPorts()
		if peerFirst != 0 {
			portFlag := "--dport"
			if direction == directionIngress {
				portFlag = "--sport"
			}
			compiled = append(compiled, portFlag, iptablesPortRange(peerFirst, peerLast))
		}
		sandboxFirst, sandboxLast := rule.SandboxPorts()
		if sandboxFirst != 0 {
			portFlag := "--sport"
			if direction == directionIngress {
				portFlag = "--dport"
			}
			compiled = append(compiled, portFlag, iptablesPortRange(sandboxFirst, sandboxLast))
		}
		if rule.Action == actionDeny {
			compiled = append(compiled, "-j", "DROP")
		} else if stateful {
			markRule := append(append([]string(nil), compiled...),
				"-m", "conntrack", "--ctstate", "NEW",
				"-j", "CONNMARK", "--set-xmark", originalMark,
			)
			rules = append(rules, markRule)
			compiled = append(compiled, "-j", "RETURN")
		} else {
			compiled = append(compiled, "-j", "RETURN")
		}
		rules = append(rules, compiled)
	}
	target := "RETURN"
	if policy.Traffic.ActionFor(direction) == actionDeny {
		target = "DROP"
	} else if stateful {
		rules = append(rules,
			[]string{
				"-m", "conntrack", "--ctstate", "NEW",
				"-j", "CONNMARK", "--set-xmark", originalMark,
			},
		)
		target = "RETURN"
	}
	return append(rules, []string{"-j", target})
}

func iptablesPortRange(first, last uint16) string {
	if first == last {
		return strconv.Itoa(int(first))
	}
	return fmt.Sprintf("%d:%d", first, last)
}

func domainSetName(ip net.IP, generation uint64, ruleIndex int, temporary bool) string {
	prefix := "S"
	if temporary {
		prefix = "T"
	}
	v4 := ip.To4()
	return fmt.Sprintf(
		"%s%02X%02X%02X%02X%08X%02X",
		prefix, v4[0], v4[1], v4[2], v4[3], uint32(generation), ruleIndex,
	)
}

func (b *iptablesBackend) ensureDomainSets(ip net.IP, generation uint64, policy Policy) error {
	if policy.Traffic == nil {
		return nil
	}
	for index, rule := range policy.Traffic.Rules {
		if rule.PeerDomain == "" {
			continue
		}
		name := domainSetName(ip, generation, index, false)
		if err := b.ipset.Run(
			"create", name, "hash:ip", "family", "inet", "timeout",
			strconv.Itoa(int(maxDomainGrantTTL)), "maxelem",
			strconv.Itoa(maxDerivedDomainGrants), "-exist",
		); err != nil {
			return fmt.Errorf("create domain ACL set %s: %w", name, err)
		}
	}
	return nil
}

func (b *iptablesBackend) deleteDomainSets(ip net.IP, generation uint64, policy Policy) error {
	if policy.Traffic == nil || b.ipset == nil {
		return nil
	}
	names, err := b.ipset.Output("list", "-name")
	if err != nil {
		return err
	}
	existing := make(map[string]struct{})
	for _, name := range strings.Fields(names) {
		existing[name] = struct{}{}
	}
	var errs []error
	for index, rule := range policy.Traffic.Rules {
		if rule.PeerDomain == "" {
			continue
		}
		for _, temporary := range []bool{false, true} {
			name := domainSetName(ip, generation, index, temporary)
			if _, ok := existing[name]; !ok {
				continue
			}
			if err := b.ipset.Run("destroy", name); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (b *iptablesBackend) applyDomainGrants(previous, next persistedEntry) error {
	if next.Policy.Traffic == nil || !policyHasDomainRules(next.Policy) {
		return nil
	}
	changed := changedIPSetPeers(previous, next)
	if len(changed) == 0 {
		return nil
	}
	ip := net.ParseIP(next.IP).To4()
	if ip == nil {
		return fmt.Errorf("iptables domain ACL sandbox IP %q is not IPv4", next.IP)
	}
	stableEgress, stableIngress, generationEgress, generationIngress :=
		iptablesChainNames(ip, next.Generation)
	// Block the active generation before even preparing replacement sets.
	// ensureDomainSets may have to recreate a missing stable set; doing that
	// while a default-allow domain DENY chain is reachable would create an
	// allow window before the later atomic swap.
	if err := errors.Join(
		b.forceStableBarrier(stableEgress),
		b.forceStableBarrier(stableIngress),
	); err != nil {
		return err
	}
	preparedIP, prepared, err := b.prepareDomainGrantSets(next)
	if err != nil {
		// The caller performs the explicit reverse update. Keep the dispatchers
		// on the barrier until that repair has restored the complete old sets.
		return err
	}
	ip = preparedIP
	if err := b.swapPreparedDomainGrantSets(ip, next.Generation, prepared); err != nil {
		return err
	}
	if err := b.deleteConntrackPeers(ip, changed); err != nil {
		// Keep both dispatchers on the drop barrier. The caller retries by
		// applying the previous grant set; traffic must not use stale
		// conntrack state in between those attempts.
		return err
	}
	if err := b.activateStable(stableEgress, generationEgress); err != nil {
		barrierErr := errors.Join(
			b.forceStableBarrier(stableEgress),
			b.forceStableBarrier(stableIngress),
		)
		return errors.Join(err, barrierErr)
	}
	if err := b.activateStable(stableIngress, generationIngress); err != nil {
		barrierErr := errors.Join(
			b.forceStableBarrier(stableEgress),
			b.forceStableBarrier(stableIngress),
		)
		return errors.Join(err, barrierErr)
	}
	return nil
}

// stageDomainGrants fills generation-specific sets before any generation
// chain can reference them. Policy replacement assigns a fresh generation, so
// swapping these sets cannot affect the currently active policy.
func (b *iptablesBackend) stageDomainGrants(entry persistedEntry) error {
	if entry.Policy.Traffic == nil || !policyHasDomainRules(entry.Policy) {
		return nil
	}
	ip, prepared, err := b.prepareDomainGrantSets(entry)
	if err != nil {
		return err
	}
	return b.swapPreparedDomainGrantSets(ip, entry.Generation, prepared)
}

func (b *iptablesBackend) prepareDomainGrantSets(entry persistedEntry) (net.IP, []int, error) {
	ip := net.ParseIP(entry.IP).To4()
	if ip == nil {
		return nil, nil, fmt.Errorf("iptables domain ACL sandbox IP %q is not IPv4", entry.IP)
	}
	if err := b.ensureDomainSets(ip, entry.Generation, entry.Policy); err != nil {
		return nil, nil, err
	}
	sets, err := compileIPSetGrants(entry)
	if err != nil {
		return nil, nil, err
	}
	indices := make([]int, 0, len(sets))
	for index := range sets {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	prepared := make([]int, 0, len(indices))
	for _, index := range indices {
		temporary := domainSetName(ip, entry.Generation, index, true)
		_ = b.ipset.Run("destroy", temporary)
		if err := b.ipset.Run(
			"create", temporary, "hash:ip", "family", "inet", "timeout",
			strconv.Itoa(int(maxDomainGrantTTL)), "maxelem",
			strconv.Itoa(maxDerivedDomainGrants),
		); err != nil {
			b.destroyTemporarySets(ip, entry.Generation, prepared)
			return nil, nil, err
		}
		prepared = append(prepared, index)
		for address, expiresAt := range sets[index] {
			remaining := time.Until(time.Unix(0, expiresAt))
			seconds := int((remaining + time.Second - 1) / time.Second)
			if seconds < 1 {
				continue
			}
			if seconds > int(maxDomainGrantTTL) {
				seconds = int(maxDomainGrantTTL)
			}
			if err := b.ipset.Run("add", temporary, address, "timeout", strconv.Itoa(seconds), "-exist"); err != nil {
				b.destroyTemporarySets(ip, entry.Generation, prepared)
				return nil, nil, err
			}
		}
	}
	return ip, prepared, nil
}

func (b *iptablesBackend) swapPreparedDomainGrantSets(ip net.IP, generation uint64, prepared []int) error {
	swapped := make([]int, 0, len(prepared))
	for _, index := range prepared {
		stable := domainSetName(ip, generation, index, false)
		temporary := domainSetName(ip, generation, index, true)
		if err := b.ipset.Run("swap", temporary, stable); err != nil {
			for reverse := len(swapped) - 1; reverse >= 0; reverse-- {
				rolledIndex := swapped[reverse]
				_ = b.ipset.Run(
					"swap",
					domainSetName(ip, generation, rolledIndex, true),
					domainSetName(ip, generation, rolledIndex, false),
				)
			}
			b.destroyTemporarySets(ip, generation, prepared)
			return err
		}
		swapped = append(swapped, index)
	}
	b.destroyTemporarySets(ip, generation, prepared)
	return nil
}

func compileIPSetGrants(entry persistedEntry) (map[int]map[string]int64, error) {
	sets := make(map[int]map[string]int64)
	if entry.Policy.Traffic == nil {
		return sets, nil
	}
	for index, rule := range entry.Policy.Traffic.Rules {
		if rule.PeerDomain != "" {
			sets[index] = make(map[string]int64)
		}
	}
	now := time.Now().UnixNano()
	for _, grant := range entry.DomainGrants {
		index := int(grant.RuleIndex)
		if grant.ExpiresAt <= now || index >= len(entry.Policy.Traffic.Rules) ||
			entry.Policy.Traffic.Rules[index].PeerDomain == "" {
			continue
		}
		if net.ParseIP(grant.IP).To4() == nil {
			return nil, fmt.Errorf("persisted domain grant IP %q is not IPv4", grant.IP)
		}
		if grant.ExpiresAt > sets[index][grant.IP] {
			sets[index][grant.IP] = grant.ExpiresAt
		}
	}
	return sets, nil
}

func (b *iptablesBackend) destroyTemporarySets(ip net.IP, generation uint64, indices []int) {
	for _, index := range indices {
		_ = b.ipset.Run("destroy", domainSetName(ip, generation, index, true))
	}
}

func changedIPSetPeers(previous, next persistedEntry) map[string]struct{} {
	type grantKey struct {
		peer      string
		ruleIndex uint16
	}
	previousGrants := make(map[grantKey]int64)
	nextGrants := make(map[grantKey]int64)
	for _, grant := range previous.DomainGrants {
		key := grantKey{peer: grant.IP, ruleIndex: grant.RuleIndex}
		if grant.ExpiresAt > previousGrants[key] {
			previousGrants[key] = grant.ExpiresAt
		}
	}
	for _, grant := range next.DomainGrants {
		key := grantKey{peer: grant.IP, ruleIndex: grant.RuleIndex}
		if grant.ExpiresAt > nextGrants[key] {
			nextGrants[key] = grant.ExpiresAt
		}
	}
	changed := make(map[string]struct{})
	for key, expiry := range previousGrants {
		if nextGrants[key] != expiry {
			changed[key.peer] = struct{}{}
		}
	}
	for key, expiry := range nextGrants {
		if previousGrants[key] != expiry {
			changed[key.peer] = struct{}{}
		}
	}
	return changed
}

func (b *iptablesBackend) deleteConntrackPeers(sandboxIP net.IP, peers map[string]struct{}) error {
	normalizedPeers := make(map[string]struct{}, len(peers))
	for peerText := range peers {
		peer := net.ParseIP(peerText).To4()
		if peer != nil {
			normalizedPeers[peer.String()] = struct{}{}
		}
	}
	if len(normalizedPeers) == 0 {
		return nil
	}
	_, err := netlink.ConntrackDeleteFilter(
		netlink.ConntrackTable,
		netlink.InetFamily(unix.AF_INET),
		domainPeerConntrackFilter{sandboxIP: sandboxIP.To4(), peers: normalizedPeers},
	)
	return err
}

type domainPeerConntrackFilter struct {
	sandboxIP net.IP
	peers     map[string]struct{}
}

func (f domainPeerConntrackFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if flow == nil {
		return false
	}
	return domainPeerTupleMatches(
		f.sandboxIP, f.peers,
		flow.Forward.SrcIP, flow.Forward.DstIP, flow.Reverse.SrcIP,
	)
}

func domainPeerTupleMatches(
	sandboxIP net.IP, peers map[string]struct{}, forwardSource, forwardDestination, reverseSource net.IP,
) bool {
	if !forwardSource.Equal(sandboxIP) {
		return false
	}
	_, forwardMatch := peers[forwardDestination.String()]
	_, reverseMatch := peers[reverseSource.String()]
	return forwardMatch || reverseMatch
}

func containsDirection(directions []uint8, wanted uint8) bool {
	for _, direction := range directions {
		if direction == wanted {
			return true
		}
	}
	return false
}

func protocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return ""
	}
}

func (b *iptablesBackend) installStable(stable, generation string) error {
	exists, err := b.client.ChainExists(filterTable, stable)
	if err != nil {
		return err
	}
	if exists {
		if err := b.client.ClearChain(filterTable, stable); err != nil {
			return err
		}
	} else if err := b.client.NewChain(filterTable, stable); err != nil {
		return err
	}
	if err := b.client.Append(filterTable, stable, "-j", generation); err != nil {
		return err
	}
	return b.client.Append(filterTable, stable, "-j", "RETURN")
}

func stableRuleTarget(rule, stable string) (string, bool) {
	fields := strings.Fields(rule)
	if len(fields) != 4 || fields[0] != "-A" || fields[1] != stable || fields[2] != "-j" {
		return "", false
	}
	return fields[3], true
}

func (b *iptablesBackend) stableIsCanonical(stable, target string) (bool, error) {
	rules, err := b.client.List(filterTable, stable)
	if err != nil {
		return false, fmt.Errorf("read network ACL chain %s: %w", stable, err)
	}
	if len(rules) != 3 {
		return false, nil
	}
	first, firstOK := stableRuleTarget(rules[1], stable)
	second, secondOK := stableRuleTarget(rules[2], stable)
	return firstOK && secondOK && first == target && second == "RETURN", nil
}

// forceStableBarrier repairs a stable dispatcher without ever exposing an
// empty chain. A direct DROP is inserted first, all repository-owned jump
// rules are removed behind it, and then the canonical shared drop barrier is
// installed before the emergency DROP is removed.
func (b *iptablesBackend) forceStableBarrier(stable string) error {
	exists, err := b.client.ChainExists(filterTable, stable)
	if err != nil {
		return err
	}
	if !exists {
		return b.installStable(stable, dropBarrierChain)
	}
	if err := b.client.Insert(filterTable, stable, 1, "-j", "DROP"); err != nil {
		return fmt.Errorf("install emergency drop in network ACL chain %s: %w", stable, err)
	}
	rules, err := b.client.List(filterTable, stable)
	if err != nil {
		return fmt.Errorf("read blocked network ACL chain %s: %w", stable, err)
	}
	targetCounts := make(map[string]int)
	for _, rule := range rules[1:] {
		target, ok := stableRuleTarget(rule, stable)
		if !ok {
			return fmt.Errorf("network ACL chain %s has an invalid dispatcher rule %q", stable, rule)
		}
		if target != "DROP" {
			targetCounts[target]++
		}
	}
	for target, count := range targetCounts {
		for range count {
			if err := b.client.Delete(filterTable, stable, "-j", target); err != nil {
				return fmt.Errorf("remove stale target %s from network ACL chain %s: %w", target, stable, err)
			}
		}
	}
	if err := b.client.Insert(filterTable, stable, 1, "-j", dropBarrierChain); err != nil {
		return fmt.Errorf("install canonical drop in network ACL chain %s: %w", stable, err)
	}
	for {
		exists, err := b.client.Exists(filterTable, stable, "-j", "DROP")
		if err != nil {
			return err
		}
		if !exists {
			break
		}
		if err := b.client.Delete(filterTable, stable, "-j", "DROP"); err != nil {
			return fmt.Errorf("remove emergency drop from network ACL chain %s: %w", stable, err)
		}
	}
	if err := b.client.Append(filterTable, stable, "-j", "RETURN"); err != nil {
		return fmt.Errorf("finish canonical network ACL chain %s: %w", stable, err)
	}
	return nil
}

func (b *iptablesBackend) forceStableBarrierIfExists(stable string) (bool, error) {
	exists, err := b.client.ChainExists(filterTable, stable)
	if err != nil || !exists {
		return exists, err
	}
	return true, b.forceStableBarrier(stable)
}

func (b *iptablesBackend) replaceStable(stable, target string) error {
	rules, err := b.client.List(filterTable, stable)
	if err != nil {
		return fmt.Errorf("read network ACL chain %s: %w", stable, err)
	}
	if len(rules) < 2 {
		return fmt.Errorf("network ACL chain %s has no dispatcher rule", stable)
	}
	fields := strings.Fields(rules[1])
	if len(fields) < 2 || fields[len(fields)-2] != "-j" {
		return fmt.Errorf("network ACL chain %s has an invalid dispatcher rule %q", stable, rules[1])
	}
	oldTarget := fields[len(fields)-1]
	if oldTarget == target {
		return nil
	}
	if err := b.client.Insert(filterTable, stable, 1, "-j", target); err != nil {
		return fmt.Errorf("switch network ACL chain %s to %s: %w", stable, target, err)
	}
	if err := b.client.Delete(filterTable, stable, "-j", oldTarget); err != nil {
		return fmt.Errorf("remove previous target %s from network ACL chain %s: %w", oldTarget, stable, err)
	}
	return nil
}

// activateStable exposes a prepared generation from a canonical drop
// dispatcher. The generation is inserted behind the barrier first; deleting
// the barrier is the only operation that makes it reachable. If that deletion
// fails, traffic remains blocked instead of observing a half-committed policy.
func (b *iptablesBackend) activateStable(stable, target string) error {
	canonical, err := b.stableIsCanonical(stable, dropBarrierChain)
	if err != nil {
		return err
	}
	if !canonical {
		return fmt.Errorf("network ACL chain %s is not on the canonical drop barrier", stable)
	}
	if err := b.client.Insert(filterTable, stable, 2, "-j", target); err != nil {
		return fmt.Errorf("stage target %s in network ACL chain %s: %w", target, stable, err)
	}
	if err := b.client.Delete(filterTable, stable, "-j", dropBarrierChain); err != nil {
		return fmt.Errorf("activate target %s in network ACL chain %s: %w", target, stable, err)
	}
	return nil
}

func (b *iptablesBackend) insertHook(
	client iptablesClient, hook iptablesHook,
) (bool, error) {
	exists, err := client.Exists(filterTable, hook.chain, hook.rule...)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := client.Insert(filterTable, hook.chain, 1, hook.rule...); err != nil {
		return false, fmt.Errorf("insert network ACL %s hook: %w", hook.chain, err)
	}
	return true, nil
}

func (b *iptablesBackend) ensureHooks(
	client iptablesClient, hooks []iptablesHook,
) ([]iptablesHook, error) {
	installed := make([]iptablesHook, 0, len(hooks))
	for _, hook := range hooks {
		added, err := b.insertHook(client, hook)
		if err != nil {
			b.deleteHooks(client, installed)
			return nil, err
		}
		if added {
			installed = append(installed, hook)
		}
	}
	return installed, nil
}

func (b *iptablesBackend) deleteHooks(client iptablesClient, hooks []iptablesHook) {
	for _, hook := range hooks {
		_ = client.DeleteIfExists(filterTable, hook.chain, hook.rule...)
	}
}

type endpointHook struct {
	client iptablesClient
	hook   iptablesHook
}

func (b *iptablesBackend) rollbackRemovedHooks(removed []endpointHook) error {
	var errs []error
	for index := len(removed) - 1; index >= 0; index-- {
		binding := removed[index]
		if _, err := b.insertHook(binding.client, binding.hook); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// removeEndpointHooks commits policy removal only after every reachable path
// is ready to be detached. If one deletion fails, reinstall all earlier hooks
// while their dispatchers still point at the drop barrier.
func (b *iptablesBackend) removeEndpointHooks(
	ipv4 []iptablesHook, ipv6 []iptablesHook, existingTargets map[string]bool,
) error {
	bindings := make([]endpointHook, 0, len(ipv4)+len(ipv6))
	for _, hook := range ipv4 {
		target := hook.rule[len(hook.rule)-1]
		// iptables-nft cannot inspect a jump to a nonexistent chain. Such a
		// hook cannot exist, so skip it when reconciling incomplete activation.
		if target != "DROP" && !existingTargets[target] {
			continue
		}
		bindings = append(bindings, endpointHook{client: b.client, hook: hook})
	}
	for _, hook := range ipv6 {
		bindings = append(bindings, endpointHook{client: b.ipv6Client, hook: hook})
	}

	removed := make([]endpointHook, 0, len(bindings))
	for _, binding := range bindings {
		exists, err := binding.client.Exists(filterTable, binding.hook.chain, binding.hook.rule...)
		if err != nil {
			return errors.Join(err, b.rollbackRemovedHooks(removed))
		}
		if !exists {
			continue
		}
		if err := binding.client.Delete(filterTable, binding.hook.chain, binding.hook.rule...); err != nil {
			return errors.Join(err, b.rollbackRemovedHooks(removed))
		}
		removed = append(removed, binding)
	}
	return nil
}

func (b *iptablesBackend) cleanup(entry persistedEntry) error {
	ip := net.ParseIP(entry.IP).To4()
	if ip == nil {
		return fmt.Errorf("iptables ACL sandbox IP %q is not IPv4", entry.IP)
	}
	stableEgress, stableIngress, _, _ := iptablesChainNames(ip, entry.Generation)
	egressExists, egressErr := b.forceStableBarrierIfExists(stableEgress)
	ingressExists, ingressErr := b.forceStableBarrierIfExists(stableIngress)
	if egressErr != nil || ingressErr != nil {
		return errors.Join(egressErr, ingressErr)
	}
	if err := b.deleteConntrack(ip); err != nil {
		return err
	}
	existingTargets := map[string]bool{
		stableEgress:  egressExists,
		stableIngress: ingressExists,
	}
	var errs []error
	chains, err := b.client.ListChains(filterTable)
	if err != nil {
		errs = append(errs, err)
	} else {
		ipPrefix := strings.TrimSuffix(strings.TrimPrefix(stableEgress, "SD-A-"), "-E")
		prefix := "SD-G-" + ipPrefix + "-"
		for _, chain := range chains {
			if strings.HasPrefix(chain, prefix) {
				if err := b.deleteChain(chain); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if err := b.deleteDomainSets(ip, entry.Generation, entry.Policy); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		// All endpoint hooks still lead to the stable drop dispatchers. A
		// failed pre-commit cleanup therefore remains restrictive while orphan
		// recovery or policy rollback retries it.
		return err
	}
	if err := b.removeEndpointHooks(
		aclIPTablesHooks(ip, entry.HostVeth, stableEgress, stableIngress),
		aclIP6TablesHooks(entry.HostVeth),
		existingTargets,
	); err != nil {
		return fmt.Errorf("remove network ACL endpoint hooks: %w", err)
	}
	// Hooks are the policy's commit point. Dispatcher deletion after this is
	// unreachable garbage collection; keep cleanup successful if a concurrent
	// or external rule reference prevents immediate collection. A later fresh
	// activation canonicalizes either retained dispatcher before reuse.
	if err := errors.Join(b.deleteChain(stableEgress), b.deleteChain(stableIngress)); err != nil {
		logrus.Warnf("delete unreachable network ACL dispatchers for %s: %v", entry.IP, err)
	}
	return nil
}

func (b *iptablesBackend) close() error {
	chains, err := b.client.ListChains(filterTable)
	if err != nil {
		return err
	}
	for _, chain := range chains {
		if strings.HasPrefix(chain, "SD-A-") {
			return nil
		}
	}
	return b.deleteChain(dropBarrierChain)
}

func (b *iptablesBackend) deleteChain(chain string) error {
	exists, err := b.client.ChainExists(filterTable, chain)
	if err != nil || !exists {
		return err
	}
	if err := b.client.ClearChain(filterTable, chain); err != nil {
		return err
	}
	return b.client.DeleteChain(filterTable, chain)
}

func (b *iptablesBackend) deleteConntrack(ip net.IP) error {
	if b.deleteConntrackForIP != nil {
		return b.deleteConntrackForIP(ip)
	}
	// NAT rewrites one side of the reply tuple, so requiring the sandbox IP in
	// both original and reply directions can miss real standalone flows. Delete
	// every entry that contains the endpoint in any tuple position with one
	// conntrack-table scan.
	_, err := netlink.ConntrackDeleteFilter(
		netlink.ConntrackTable,
		netlink.InetFamily(unix.AF_INET),
		endpointConntrackFilter{ip: ip.To4()},
	)
	return err
}

type endpointConntrackFilter struct {
	ip net.IP
}

func (f endpointConntrackFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	return flow != nil && endpointTupleMatches(
		f.ip,
		flow.Forward.SrcIP, flow.Forward.DstIP,
		flow.Reverse.SrcIP, flow.Reverse.DstIP,
	)
}

func endpointTupleMatches(endpoint, forwardSource, forwardDestination, reverseSource, reverseDestination net.IP) bool {
	return forwardSource.Equal(endpoint) || forwardDestination.Equal(endpoint) ||
		reverseSource.Equal(endpoint) || reverseDestination.Equal(endpoint)
}
