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
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	aclBackendIPTables = "iptables"
	aclBackendBPFNAT   = "bpfnat"

	filterTable      = "filter"
	forwardChain     = "FORWARD"
	inputChain       = "INPUT"
	outputChain      = "OUTPUT"
	dropBarrierChain = "SD-ACL-DROP"
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

type iptablesBackend struct {
	client   iptablesClient
	bridgeIP net.IP
}

func newIPTablesBackend(bridgeIP net.IP) (*iptablesBackend, error) {
	if err := ensureBridgeNetfilter(); err != nil {
		return nil, err
	}
	client, err := newACLIPTablesClient()
	if err != nil {
		return nil, fmt.Errorf("open iptables: %w", err)
	}
	backend := &iptablesBackend{client: client, bridgeIP: append(net.IP(nil), bridgeIP.To4()...)}
	if err := backend.ensureDropBarrier(); err != nil {
		return nil, err
	}
	return backend, nil
}

func ensureBridgeNetfilter() error {
	const bridgeCallIPTables = "/proc/sys/net/bridge/bridge-nf-call-iptables"
	value, err := os.ReadFile(bridgeCallIPTables)
	if err != nil {
		return fmt.Errorf("iptables ACL requires br_netfilter and %s=1: %w", bridgeCallIPTables, err)
	}
	if strings.TrimSpace(string(value)) == "1" {
		return nil
	}
	if err := os.WriteFile(bridgeCallIPTables, []byte("1\n"), 0); err != nil {
		return fmt.Errorf("enable bridge netfilter at %s: %w", bridgeCallIPTables, err)
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
	if len(rules) >= 2 && strings.HasSuffix(rules[1], " -j DROP") {
		return nil
	}
	if err := b.client.Insert(filterTable, dropBarrierChain, 1, "-j", "DROP"); err != nil {
		return fmt.Errorf("populate network ACL drop barrier: %w", err)
	}
	return nil
}

func aclIPTablesHooks(ip net.IP, stableEgress, stableIngress string) []iptablesHook {
	return []iptablesHook{
		{chain: forwardChain, rule: []string{"-s", ip.String(), "-j", stableEgress}},
		{chain: inputChain, rule: []string{"-s", ip.String(), "-j", stableEgress}},
		{chain: forwardChain, rule: []string{"-d", ip.String(), "-j", stableIngress}},
		{chain: outputChain, rule: []string{"-d", ip.String(), "-j", stableIngress}},
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
	if !old.Policy.Empty() {
		oldIP := net.ParseIP(old.IP).To4()
		egressExists, egressErr := b.client.ChainExists(filterTable, stableEgress)
		ingressExists, ingressErr := b.client.ChainExists(filterTable, stableIngress)
		if egressErr != nil || ingressErr != nil {
			return errors.Join(egressErr, ingressErr)
		}
		if oldIP == nil || !oldIP.Equal(ip) || !egressExists || !ingressExists {
			if err := b.cleanup(old); err != nil {
				return fmt.Errorf("clean incomplete iptables ACL before restore: %w", err)
			}
			old = persistedEntry{}
		}
	}
	if err := b.installGeneration(nextEgress, next.Policy, directionEgress, next.Generation); err != nil {
		return err
	}
	if err := b.installGeneration(nextIngress, next.Policy, directionIngress, next.Generation); err != nil {
		_ = b.deleteChain(nextEgress)
		return err
	}

	if old.Policy.Empty() {
		if err := b.deleteConntrack(ip); err != nil {
			_ = b.deleteChain(nextEgress)
			_ = b.deleteChain(nextIngress)
			return err
		}
		if err := b.installStable(stableEgress, nextEgress); err != nil {
			_ = b.deleteChain(nextEgress)
			_ = b.deleteChain(nextIngress)
			return err
		}
		if err := b.installStable(stableIngress, nextIngress); err != nil {
			_ = b.deleteChain(stableEgress)
			_ = b.deleteChain(nextEgress)
			_ = b.deleteChain(nextIngress)
			return err
		}
		var installed []iptablesHook
		for _, hook := range aclIPTablesHooks(ip, stableEgress, stableIngress) {
			if err := b.insertHook(hook); err != nil {
				for _, previous := range installed {
					_ = b.client.DeleteIfExists(filterTable, previous.chain, previous.rule...)
				}
				_ = b.deleteChain(stableEgress)
				_ = b.deleteChain(stableIngress)
				_ = b.deleteChain(nextEgress)
				_ = b.deleteChain(nextIngress)
				return err
			}
			installed = append(installed, hook)
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
	if err := b.replaceStable(stableEgress, nextEgress); err != nil {
		return err
	}
	if err := b.replaceStable(stableIngress, nextIngress); err != nil {
		_ = b.replaceStable(stableEgress, dropBarrierChain)
		return err
	}
	if oldEgress != nextEgress {
		_ = b.deleteChain(oldEgress)
	}
	if oldIngress != nextIngress {
		_ = b.deleteChain(oldIngress)
	}
	return nil
}

func (b *iptablesBackend) installGeneration(
	chain string, policy Policy, direction uint8, generation uint64,
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
	for _, rule := range b.compileRules(policy, direction, generation) {
		if err := b.client.Append(filterTable, chain, rule...); err != nil {
			_ = b.deleteChain(chain)
			return fmt.Errorf("populate network ACL chain %s: %w", chain, err)
		}
	}
	return nil
}

func (b *iptablesBackend) compileRules(policy Policy, direction uint8, generation uint64) [][]string {
	var rules [][]string
	stateful := policy.Traffic != nil && policy.Traffic.Mode == policyModeStateful
	mark := iptablesConnectionMark(generation)
	markText := fmt.Sprintf("0x%08x", mark)
	if policy.DNS != nil {
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
				"-m", "connmark", "--mark", markText, "-j", "RETURN",
			},
		)
	}
	for _, wantedAction := range []uint8{actionDeny, actionAllow} {
		for _, rule := range policy.Traffic.Rules {
			if rule.Action != wantedAction || !containsDirection(rule.Directions, direction) {
				continue
			}
			compiled := make([]string, 0, 14)
			protocol := protocolName(rule.Protocol)
			if protocol != "" {
				compiled = append(compiled, "-p", protocol)
			}
			if !rule.PeerAny {
				peerFlag := "-d"
				if direction == directionIngress {
					peerFlag = "-s"
				}
				compiled = append(compiled, peerFlag, net.IP(rule.PeerIP[:]).String())
			}
			if rule.PeerPort != 0 {
				portFlag := "--dport"
				if direction == directionIngress {
					portFlag = "--sport"
				}
				compiled = append(compiled, portFlag, strconv.Itoa(int(rule.PeerPort)))
			}
			if rule.SandboxPort != 0 {
				portFlag := "--sport"
				if direction == directionIngress {
					portFlag = "--dport"
				}
				compiled = append(compiled, portFlag, strconv.Itoa(int(rule.SandboxPort)))
			}
			if wantedAction == actionDeny {
				compiled = append(compiled, "-j", "DROP")
			} else if stateful {
				compiled = append(compiled,
					"-m", "conntrack", "--ctstate", "NEW",
					"-j", "CONNMARK", "--set-xmark", markText+"/0xffffffff",
				)
			} else {
				compiled = append(compiled, "-j", "RETURN")
			}
			rules = append(rules, compiled)
		}
	}
	if stateful {
		rules = append(rules,
			[]string{"-m", "connmark", "--mark", markText, "-j", "RETURN"},
		)
	}
	target := "RETURN"
	if policy.Traffic.DefaultAction == actionDeny {
		target = "DROP"
	} else if stateful {
		rules = append(rules,
			[]string{
				"-m", "conntrack", "--ctstate", "NEW",
				"-j", "CONNMARK", "--set-xmark", markText + "/0xffffffff",
			},
		)
		target = "RETURN"
	}
	return append(rules, []string{"-j", target})
}

func iptablesConnectionMark(generation uint64) uint32 {
	mark := uint32(generation) ^ 0xa5c10000
	if mark == 0 {
		return 0xa5c10000
	}
	return mark
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

func (b *iptablesBackend) insertHook(hook iptablesHook) error {
	exists, err := b.client.Exists(filterTable, hook.chain, hook.rule...)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if err := b.client.Insert(filterTable, hook.chain, 1, hook.rule...); err != nil {
		return fmt.Errorf("insert network ACL %s hook: %w", hook.chain, err)
	}
	return nil
}

func (b *iptablesBackend) cleanup(entry persistedEntry) error {
	ip := net.ParseIP(entry.IP).To4()
	if ip == nil {
		return fmt.Errorf("iptables ACL sandbox IP %q is not IPv4", entry.IP)
	}
	stableEgress, stableIngress, _, _ := iptablesChainNames(ip, entry.Generation)
	egressExists, err := b.replaceStableIfExists(stableEgress, dropBarrierChain)
	if err != nil {
		return err
	}
	ingressExists, err := b.replaceStableIfExists(stableIngress, dropBarrierChain)
	if err != nil {
		return err
	}
	if err := b.deleteConntrack(ip); err != nil {
		return err
	}
	var errs []error
	existingTargets := map[string]bool{
		stableEgress:  egressExists,
		stableIngress: ingressExists,
	}
	for _, hook := range aclIPTablesHooks(ip, stableEgress, stableIngress) {
		// iptables-nft cannot check a rule that jumps to a nonexistent
		// chain. Such a hook cannot exist, so skip the check when cleanup
		// is reconciling an entry that never installed a policy.
		if !existingTargets[hook.rule[len(hook.rule)-1]] {
			continue
		}
		if err := b.client.DeleteIfExists(filterTable, hook.chain, hook.rule...); err != nil {
			errs = append(errs, err)
		}
	}
	if err := b.deleteChain(stableEgress); err != nil {
		errs = append(errs, err)
	}
	if err := b.deleteChain(stableIngress); err != nil {
		errs = append(errs, err)
	}
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
	return errors.Join(errs...)
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

func (b *iptablesBackend) replaceStableIfExists(stable, target string) (bool, error) {
	exists, err := b.client.ChainExists(filterTable, stable)
	if err != nil || !exists {
		return exists, err
	}
	return true, b.replaceStable(stable, target)
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
	egress := &netlink.ConntrackFilter{}
	if err := egress.AddIP(netlink.ConntrackOrigSrcIP, ip); err != nil {
		return err
	}
	if err := egress.AddIP(netlink.ConntrackReplyDstIP, ip); err != nil {
		return err
	}
	ingress := &netlink.ConntrackFilter{}
	if err := ingress.AddIP(netlink.ConntrackOrigDstIP, ip); err != nil {
		return err
	}
	if err := ingress.AddIP(netlink.ConntrackReplySrcIP, ip); err != nil {
		return err
	}
	_, egressErr := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET), egress)
	_, ingressErr := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET), ingress)
	return errors.Join(egressErr, ingressErr)
}
