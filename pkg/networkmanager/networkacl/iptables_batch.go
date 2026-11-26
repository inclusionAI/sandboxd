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
	"bytes"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

// iptables-restore commits one filter table per address family. All transactions
// below use --noflush and name only endpoint-owned chains or exact hook rules.
type filterBatch struct {
	v4, v6 filterCommands
}

type filterCommands struct{ save, restore string }

func findFilterBatch() *filterBatch {
	family := func(name string) (filterCommands, bool) {
		save, err := exec.LookPath(name + "-save")
		if err != nil {
			return filterCommands{}, false
		}
		restore, err := exec.LookPath(name + "-restore")
		if err != nil {
			return filterCommands{}, false
		}
		// Mixed alternatives would inspect or modify a different ruleset.
		mode := func(path string) string {
			out, err := exec.Command(path, "--version").Output()
			if err != nil {
				return ""
			}
			for _, m := range []string{"(nf_tables)", "(legacy)"} {
				if bytes.Contains(out, []byte(m)) {
					return m
				}
			}
			return ""
		}
		m := mode(name)
		return filterCommands{save, restore}, m != "" && mode(save) == m && mode(restore) == m
	}
	v4, ok4 := family("iptables")
	v6, ok6 := family("ip6tables")
	if !ok4 || !ok6 {
		return nil
	}
	return &filterBatch{v4, v6}
}

type rulesBatch [][]string

func (r *rulesBatch) add(args ...string) { *r = append(*r, args) }
func (r *rulesBatch) hooks(op string, hooks []iptablesHook) {
	for _, h := range hooks {
		r.add(append([]string{op, h.chain}, h.rule...)...)
	}
}

var restoreToken = regexp.MustCompile(`^[a-zA-Z0-9_./:!,+@%=-]+$`)

func (c filterCommands) commit(r rulesBatch) error {
	if len(r) == 0 {
		return nil
	}
	var input strings.Builder
	input.WriteString("*filter\n")
	for _, rule := range r {
		for _, arg := range rule {
			if !restoreToken.MatchString(arg) {
				return fmt.Errorf("invalid iptables restore token %q", arg)
			}
		}
		input.WriteString(strings.Join(rule, " "))
		input.WriteByte('\n')
	}
	input.WriteString("COMMIT\n")
	cmd := exec.Command(c.restore, "--wait", "--noflush")
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", c.restore, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (c filterCommands) snapshot() (string, error) {
	out, err := exec.Command(c.save, "-t", filterTable).Output()
	if err != nil {
		return "", fmt.Errorf("%s filter: %w", c.save, err)
	}
	return string(out), nil
}

// On retry or restore, let the reconciliation path repair partial hooks and
// old generations. Substring matches are conservative here.
func (b *filterBatch) fresh(ip net.IP, veth string) (bool, error) {
	v4, err := b.v4.snapshot()
	if err != nil {
		return false, err
	}
	se, _, ge, _ := iptablesChainNames(ip, 0)
	if strings.Contains(v4, strings.TrimSuffix(se, "-E")+"-") || strings.Contains(v4, ge[:len("SD-G-")+8]+"-") || strings.Contains(v4, veth) {
		return false, nil
	}
	v6, err := b.v6.snapshot()
	return !strings.Contains(v6, veth), err
}

func (b *filterBatch) hasGeneration(ip net.IP, g uint64) (bool, error) {
	v4, err := b.v4.snapshot()
	if err != nil {
		return false, err
	}
	se, si, ge, gi := iptablesChainNames(ip, g)
	for _, name := range []string{se, si, ge, gi} {
		if !strings.Contains(v4, "\n:"+name+" ") {
			return false, nil
		}
	}
	// Recovery also collects abandoned generations from interrupted updates.
	prefix := ge[:len("SD-G-")+8] + "-"
	return strings.Count(v4, "\n:"+prefix) == 2, nil
}

func setDispatcher(r *rulesBatch, chain, target string, create bool) {
	if create {
		r.add("-N", chain)
	} else {
		r.add("-F", chain)
	}
	r.add("-A", chain, "-j", target)
	r.add("-A", chain, "-j", "RETURN")
}

func (b *iptablesBackend) createBatch(ip net.IP, entry persistedEntry) error {
	se, si, ge, gi := iptablesChainNames(ip, entry.Generation)
	var ipv6, barrier, active rulesBatch
	ipv6.hooks("-I", aclIP6TablesHooks(entry.HostVeth))
	if err := b.batch.v6.commit(ipv6); err != nil {
		return err
	}
	setDispatcher(&barrier, se, dropBarrierChain, true)
	setDispatcher(&barrier, si, dropBarrierChain, true)
	barrier.hooks("-I", aclIPTablesHooks(ip, entry.HostVeth, se, si))
	if err := b.batch.v4.commit(barrier); err != nil {
		return err
	}
	if err := b.stageDomainGrants(entry); err != nil {
		return err
	}
	if err := b.deleteConntrack(ip); err != nil {
		return err
	}
	for i, chain := range []string{ge, gi} {
		direction := []uint8{directionEgress, directionIngress}[i]
		active.add("-N", chain)
		for _, rule := range b.compileRulesForSandbox(entry.Policy, direction, entry.Generation, ip) {
			active.add(append([]string{"-A", chain}, rule...)...)
		}
	}
	setDispatcher(&active, se, ge, false)
	setDispatcher(&active, si, gi, false)
	return b.batch.v4.commit(active)
}

// A restored endpoint may already lack a subset of its hooks. Try the normal
// single transaction first. A rejected COMMIT has removed no hooks.
func (c filterCommands) detach(client iptablesClient, hooks []iptablesHook) ([]iptablesHook, error) {
	var batch rulesBatch
	batch.hooks("-D", hooks)
	err := c.commit(batch)
	if err == nil {
		return hooks, nil
	}
	var present []iptablesHook
	for _, h := range hooks {
		exists, check := client.Exists(filterTable, h.chain, h.rule...)
		if check != nil {
			return nil, errors.Join(err, check)
		}
		if exists {
			present = append(present, h)
		}
	}
	if len(present) == len(hooks) {
		return nil, err
	}
	batch = nil
	batch.hooks("-D", present)
	return present, c.commit(batch)
}

func (b *iptablesBackend) cleanupBatch(ip net.IP, entry persistedEntry) error {
	se, si, ge, gi := iptablesChainNames(ip, entry.Generation)
	var barrier rulesBatch
	setDispatcher(&barrier, se, dropBarrierChain, false)
	setDispatcher(&barrier, si, dropBarrierChain, false)
	if err := b.batch.v4.commit(barrier); err != nil {
		return err
	}
	if err := b.deleteConntrack(ip); err != nil {
		return err
	}
	if err := b.batch.v4.commit(rulesBatch{{"-F", ge}, {"-F", gi}, {"-X", ge}, {"-X", gi}}); err != nil {
		return err
	}
	if err := b.deleteDomainSets(ip, entry.Generation, entry.Policy); err != nil {
		return err
	}
	removed, err := b.batch.v4.detach(b.client, aclIPTablesHooks(ip, entry.HostVeth, se, si))
	if err != nil {
		return err
	}
	if _, err = b.batch.v6.detach(b.ipv6Client, aclIP6TablesHooks(entry.HostVeth)); err != nil {
		var rollback rulesBatch
		rollback.hooks("-I", removed)
		return errors.Join(err, b.batch.v4.commit(rollback))
	}
	// Detached dispatchers are unreachable; preserve the existing GC semantics.
	if err := b.batch.v4.commit(rulesBatch{{"-F", se}, {"-F", si}, {"-X", se}, {"-X", si}}); err != nil {
		logrus.Warnf("delete unreachable network ACL dispatchers for %s: %v", ip, err)
	}
	return nil
}
