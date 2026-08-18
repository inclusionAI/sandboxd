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

package server

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/sirupsen/logrus"
)

type dnatRule struct {
	Protocol   string
	DstPort    uint16
	TargetIP   string
	TargetPort uint16
	SandboxID  string
}

type restoredDnatFact struct {
	ports    []string
	targetIP string
}

type hostPortKey struct {
	protocol string
	port     uint16
}

type networkManager struct {
	iface           *networkmanager.InterfaceManager
	natBackend      string
	enableLocalDNAT bool

	dnatMu    sync.Mutex
	dnatRules map[string][]*dnatRule

	portMu        sync.Mutex
	hostPortStart int
	hostPortCount int
	portOwners    map[hostPortKey]string
	portFacts     map[string][]string
}

type preparedNetwork struct {
	resource string
	config   *networkmanager.NetResource
}

func resolveNATBackend(name string) (string, error) {
	if name == "" {
		name = config.NatBackendIptables
	}
	if _, ok := networkmanager.NetworkManagers[name]; !ok {
		return "", fmt.Errorf("unsupported NAT backend %q", name)
	}
	return name, nil
}

func newNetworkManager(
	iface *networkmanager.InterfaceManager,
	natBackend string,
	enableLocalDNAT bool,
) *networkManager {
	return &networkManager{
		iface:           iface,
		natBackend:      natBackend,
		enableLocalDNAT: enableLocalDNAT,
		dnatRules:       make(map[string][]*dnatRule),
		hostPortStart:   config.DefaultHostPortStart,
		hostPortCount:   config.DefaultHostPortCount,
		portOwners:      make(map[hostPortKey]string),
		portFacts:       make(map[string][]string),
	}
}

func (m *networkManager) configureHostPortRange(start, count int) error {
	if start == 0 && count == 0 {
		return nil
	}
	if start < 1 || start > 65535 || count < 1 || count > 65535-start+1 {
		return fmt.Errorf("invalid host port range start=%d count=%d", start, count)
	}
	m.hostPortStart = start
	m.hostPortCount = count
	return nil
}

func clonePorts(ports []string) []string {
	return append([]string(nil), ports...)
}

func portRequestMatchesFact(request, fact *dnatRule) bool {
	return request.Protocol == fact.Protocol && request.TargetPort == fact.TargetPort &&
		(request.DstPort == 0 || request.DstPort == fact.DstPort)
}

func hostPortAvailable(protocol string, port uint16) bool {
	address := net.JoinHostPort("0.0.0.0", strconv.Itoa(int(port)))
	if protocol == "udp" {
		conn, err := net.ListenPacket("udp", address)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

// resolveDnatPorts atomically resolves zero-host requests and reserves the
// concrete ports for one sandbox. A replay returns the existing physical fact.
func (m *networkManager) resolveDnatPorts(sandboxID string, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	m.portMu.Lock()
	defer m.portMu.Unlock()

	requests := make([]*dnatRule, 0, len(requested))
	for _, encoded := range requested {
		rule, err := parseDnatRule(sandboxID, encoded, "")
		if err != nil {
			return nil, err
		}
		requests = append(requests, rule)
	}
	if existing, ok := m.portFacts[sandboxID]; ok {
		if len(existing) != len(requests) {
			return nil, fmt.Errorf("sandbox %s port request conflicts with existing physical fact", sandboxID)
		}
		for index, encoded := range existing {
			fact, err := parseDnatRule(sandboxID, encoded, "")
			if err != nil || !portRequestMatchesFact(requests[index], fact) {
				return nil, fmt.Errorf("sandbox %s port request conflicts with existing physical fact", sandboxID)
			}
		}
		return clonePorts(existing), nil
	}

	selected := make(map[hostPortKey]struct{}, len(requests))
	resolved := make([]string, 0, len(requests))
	for _, request := range requests {
		port := request.DstPort
		if port == 0 {
			for offset := 0; offset < m.hostPortCount; offset++ {
				candidate := m.hostPortStart + offset
				if candidate > 65535 {
					continue
				}
				value := uint16(candidate)
				key := hostPortKey{protocol: request.Protocol, port: value}
				if _, used := m.portOwners[key]; used {
					continue
				}
				if _, duplicate := selected[key]; duplicate || !hostPortAvailable(request.Protocol, value) {
					continue
				}
				port = value
				break
			}
			if port == 0 {
				return nil, fmt.Errorf("no host port available for sandbox %s", sandboxID)
			}
			selected[hostPortKey{protocol: request.Protocol, port: port}] = struct{}{}
		} else {
			key := hostPortKey{protocol: request.Protocol, port: port}
			if owner, used := m.portOwners[key]; used && owner != sandboxID {
				return nil, fmt.Errorf("host port %s/%d is owned by sandbox %s",
					request.Protocol, port, owner)
			}
			if _, duplicate := selected[key]; duplicate || !hostPortAvailable(request.Protocol, port) {
				return nil, fmt.Errorf("host port %s/%d is unavailable", request.Protocol, port)
			}
			selected[key] = struct{}{}
		}
		resolved = append(resolved, fmt.Sprintf("%s:%d:%d", request.Protocol, port, request.TargetPort))
	}
	for key := range selected {
		m.portOwners[key] = sandboxID
	}
	m.portFacts[sandboxID] = clonePorts(resolved)
	return resolved, nil
}

func (m *networkManager) resolvedPortsFor(sandboxID string) []string {
	m.portMu.Lock()
	defer m.portMu.Unlock()
	return clonePorts(m.portFacts[sandboxID])
}

func (m *networkManager) releaseDnatPorts(sandboxID string) {
	m.portMu.Lock()
	defer m.portMu.Unlock()
	for _, encoded := range m.portFacts[sandboxID] {
		rule, err := parseDnatRule(sandboxID, encoded, "")
		if err == nil {
			key := hostPortKey{protocol: rule.Protocol, port: rule.DstPort}
			if m.portOwners[key] == sandboxID {
				delete(m.portOwners, key)
			}
		}
	}
	delete(m.portFacts, sandboxID)
}

// restoreDnatPortFacts rebuilds allocation caches from persisted sandbox
// metadata. The metadata remains authoritative; these maps only enforce it.
func (m *networkManager) restoreDnatPortFacts(facts map[string][]string) error {
	m.portMu.Lock()
	defer m.portMu.Unlock()
	owners := make(map[hostPortKey]string)
	canonical := make(map[string][]string, len(facts))
	for sandboxID, ports := range facts {
		for _, encoded := range ports {
			rule, err := parseDnatRule(sandboxID, encoded, "")
			if err != nil || rule.DstPort == 0 {
				return fmt.Errorf("sandbox %s has invalid persisted port fact %q", sandboxID, encoded)
			}
			key := hostPortKey{protocol: rule.Protocol, port: rule.DstPort}
			if owner, exists := owners[key]; exists && owner != sandboxID {
				return fmt.Errorf("persisted host port %s/%d conflicts between %s and %s",
					rule.Protocol, rule.DstPort, owner, sandboxID)
			}
			owners[key] = sandboxID
		}
		canonical[sandboxID] = clonePorts(ports)
	}
	m.portOwners = owners
	m.portFacts = canonical
	return nil
}

// restoreDnatRuleFacts idempotently installs every committed physical rule and
// rebuilds the in-memory cleanup index. Both supported backends converge an
// exact duplicate without appending another rule.
func (m *networkManager) restoreDnatRuleFacts(facts map[string]restoredDnatFact) error {
	m.dnatMu.Lock()
	m.dnatRules = make(map[string][]*dnatRule, len(facts))
	m.dnatMu.Unlock()

	sandboxIDs := make([]string, 0, len(facts))
	for sandboxID := range facts {
		sandboxIDs = append(sandboxIDs, sandboxID)
	}
	sort.Strings(sandboxIDs)
	for _, sandboxID := range sandboxIDs {
		fact := facts[sandboxID]
		if err := m.setupDnatRules(sandboxID, fact.ports, fact.targetIP); err != nil {
			return fmt.Errorf("reconcile DNAT rules for sandbox %s: %w", sandboxID, err)
		}
	}
	return nil
}

func (m *networkManager) Prepare(runtimeName, sandboxID string) (*preparedNetwork, error) {
	if m.iface == nil {
		return nil, fmt.Errorf("interface manager not configured")
	}
	var resource string
	var err error
	if runtimeName == config.RuntimeNameRunc {
		resource, err = m.iface.AllocateEphemeral(sandboxID)
	} else {
		resource, err = m.iface.Allocate()
	}
	if err != nil {
		return nil, err
	}
	netResource := &networkmanager.NetResource{}
	if err := netResource.FromString(resource); err != nil {
		if recycleErr := m.iface.Recycle(resource); recycleErr != nil {
			logrus.Warnf("recycle malformed network resource %q failed: %v", resource, recycleErr)
		}
		return nil, fmt.Errorf("parse net device(%s) failed, err: %v", resource, err)
	}
	return &preparedNetwork{
		resource: resource,
		config:   netResource,
	}, nil
}

func (m *networkManager) Release(resource string) error {
	if resource == "" {
		return nil
	}
	if m.iface == nil {
		return fmt.Errorf("interface manager not configured")
	}
	return m.iface.Release(resource)
}

func (m *networkManager) Discard(resource string) error {
	if resource == "" {
		return nil
	}
	if m.iface == nil {
		return fmt.Errorf("interface manager not configured")
	}
	return m.iface.Discard(resource)
}

func (m *networkManager) setupDnatRules(sandboxID string, ports []string, targetIP string) error {
	if len(ports) == 0 {
		return nil
	}

	nat, ok := networkmanager.NetworkManagers[m.natBackend]
	if !ok {
		return fmt.Errorf("network manager not found for type: %s", m.natBackend)
	}
	var localNAT networkmanager.LocalDNATManager
	if m.enableLocalDNAT {
		var supported bool
		localNAT, supported = nat.(networkmanager.LocalDNATManager)
		if !supported {
			return fmt.Errorf("network manager %s does not support local DNAT", m.natBackend)
		}
	}

	rules := make([]*dnatRule, 0, len(ports))
	for _, port := range ports {
		rule, err := parseDnatRule(sandboxID, port, targetIP)
		if err != nil {
			return err
		}

		if err := nat.SetupDNATRule(rule.Protocol, rule.DstPort, rule.TargetIP, rule.TargetPort); err != nil {
			for i := len(rules) - 1; i >= 0; i-- {
				prev := rules[i]
				if cleanupErr := cleanupDnatRule(nat, prev); cleanupErr != nil {
					logrus.Warnf("rollback DNAT rule for %s:%d->%s:%d failed: %v",
						prev.Protocol, prev.DstPort, prev.TargetIP, prev.TargetPort, cleanupErr)
				}
			}
			return fmt.Errorf("failed to add DNAT rule for %s:%d->%s:%d: %v",
				rule.Protocol, rule.DstPort, rule.TargetIP, rule.TargetPort, err)
		}
		if localNAT != nil {
			if err := localNAT.SetupLocalDNATRule(
				rule.Protocol,
				rule.DstPort,
				rule.TargetIP,
				rule.TargetPort,
			); err != nil {
				if cleanupErr := cleanupDnatRule(nat, rule); cleanupErr != nil {
					logrus.Warnf("rollback DNAT rule for %s:%d->%s:%d failed: %v",
						rule.Protocol, rule.DstPort, rule.TargetIP, rule.TargetPort, cleanupErr)
				}
				for i := len(rules) - 1; i >= 0; i-- {
					prev := rules[i]
					if cleanupErr := cleanupDnatRule(nat, prev); cleanupErr != nil {
						logrus.Warnf("rollback DNAT rule for %s:%d->%s:%d failed: %v",
							prev.Protocol, prev.DstPort, prev.TargetIP, prev.TargetPort, cleanupErr)
					}
				}
				return fmt.Errorf("failed to add local DNAT rule for %s:%d->%s:%d: %v",
					rule.Protocol, rule.DstPort, rule.TargetIP, rule.TargetPort, err)
			}
		}

		logrus.Infof("Added DNAT rule: %s:%d -> %s:%d for sandbox %s",
			rule.Protocol, rule.DstPort, rule.TargetIP, rule.TargetPort, sandboxID)

		rules = append(rules, rule)
	}

	m.dnatMu.Lock()
	m.dnatRules[sandboxID] = rules
	m.dnatMu.Unlock()
	return nil
}

func cleanupDnatRule(nat networkmanager.NetworkManager, rule *dnatRule) error {
	var cleanupErrors []error
	if localNAT, ok := nat.(networkmanager.LocalDNATManager); ok {
		if err := localNAT.CleanupLocalDNATRule(
			rule.Protocol,
			rule.DstPort,
			rule.TargetIP,
			rule.TargetPort,
		); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("cleanup local DNAT: %w", err))
		}
	}
	if err := nat.CleanupDNATRule(
		rule.Protocol,
		rule.DstPort,
		rule.TargetIP,
		rule.TargetPort,
	); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("cleanup DNAT: %w", err))
	}
	return errors.Join(cleanupErrors...)
}

func (m *networkManager) cleanupPersistedDnatRules(
	sandboxID string,
	ports []string,
	targetIP string,
) error {
	if len(ports) == 0 {
		return nil
	}
	nat, ok := networkmanager.NetworkManagers[m.natBackend]
	if !ok {
		return fmt.Errorf("network manager not found for type: %s", m.natBackend)
	}
	rules := make([]*dnatRule, 0, len(ports))
	for _, encoded := range ports {
		rule, err := parseDnatRule(sandboxID, encoded, targetIP)
		if err != nil || rule.DstPort == 0 {
			return fmt.Errorf("sandbox %s has invalid persisted DNAT fact %q", sandboxID, encoded)
		}
		rules = append(rules, rule)
	}
	var cleanupErrors []error
	for _, rule := range rules {
		if err := cleanupDnatRule(nat, rule); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf(
				"cleanup %s/%d for sandbox %s: %w",
				rule.Protocol, rule.DstPort, sandboxID, err))
		}
	}
	if len(cleanupErrors) == 0 {
		m.dnatMu.Lock()
		delete(m.dnatRules, sandboxID)
		m.dnatMu.Unlock()
	}
	return errors.Join(cleanupErrors...)
}

func parseDnatRule(sandboxID, port, targetIP string) (*dnatRule, error) {
	parts := strings.Split(port, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid port format: %s, expected format: protocol:dstPort:targetPort", port)
	}

	protocol := parts[0]
	dstPort, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid dstPort: %s, err: %v", parts[1], err)
	}
	targetPort, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid targetPort: %s, err: %v", parts[2], err)
	}

	return &dnatRule{
		Protocol:   protocol,
		DstPort:    uint16(dstPort),
		TargetIP:   targetIP,
		TargetPort: uint16(targetPort),
		SandboxID:  sandboxID,
	}, nil
}

func (m *networkManager) cleanupDnatRules(sandboxID string) {
	m.dnatMu.Lock()
	rules, ok := m.dnatRules[sandboxID]
	if !ok {
		m.dnatMu.Unlock()
		return
	}
	delete(m.dnatRules, sandboxID)
	m.dnatMu.Unlock()

	nat, ok := networkmanager.NetworkManagers[m.natBackend]
	for _, rule := range rules {
		if !ok {
			logrus.Warnf("network manager not found for type %s, cannot delete DNAT rule %s:%d->%s:%d",
				m.natBackend, rule.Protocol, rule.DstPort, rule.TargetIP, rule.TargetPort)
			continue
		}
		if err := cleanupDnatRule(nat, rule); err != nil {
			logrus.Warnf("failed to delete DNAT rule for %s:%d->%s:%d: %v",
				rule.Protocol, rule.DstPort, rule.TargetIP, rule.TargetPort, err)
			continue
		}
		logrus.Infof("Deleted DNAT rule: %s:%d -> %s:%d for sandbox %s",
			rule.Protocol, rule.DstPort, rule.TargetIP, rule.TargetPort, sandboxID)
	}
}

func (m *networkManager) rulesFor(sandboxID string) []*dnatRule {
	m.dnatMu.Lock()
	defer m.dnatMu.Unlock()
	rules := m.dnatRules[sandboxID]
	out := make([]*dnatRule, len(rules))
	copy(out, rules)
	return out
}

func (m *networkManager) ruleCount() int {
	m.dnatMu.Lock()
	defer m.dnatMu.Unlock()
	return len(m.dnatRules)
}
