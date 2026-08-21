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

type networkManager struct {
	iface           *networkmanager.InterfaceManager
	natBackend      string
	enableLocalDNAT bool

	dnatMu    sync.Mutex
	dnatRules map[string][]*dnatRule
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
	}
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

func (m *networkManager) Deactivate(resource string) error {
	if resource == "" {
		return nil
	}
	if m.iface == nil {
		return fmt.Errorf("interface manager not configured")
	}
	return m.iface.Deactivate(resource)
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
