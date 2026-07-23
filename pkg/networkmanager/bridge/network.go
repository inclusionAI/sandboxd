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

package bridge

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
)

type BridgeNetworkManager struct{}

// SetupSNATRules implements networkmanager.NetworkManager.
func (BridgeNetworkManager) SetupSNATRules(ipRange string) error {
	// add follow iptable rule: iptables -t nat -A POSTROUTING -s 172.17.0.0/16 -j MASQUERADE
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	// check if rule exists.
	if exists, err := ipt.Exists("nat", "POSTROUTING", "-s", ipRange, "-j", "MASQUERADE"); err != nil {
		return err
	} else if exists {
		return nil
	}

	// create rule.
	return ipt.Append("nat", "POSTROUTING", "-s", ipRange, "-j", "MASQUERADE")
}

// CleanupSNATRules implements networkmanager.NetworkManager.
func (BridgeNetworkManager) CleanupSNATRules(ipRange string) error {
	// clean iptable rule if exists.
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	// check if rule exists.
	if exists, err := ipt.Exists("nat", "POSTROUTING", "-s", ipRange, "-j", "MASQUERADE"); err != nil {
		return err
	} else if !exists {
		return nil
	}

	// delete rule.
	return ipt.Delete("nat", "POSTROUTING", "-s", ipRange, "-j", "MASQUERADE")
}

// SetupNetworkRulesForActivating implements networkmanager.NetworkManager.
func (BridgeNetworkManager) SetupNetworkRulesForActivating(ip net.IP, envId string) error {
	return nil
}

// CleanupNetworkRulesForActivating implements networkmanager.NetworkManager.
func (BridgeNetworkManager) CleanupNetworkRulesForActivating(ip net.IP) error {
	return nil
}

// SetupDNATRule implements networkmanager.NetworkManager.
func (BridgeNetworkManager) SetupDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	dstPortStr := strconv.FormatUint(uint64(dstPort), 10)
	targetPortStr := strconv.FormatUint(uint64(targetPort), 10)
	toDest := fmt.Sprintf("%s:%s", targetIP, targetPortStr)

	// iptables -t nat -A PREROUTING -p <proto> --dport <dstPort> -j DNAT --to-destination <targetIP>:<targetPort>
	if err := ipt.AppendUnique("nat", "PREROUTING", "-p", protocol, "--dport", dstPortStr, "-j", "DNAT", "--to-destination", toDest); err != nil {
		return fmt.Errorf("failed to add PREROUTING DNAT rule: %v", err)
	}

	// iptables -A FORWARD -p <proto> -d <targetIP> --dport <targetPort> -j ACCEPT
	if err := ipt.AppendUnique("filter", "FORWARD", "-p", protocol, "-d", targetIP, "--dport", targetPortStr, "-j", "ACCEPT"); err != nil {
		// rollback PREROUTING rule
		ipt.Delete("nat", "PREROUTING", "-p", protocol, "--dport", dstPortStr, "-j", "DNAT", "--to-destination", toDest)
		return fmt.Errorf("failed to add FORWARD rule: %v", err)
	}

	return nil
}

// CleanupDNATRule implements networkmanager.NetworkManager.
func (BridgeNetworkManager) CleanupDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	dstPortStr := strconv.FormatUint(uint64(dstPort), 10)
	targetPortStr := strconv.FormatUint(uint64(targetPort), 10)
	toDest := fmt.Sprintf("%s:%s", targetIP, targetPortStr)

	// best-effort: remove both rules, report first error
	var firstErr error

	if err := ipt.DeleteIfExists("nat", "PREROUTING", "-p", protocol, "--dport", dstPortStr, "-j", "DNAT", "--to-destination", toDest); err != nil {
		firstErr = fmt.Errorf("failed to delete PREROUTING DNAT rule: %v", err)
	}

	if err := ipt.DeleteIfExists("filter", "FORWARD", "-p", protocol, "-d", targetIP, "--dport", targetPortStr, "-j", "ACCEPT"); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("failed to delete FORWARD rule: %v", err)
	}

	return firstErr
}

func init() {
	networkmanager.Register(config.NatBackendIptables, &BridgeNetworkManager{})
}
