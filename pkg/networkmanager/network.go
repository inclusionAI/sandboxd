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

package networkmanager

import "net"

type NetworkManager interface {
	SetupSNATRules(ipRange string) error

	CleanupSNATRules(ipRange string) error

	SetupNetworkRulesForActivating(ip net.IP, envId string) error

	CleanupNetworkRulesForActivating(ip net.IP) error

	SetupDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error

	CleanupDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error
}

// LocalDNATManager optionally forwards callers that share sandboxd's network
// namespace. Deployments must enable this behavior explicitly.
type LocalDNATManager interface {
	SetupLocalDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error

	CleanupLocalDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error
}

// BackendConfig contains host-level settings needed before a stateful NAT
// backend initializes its dataplane.
type BackendConfig struct {
	Device          string
	EnableLocalDNAT bool
}

// ConfigurableNetworkManager is implemented by stateful backends whose
// dataplane needs host-level configuration before it is initialized.
type ConfigurableNetworkManager interface {
	Configure(BackendConfig) error
}

var NetworkManagers = map[string]NetworkManager{}

func Register(name string, manager NetworkManager) {
	NetworkManagers[name] = manager
}
