// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"fmt"
	"net"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

const (
	actionAllow uint8 = 1
	actionDeny  uint8 = 2

	directionIngress uint8 = 1
	directionEgress  uint8 = 2
)

type Policy struct {
	Traffic *TrafficPolicy `json:"traffic,omitempty"`
	DNS     *DNSPolicy     `json:"dns,omitempty"`
}

type TrafficPolicy struct {
	DefaultAction uint8         `json:"default_action"`
	Rules         []TrafficRule `json:"rules,omitempty"`
}

type TrafficRule struct {
	Action     uint8   `json:"action"`
	Directions []uint8 `json:"directions"`
	Protocol   uint8   `json:"protocol"`
	PeerIP     [4]byte `json:"peer_ip"`
	PeerPort   uint16  `json:"peer_port"`
}

type DNSPolicy struct {
	DefaultAction uint8     `json:"default_action"`
	Rules         []DNSRule `json:"rules,omitempty"`
}

type DNSRule struct {
	Action   uint8  `json:"action"`
	Name     string `json:"name"`
	Wildcard bool   `json:"wildcard"`
}

func NormalizePolicy(input *runtime.NetworkPolicy) (Policy, error) {
	var out Policy
	if input == nil {
		return out, nil
	}
	if input.Traffic != nil {
		traffic, err := normalizeTraffic(input.Traffic)
		if err != nil {
			return Policy{}, err
		}
		out.Traffic = traffic
	}
	if input.Dns != nil {
		dns, err := normalizeDNS(input.Dns)
		if err != nil {
			return Policy{}, err
		}
		out.DNS = dns
	}
	return out, nil
}

func normalizeTraffic(input *runtime.TrafficPolicy) (*TrafficPolicy, error) {
	defaultAction, err := normalizeAction(input.DefaultAction)
	if err != nil {
		return nil, fmt.Errorf("traffic default action: %w", err)
	}
	out := &TrafficPolicy{DefaultAction: defaultAction, Rules: make([]TrafficRule, 0, len(input.Rules))}
	for index, inputRule := range input.Rules {
		if inputRule == nil {
			return nil, fmt.Errorf("traffic rule %d is nil", index)
		}
		action, err := normalizeAction(inputRule.Action)
		if err != nil {
			return nil, fmt.Errorf("traffic rule %d action: %w", index, err)
		}
		directions, err := normalizeDirection(inputRule.Direction)
		if err != nil {
			return nil, fmt.Errorf("traffic rule %d direction: %w", index, err)
		}
		protocol, err := normalizeProtocol(inputRule.Protocol)
		if err != nil {
			return nil, fmt.Errorf("traffic rule %d protocol: %w", index, err)
		}
		if inputRule.Peer == nil {
			return nil, fmt.Errorf("traffic rule %d peer is required", index)
		}
		parsed := net.ParseIP(strings.TrimSpace(inputRule.Peer.Address))
		if parsed == nil || parsed.To4() == nil || strings.Contains(inputRule.Peer.Address, ":") {
			return nil, fmt.Errorf("traffic rule %d peer address %q is not IPv4", index, inputRule.Peer.Address)
		}
		if inputRule.Peer.Port > 65535 {
			return nil, fmt.Errorf("traffic rule %d peer port %d exceeds 65535", index, inputRule.Peer.Port)
		}
		if inputRule.Peer.Port != 0 && protocol != 6 && protocol != 17 {
			return nil, fmt.Errorf("traffic rule %d uses a port with a non-TCP/UDP protocol", index)
		}
		var peerIP [4]byte
		copy(peerIP[:], parsed.To4())
		out.Rules = append(out.Rules, TrafficRule{
			Action:     action,
			Directions: directions,
			Protocol:   protocol,
			PeerIP:     peerIP,
			PeerPort:   uint16(inputRule.Peer.Port),
		})
	}
	return out, nil
}

func normalizeDNS(input *runtime.DNSPolicy) (*DNSPolicy, error) {
	defaultAction, err := normalizeAction(input.DefaultAction)
	if err != nil {
		return nil, fmt.Errorf("DNS default action: %w", err)
	}
	out := &DNSPolicy{DefaultAction: defaultAction, Rules: make([]DNSRule, 0, len(input.Rules))}
	for index, inputRule := range input.Rules {
		if inputRule == nil {
			return nil, fmt.Errorf("DNS rule %d is nil", index)
		}
		action, err := normalizeAction(inputRule.Action)
		if err != nil {
			return nil, fmt.Errorf("DNS rule %d action: %w", index, err)
		}
		name, wildcard, err := normalizeDomainPattern(inputRule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("DNS rule %d: %w", index, err)
		}
		out.Rules = append(out.Rules, DNSRule{Action: action, Name: name, Wildcard: wildcard})
	}
	return out, nil
}

func normalizeAction(action runtime.NetworkPolicyAction) (uint8, error) {
	switch action {
	case runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW:
		return actionAllow, nil
	case runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY:
		return actionDeny, nil
	default:
		return 0, fmt.Errorf("action must be ALLOW or DENY")
	}
}

func normalizeDirection(direction runtime.NetworkDirection) ([]uint8, error) {
	switch direction {
	case runtime.NetworkDirection_NETWORK_DIRECTION_INGRESS:
		return []uint8{directionIngress}, nil
	case runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS:
		return []uint8{directionEgress}, nil
	case runtime.NetworkDirection_NETWORK_DIRECTION_BOTH:
		return []uint8{directionIngress, directionEgress}, nil
	default:
		return nil, fmt.Errorf("direction must be INGRESS, EGRESS, or BOTH")
	}
}

func normalizeProtocol(protocol runtime.NetworkProtocol) (uint8, error) {
	switch protocol {
	case runtime.NetworkProtocol_NETWORK_PROTOCOL_ANY:
		return 0, nil
	case runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP:
		return 6, nil
	case runtime.NetworkProtocol_NETWORK_PROTOCOL_UDP:
		return 17, nil
	case runtime.NetworkProtocol_NETWORK_PROTOCOL_ICMP:
		return 1, nil
	default:
		return 0, fmt.Errorf("protocol must be ANY, TCP, UDP, or ICMP")
	}
}

func normalizeDomainPattern(pattern string) (string, bool, error) {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	if value == "" || strings.Contains(value, "*") || strings.Contains(value, "?") || len(value) > 253 {
		return "", false, fmt.Errorf("domain pattern %q is invalid", pattern)
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, fmt.Errorf("domain pattern %q is invalid", pattern)
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
				return "", false, fmt.Errorf("domain pattern %q is not ASCII/punycode", pattern)
			}
		}
	}
	return value, wildcard, nil
}

func (p Policy) Empty() bool {
	return p.Traffic == nil && p.DNS == nil
}

func (p Policy) AllowDNS(name string) bool {
	if p.DNS == nil {
		return true
	}
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	allowed := false
	for _, rule := range p.DNS.Rules {
		matched := name == rule.Name
		if rule.Wildcard {
			matched = len(name) > len(rule.Name) && strings.HasSuffix(name, "."+rule.Name)
		}
		if !matched {
			continue
		}
		if rule.Action == actionDeny {
			return false
		}
		allowed = true
	}
	if allowed {
		return true
	}
	return p.DNS.DefaultAction == actionAllow
}
