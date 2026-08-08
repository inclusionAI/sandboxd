// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package networkacl

import (
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizePolicyAndDNSMatching(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
		Rules: []*runtime.DNSRule{
			{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "GitHub.COM."},
			{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "*.github.com"},
		},
	}})
	require.NoError(t, err)
	assert.False(t, policy.AllowDNS("github.com."))
	assert.False(t, policy.AllowDNS("api.github.com."))
	assert.False(t, policy.AllowDNS("a.b.github.com."))
	assert.True(t, policy.AllowDNS("notgithub.com."))
}

func TestDNSDenyWins(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
		Rules: []*runtime.DNSRule{
			{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW, Pattern: "*.example.com"},
			{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "blocked.example.com"},
		},
	}})
	require.NoError(t, err)
	assert.True(t, policy.AllowDNS("ok.example.com"))
	assert.False(t, policy.AllowDNS("blocked.example.com"))
	assert.False(t, policy.AllowDNS("example.com"))
}

func TestNormalizeDNSAllowsServiceDiscoveryOwnerNames(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
		Rules: []*runtime.DNSRule{{
			Action:  runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Pattern: "_grpc._tcp.example.com",
		}},
	}})
	require.NoError(t, err)
	assert.True(t, policy.AllowDNS("_grpc._tcp.example.com."))
}

func TestNormalizeTrafficPolicy(t *testing.T) {
	policy, err := NormalizePolicy(&runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{
		DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
		Rules: []*runtime.TrafficRule{{
			Action:    runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Direction: runtime.NetworkDirection_NETWORK_DIRECTION_BOTH,
			Protocol:  runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
			Peer:      &runtime.NetworkEndpoint{Address: "10.88.0.1", Port: 8080},
		}},
	}})
	require.NoError(t, err)
	require.Len(t, policy.Traffic.Rules, 1)
	assert.Equal(t, []uint8{directionIngress, directionEgress}, policy.Traffic.Rules[0].Directions)
	assert.Equal(t, uint8(6), policy.Traffic.Rules[0].Protocol)
}

func TestNormalizePolicyRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		policy *runtime.NetworkPolicy
	}{
		{name: "unspecified default", policy: &runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{}}},
		{name: "IPv6", policy: &runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{
			DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Rules: []*runtime.TrafficRule{{
				Action:    runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
				Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
				Protocol:  runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
				Peer:      &runtime.NetworkEndpoint{Address: "2001:db8::1", Port: 443},
			}},
		}}},
		{name: "port with any", policy: &runtime.NetworkPolicy{Traffic: &runtime.TrafficPolicy{
			DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Rules: []*runtime.TrafficRule{{
				Action:    runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
				Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
				Protocol:  runtime.NetworkProtocol_NETWORK_PROTOCOL_ANY,
				Peer:      &runtime.NetworkEndpoint{Address: "192.0.2.1", Port: 443},
			}},
		}}},
		{name: "arbitrary glob", policy: &runtime.NetworkPolicy{Dns: &runtime.DNSPolicy{
			DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
			Rules:         []*runtime.DNSRule{{Action: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY, Pattern: "api.*.example.com"}},
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NormalizePolicy(test.policy)
			require.Error(t, err)
		})
	}
}
