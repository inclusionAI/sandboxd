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

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	address := flag.String("address", "", "sandboxd Unix socket")
	sandboxID := flag.String("sandbox-id", "", "sandbox identifier")
	policyName := flag.String(
		"policy",
		"",
		"policy fixture: deny-all, allow-http, dns-deny-all, or clear",
	)
	peerAddress := flag.String("peer-address", "", "allow-http peer IPv4 address")
	peerPort := flag.Uint("peer-port", 0, "allow-http peer TCP port")
	flag.Parse()

	if *address == "" || *sandboxID == "" || *policyName == "" {
		flag.Usage()
		os.Exit(2)
	}
	policy, err := policyFixture(
		*policyName,
		*peerAddress,
		uint32(*peerPort),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(
		ctx,
		"passthrough:///sandboxd",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", *address)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to sandboxd: %v\n", err)
		os.Exit(1)
	}
	defer connection.Close()

	_, err = runtime.NewSandboxServiceClient(connection).SetNetworkPolicy(
		ctx,
		&runtime.SetNetworkPolicyRequest{
			SandboxID:     *sandboxID,
			NetworkPolicy: policy,
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "set network policy: %v\n", err)
		os.Exit(1)
	}
}

func policyFixture(
	name,
	peerAddress string,
	peerPort uint32,
) (*runtime.NetworkPolicy, error) {
	switch name {
	case "deny-all":
		return &runtime.NetworkPolicy{
			Traffic: &runtime.TrafficPolicy{
				DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
				Mode:          runtime.TrafficPolicyMode_TRAFFIC_POLICY_MODE_STATEFUL,
			},
		}, nil
	case "allow-http":
		if net.ParseIP(peerAddress).To4() == nil || peerPort == 0 || peerPort > 65535 {
			return nil, fmt.Errorf(
				"allow-http requires an IPv4 peer and a port in 1..65535",
			)
		}
		return &runtime.NetworkPolicy{
			Traffic: &runtime.TrafficPolicy{
				DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
				Mode:          runtime.TrafficPolicyMode_TRAFFIC_POLICY_MODE_STATEFUL,
				Rules: []*runtime.TrafficRule{{
					Action:    runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_ALLOW,
					Direction: runtime.NetworkDirection_NETWORK_DIRECTION_EGRESS,
					Protocol:  runtime.NetworkProtocol_NETWORK_PROTOCOL_TCP,
					Peer: &runtime.NetworkEndpoint{
						Address: peerAddress,
						Port:    peerPort,
					},
				}},
			},
		}, nil
	case "dns-deny-all":
		return &runtime.NetworkPolicy{
			Dns: &runtime.DNSPolicy{
				DefaultAction: runtime.NetworkPolicyAction_NETWORK_POLICY_ACTION_DENY,
			},
		}, nil
	case "clear":
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown policy fixture %q", name)
	}
}
