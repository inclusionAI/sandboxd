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

package util

import (
	"github.com/inclusionAI/sandboxd/config"
	"net"
	"testing"
)

func TestIpToVeth(t *testing.T) {
	type args struct {
		ip string
	}
	tests := []struct {
		name     string
		args     args
		wantHost string
		wantPeer string
	}{
		{
			name:     "test1",
			args:     args{ip: "172.17.0.24"},
			wantHost: config.HostVethPrefix + "ac110018",
			wantPeer: config.PeerVethPrefix + "ac110018",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPeer := IpToVeth(tt.args.ip)
			if gotHost != tt.wantHost {
				t.Errorf("IpToVeth() gotHost = %v, want %v", gotHost, tt.wantHost)
			}
			if gotPeer != tt.wantPeer {
				t.Errorf("IpToVeth() gotPeer = %v, want %v", gotPeer, tt.wantPeer)
			}
		})
	}
}

func TestVethToIp(t *testing.T) {
	type args struct {
		veth string
	}
	tests := []struct {
		name string
		args args
		want net.IP
	}{
		{
			name: "from host veth",
			args: args{
				veth: config.HostVethPrefix + "ac110018",
			},
			want: net.ParseIP("172.17.0.24"),
		},
		{
			name: "from peer veth",
			args: args{
				veth: config.PeerVethPrefix + "ac110018",
			},
			want: net.ParseIP("172.17.0.24"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VethToIp(tt.args.veth); got.String() != tt.want.String() {
				t.Errorf("VethToIp(%s) = %v, want %v", tt.args.veth, got, tt.want)
			}
		})
	}
}

func TestGenerateIp(t *testing.T) {
	gatewayIp, mask, ips, err := GenerateIp("172.17.0.1/16", 1000)
	if err != nil {
		t.Errorf("GenerateIp() error = %v", err)
	} else {
		t.Logf("GenerateIp() gatewayIp = %v, mask = %v", gatewayIp, mask)
	}
	for _, ip := range ips.UnsortedList() {
		if ip == gatewayIp.String() {
			t.Errorf("GenerateIp() gatewayIp = %v, unwant %v", gatewayIp, ip)
		}
	}
}
