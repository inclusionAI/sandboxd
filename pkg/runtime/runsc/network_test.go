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

package runsc

import (
	"net"
	"os"
	"testing"
)

func TestBuildNetworkArgsConfiguresDualStackLoopback(t *testing.T) {
	rawSocket, err := os.CreateTemp(t.TempDir(), "raw-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer rawSocket.Close()

	args, err := BuildNetworkArgs(NetworkConfig{
		Interface: &net.Interface{
			Index:        1,
			MTU:          1500,
			Name:         "eth0",
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		},
		IP:      net.ParseIP("10.88.0.2"),
		Mask:    net.CIDRMask(24, 32),
		Gateway: net.ParseIP("10.88.0.1"),
	}, rawSocket)
	if err != nil {
		t.Fatal(err)
	}
	if len(args.LoopbackLinks) != 1 {
		t.Fatalf("loopback links = %+v", args.LoopbackLinks)
	}

	want := map[string]int{
		"127.0.0.1": 8,
		"::1":       128,
	}
	got := make(map[string]int)
	for _, address := range args.LoopbackLinks[0].Addresses {
		got[address.Address.String()] = address.PrefixLen
	}
	if len(got) != len(want) {
		t.Fatalf("loopback addresses = %+v, want %+v", got, want)
	}
	for address, prefixLen := range want {
		if got[address] != prefixLen {
			t.Fatalf("loopback address %s/%d missing from %+v", address, prefixLen, got)
		}
	}
}
