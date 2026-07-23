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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/inclusionAI/sandboxd/config"
	"k8s.io/apimachinery/pkg/util/sets"
)

func GenerateIp(ipRange string, maxNum uint32) (net.IP, net.IPMask, sets.Set[string], error) {
	gateway, ipv4Net, err := net.ParseCIDR(ipRange)
	if err != nil {
		return net.IPv4zero, nil, nil, err
	}
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(gateway.To4())

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	if finish-start < maxNum {
		return net.IPv4zero, nil, nil, fmt.Errorf("ip range is too small, should be at least %d", maxNum)
	}

	ipset := sets.New[string]()

	for i := start; i < start+maxNum; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		if ip.String() == gateway.String() {
			continue
		}
		ipset.Insert(ip.String())
	}
	return gateway, ipv4Net.Mask, ipset, nil
}

func IpToVeth(ip string) (host, peer string) {
	parsedIp := net.ParseIP(ip)
	ipInHex := hex.EncodeToString(parsedIp.To4())
	return config.HostVethPrefix + ipInHex, config.PeerVethPrefix + ipInHex
}

func VethToIp(veth string) net.IP {
	if strings.HasPrefix(veth, config.HostVethPrefix) {
		veth = veth[len(config.HostVethPrefix):]
	} else if strings.HasPrefix(veth, config.PeerVethPrefix) {
		veth = veth[len(config.PeerVethPrefix):]
	}
	ip, _ := hex.DecodeString(veth)
	return ip
}
