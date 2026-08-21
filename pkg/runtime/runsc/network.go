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
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	containerLoName = "lo"
	qDiscFIFO       = 1
)

// NetworkConfig contains the host-side TAP and the in-sandbox network
// configuration installed through gVisor's control RPC.
type NetworkConfig struct {
	Interface   *net.Interface
	LinkAddress net.HardwareAddr
	IP          net.IP
	Mask        net.IPMask
	Gateway     net.IP
}

type ipWithPrefix struct {
	Address   net.IP
	PrefixLen int
}

type route struct {
	Destination net.IPNet
	Gateway     net.IP
	MTU         uint32
}

type defaultRoute struct {
	Route route
	Name  string
}

type loopbackLink struct {
	Name      string
	Addresses []ipWithPrefix
	Routes    []route
	GVisorGRO bool
}

type neighbor struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

type fdBasedLink struct {
	Name                 string
	InterfaceIndex       int
	MTU                  int
	Addresses            []ipWithPrefix
	Routes               []route
	GSOMaxSize           uint32
	GVisorGSOEnabled     bool
	GVisorGRO            bool
	TXChecksumOffload    bool
	RXChecksumOffload    bool
	LinkAddress          net.HardwareAddr
	QDisc                int
	TBFRate              uint64
	TBFBurst             uint32
	Neighbors            []neighbor
	NumChannels          int
	ProcessorsPerChannel int
}

type createLinksAndRoutesArgs struct {
	payload filePayload

	LoopbackLinks []loopbackLink
	FDBasedLinks  []fdBasedLink

	Defaultv4Gateway defaultRoute
	Defaultv6Gateway defaultRoute

	PCAP                    bool
	LogPackets              bool
	NATBlob                 bool
	PauseExternalNetworking bool
	AllowConnectedOnSave    bool
}

func (a *createLinksAndRoutesArgs) filePayload() []*os.File {
	return a.payload.Files
}

func (a *createLinksAndRoutesArgs) setFilePayload(files []*os.File) {
	a.payload.Files = files
}

// OpenTAP attaches one non-blocking queue to a cached persistent TAP. gVisor
// consumes ordinary Ethernet frames, so this FD deliberately omits IFF_VNET_HDR;
// Kata and Firecracker request vnet headers on their own TAP queues.
func OpenTAP(iface net.Interface) (_ *os.File, retErr error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun for %s: %w", iface.Name, err)
	}
	file := os.NewFile(uintptr(fd), "runsc-tap-device-fd")
	defer func() {
		if retErr != nil {
			_ = file.Close()
		}
	}()

	ifreq, err := unix.NewIfreq(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("build TAP request for %s: %w", iface.Name, err)
	}
	ifreq.SetUint16(uint16(unix.IFF_TAP | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifreq); err != nil {
		return nil, fmt.Errorf("attach runsc to TAP %s: %w", iface.Name, err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("set runsc TAP %s non-blocking: %w", iface.Name, err)
	}
	return file, nil
}

// BuildNetworkArgs converts sandboxd's bridge/TAP allocation into the
// upstream gVisor SetNetworkArgs RPC payload.
func BuildNetworkArgs(network NetworkConfig, tap *os.File) (*createLinksAndRoutesArgs, error) {
	if network.Interface == nil {
		return nil, fmt.Errorf("network interface is nil")
	}
	if tap == nil {
		return nil, fmt.Errorf("TAP file is nil")
	}
	if len(network.LinkAddress) == 0 {
		return nil, fmt.Errorf("guest link MAC is empty")
	}
	ip4 := network.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 network is supported in the first open-source runsc adapter, got %q", network.IP)
	}
	gateway4 := network.Gateway.To4()
	if gateway4 == nil {
		return nil, fmt.Errorf("only IPv4 gateway is supported in the first open-source runsc adapter, got %q", network.Gateway)
	}
	prefixLen, bits := network.Mask.Size()
	if bits != 32 || prefixLen <= 0 {
		return nil, fmt.Errorf("invalid IPv4 mask %v", network.Mask)
	}

	subnet := net.IPNet{
		IP:   ip4.Mask(network.Mask),
		Mask: network.Mask,
	}
	defaultRouteValue := route{
		Destination: net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
		Gateway: gateway4,
	}

	return &createLinksAndRoutesArgs{
		payload: filePayload{
			Files: []*os.File{tap},
		},
		LoopbackLinks: []loopbackLink{
			{
				Name: containerLoName,
				Addresses: []ipWithPrefix{
					{Address: net.IPv4(127, 0, 0, 1), PrefixLen: 8},
					{Address: net.IPv6loopback, PrefixLen: 128},
				},
			},
		},
		FDBasedLinks: []fdBasedLink{
			{
				Name:        network.Interface.Name,
				MTU:         network.Interface.MTU,
				LinkAddress: network.LinkAddress,
				Addresses: []ipWithPrefix{
					{Address: ip4, PrefixLen: prefixLen},
				},
				Routes: []route{
					{Destination: subnet},
				},
				QDisc:       qDiscFIFO,
				NumChannels: 1,
			},
		},
		Defaultv4Gateway: defaultRoute{
			Route: defaultRouteValue,
			Name:  network.Interface.Name,
		},
	}, nil
}
