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
	containerLoName  = "lo"
	rawSocketBufSize = 4 << 20 // 4 MiB.
	vethGSOMaxSize   = 65536
	qDiscFIFO        = 1
)

// NetworkConfig contains the host-side veth peer and the in-sandbox network
// configuration that should be installed through gVisor's control RPC.
type NetworkConfig struct {
	Interface *net.Interface
	IP        net.IP
	Mask      net.IPMask
	Gateway   net.IP
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

// OpenRawSocket opens an AF_PACKET raw socket bound to iface. The returned file
// is ready to be passed to gVisor through urpc.FilePayload.
func OpenRawSocket(iface net.Interface) (_ *os.File, retErr error) {
	const protocol = 0x0300 // htons(ETH_P_ALL)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create raw socket for %s: %w", iface.Name, err)
	}
	file := os.NewFile(uintptr(fd), "runsc-raw-device-fd")
	defer func() {
		if retErr != nil {
			_ = file.Close()
		}
	}()

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: protocol,
		Ifindex:  iface.Index,
		Pkttype:  unix.PACKET_OTHERHOST,
	}); err != nil {
		return nil, fmt.Errorf("bind raw socket to %s(index=%d): %w", iface.Name, iface.Index, err)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
		return nil, fmt.Errorf("enable PACKET_VNET_HDR on %s(index=%d): %w", iface.Name, iface.Index, err)
	}

	setSocketBuffer(fd, unix.SO_RCVBUFFORCE, unix.SO_RCVBUF)
	setSocketBuffer(fd, unix.SO_SNDBUFFORCE, unix.SO_SNDBUF)

	return file, nil
}

func setSocketBuffer(fd, forceOpt, fallbackOpt int) {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, forceOpt, rawSocketBufSize); err == nil {
		return
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, fallbackOpt, rawSocketBufSize)
}

// BuildNetworkArgs converts sandboxd's bridge/veth allocation into the
// upstream gVisor CreateLinksAndRoutes RPC payload.
func BuildNetworkArgs(network NetworkConfig, rawSocket *os.File) (*createLinksAndRoutesArgs, error) {
	if network.Interface == nil {
		return nil, fmt.Errorf("network interface is nil")
	}
	if rawSocket == nil {
		return nil, fmt.Errorf("raw socket is nil")
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
			Files: []*os.File{rawSocket},
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
				LinkAddress: network.Interface.HardwareAddr,
				Addresses: []ipWithPrefix{
					{Address: ip4, PrefixLen: prefixLen},
				},
				Routes: []route{
					{Destination: subnet},
				},
				GSOMaxSize:        vethGSOMaxSize,
				QDisc:             qDiscFIFO,
				RXChecksumOffload: true,
				NumChannels:       1,
			},
		},
		Defaultv4Gateway: defaultRoute{
			Route: defaultRouteValue,
			Name:  network.Interface.Name,
		},
	}, nil
}
