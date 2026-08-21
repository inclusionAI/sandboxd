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

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// NetResourceSchemaVersion is bumped when the persisted endpoint contract
	// changes incompatibly.
	NetResourceSchemaVersion = 1

	EndpointTypeTap  = "tap"
	EndpointTypeVeth = "veth"
)

func deterministicMAC(prefix byte, ip net.IP) (net.HardwareAddr, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("deterministic endpoint MAC requires IPv4, got %q", ip)
	}
	return net.HardwareAddr{0x02, prefix, ip4[0], ip4[1], ip4[2], ip4[3]}, nil
}

// GuestHardwareAddr returns the MAC presented inside a sandbox. Legacy veth
// resources used the peer MAC for both the host endpoint and the guest link.
func (n *NetResource) GuestHardwareAddr() net.HardwareAddr {
	if n == nil {
		return nil
	}
	if len(n.GuestMAC) != 0 {
		return append(net.HardwareAddr(nil), n.GuestMAC...)
	}
	if n.Interface == nil {
		return nil
	}
	return append(net.HardwareAddr(nil), n.Interface.HardwareAddr...)
}

func tapHostMAC(ip net.IP) (net.HardwareAddr, error) {
	return deterministicMAC(0xfd, ip)
}

func tapGuestMAC(ip net.IP) (net.HardwareAddr, error) {
	return deterministicMAC(0xfc, ip)
}

func interfaceFromLink(link netlink.Link) *net.Interface {
	attrs := link.Attrs()
	return &net.Interface{
		Index:        attrs.Index,
		MTU:          attrs.MTU,
		Name:         attrs.Name,
		HardwareAddr: append(net.HardwareAddr(nil), attrs.HardwareAddr...),
		Flags:        attrs.Flags,
	}
}

func (m *InterfaceManager) createTapDevice(ip string) (netlink.Link, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP.To4() == nil {
		return nil, fmt.Errorf("create TAP requires IPv4, got %q", ip)
	}
	name := util.IpToTap(ip)
	if existing, err := netlink.LinkByName(name); err == nil && existing != nil {
		return nil, fmt.Errorf("refuse to replace existing TAP %s", name)
	} else if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("query TAP %s: %w", name, err)
		}
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	if m.bridgeLink != nil && m.bridgeLink.Attrs().MTU > 0 {
		attrs.MTU = m.bridgeLink.Attrs().MTU
	}
	tap := &netlink.Tuntap{
		LinkAttrs: attrs,
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TuntapFlag(unix.IFF_NO_PI),
	}
	if err := netlink.LinkAdd(tap); err != nil {
		return nil, fmt.Errorf("create persistent TAP %s: %w", name, err)
	}
	cleanup := func() {
		if current, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(current)
		}
	}

	current, err := netlink.LinkByName(name)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("find created TAP %s: %w", name, err)
	}
	hostMAC, err := tapHostMAC(parsedIP)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := netlink.LinkSetHardwareAddr(current, hostMAC); err != nil {
		cleanup()
		return nil, fmt.Errorf("set TAP %s host MAC: %w", name, err)
	}
	if err := netlink.LinkSetMaster(current, m.bridgeLink); err != nil {
		cleanup()
		return nil, fmt.Errorf("attach TAP %s to %s: %w", name, BridgeName, err)
	}
	if err := netlink.LinkSetDown(current); err != nil {
		cleanup()
		return nil, fmt.Errorf("set idle TAP %s down: %w", name, err)
	}
	current, err = netlink.LinkByName(name)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("reload TAP %s: %w", name, err)
	}
	return current, nil
}

func (m *InterfaceManager) tapResource(link netlink.Link, ip net.IP) (*NetResource, error) {
	guestMAC, err := tapGuestMAC(ip)
	if err != nil {
		return nil, err
	}
	return &NetResource{
		SchemaVersion: NetResourceSchemaVersion,
		EndpointType:  EndpointTypeTap,
		GuestMAC:      guestMAC,
		Interface:     interfaceFromLink(link),
		Ip:            append(net.IP(nil), ip...),
		Mask:          append(net.IPMask(nil), m.mask...),
		Gateway:       append(net.IP(nil), m.BridgeIp...),
		Type:          "bridge",
	}, nil
}

func (m *InterfaceManager) setTapState(resource *NetResource, up bool) error {
	if resource == nil || resource.Interface == nil {
		return errors.New("TAP resource interface is missing")
	}
	if resource.SchemaVersion > NetResourceSchemaVersion {
		return fmt.Errorf(
			"unsupported network resource schema %d (max %d)",
			resource.SchemaVersion,
			NetResourceSchemaVersion,
		)
	}
	if resource.EndpointType != EndpointTypeTap {
		return nil
	}
	ip4 := resource.Ip.To4()
	if ip4 == nil {
		return fmt.Errorf("TAP resource has invalid IPv4 address %q", resource.Ip)
	}
	expectedName := util.IpToTap(ip4.String())
	if resource.Interface.Name != expectedName {
		return fmt.Errorf(
			"TAP resource identity mismatch: interface %q, want %q",
			resource.Interface.Name,
			expectedName,
		)
	}
	link, err := netlink.LinkByName(expectedName)
	if err != nil {
		return fmt.Errorf("find pooled TAP %s: %w", expectedName, err)
	}
	if link.Type() != "tuntap" {
		return fmt.Errorf("pooled endpoint %s has type %q, want tuntap", expectedName, link.Type())
	}
	if m.bridgeLink == nil || link.Attrs().MasterIndex != m.bridgeLink.Attrs().Index {
		return fmt.Errorf("pooled TAP %s is not attached to %s", expectedName, BridgeName)
	}
	expectedHostMAC, _ := tapHostMAC(ip4)
	if !bytes.Equal(link.Attrs().HardwareAddr, expectedHostMAC) {
		return fmt.Errorf(
			"pooled TAP %s host MAC is %s, want %s",
			expectedName,
			link.Attrs().HardwareAddr,
			expectedHostMAC,
		)
	}
	expectedGuestMAC, _ := tapGuestMAC(ip4)
	if !bytes.Equal(resource.GuestHardwareAddr(), expectedGuestMAC) {
		return fmt.Errorf(
			"pooled TAP %s guest MAC is %s, want %s",
			expectedName,
			resource.GuestHardwareAddr(),
			expectedGuestMAC,
		)
	}
	if resource.Interface.Index != 0 && resource.Interface.Index != link.Attrs().Index {
		return fmt.Errorf(
			"pooled TAP %s index is %d, lease records %d",
			expectedName,
			link.Attrs().Index,
			resource.Interface.Index,
		)
	}
	if up {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("activate pooled TAP %s: %w", expectedName, err)
		}
		return nil
	}
	if err := netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("deactivate pooled TAP %s: %w", expectedName, err)
	}
	return nil
}
