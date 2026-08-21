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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
)

// load reconciles durable leases against the versioned endpoint schema. Pooled
// runtimes recover only TAPs. runc's explicitly ephemeral veth/netns leases
// retain their independent lifecycle.
func (m *InterfaceManager) load(ips sets.Set[string]) error {
	_, ipv4Net, err := net.ParseCIDR(m.IpRange)
	if err != nil {
		return err
	}

	devs, err := m.interfacesOnHost()
	if err != nil {
		return err
	}

	hostIPs := sets.New[string]()
	peerByIP := make(map[string]net.Interface)
	tapByIP := make(map[string]net.Interface)
	for _, dev := range devs {
		switch {
		case strings.HasPrefix(dev.Name, config.HostVethPrefix):
			ip := util.VethToIp(dev.Name)
			if ip.To4() != nil && ipv4Net.Contains(ip) {
				hostIPs.Insert(ip.String())
			}
		case strings.HasPrefix(dev.Name, config.PeerVethPrefix):
			ip := util.VethToIp(dev.Name)
			if ip.To4() != nil && ipv4Net.Contains(ip) {
				peerByIP[ip.String()] = dev
			}
		case strings.HasPrefix(dev.Name, config.TapPrefix):
			ip := util.TapToIp(dev.Name)
			if ip.To4() != nil && ipv4Net.Contains(ip) {
				tapByIP[ip.String()] = dev
			}
		}
	}

	activeTapByIP := make(map[string]string)
	ephemeralLeases := make(map[string]*NetResource)
	for _, id := range m.usingInterfaces.Keys() {
		resource, parseErr := NewNetResource(id)
		if parseErr != nil {
			return fmt.Errorf("decode durable network lease: %w", parseErr)
		}
		if resource.Interface == nil {
			return fmt.Errorf("durable network lease is missing interface metadata: %s", id)
		}
		if resource.Lifecycle == InterfaceLifecycleEphemeral {
			ephemeralLeases[id] = resource
			continue
		}
		if resource.EndpointType == "" &&
			strings.HasPrefix(resource.Interface.Name, config.PeerVethPrefix) {
			return fmt.Errorf(
				"legacy pooled veth lease %s is still active; drain existing sandboxes before enabling the TAP interface cache",
				resource.Interface.Name,
			)
		}
		if resource.SchemaVersion != NetResourceSchemaVersion ||
			resource.EndpointType != EndpointTypeTap ||
			!strings.HasPrefix(resource.Interface.Name, config.TapPrefix) {
			return fmt.Errorf(
				"unsupported active pooled network lease schema=%d endpoint=%q interface=%q; drain existing sandboxes before upgrading",
				resource.SchemaVersion,
				resource.EndpointType,
				resource.Interface.Name,
			)
		}
		ip := resource.Ip.To4()
		if ip == nil || !ipv4Net.Contains(ip) {
			return fmt.Errorf("active pooled TAP lease has invalid IP %q", resource.Ip)
		}
		if previous, duplicate := activeTapByIP[ip.String()]; duplicate {
			return fmt.Errorf("duplicate active TAP leases for %s: %s and %s", ip, previous, id)
		}
		activeTapByIP[ip.String()] = id
		ips.Delete(ip.String())
	}

	// Ephemeral peers live in named namespaces, so host net.Interfaces cannot
	// see them. Reconcile their durable leases against the host end, which stays
	// visible and whose deterministic name encodes the allocated IP.
	ephemeralByIP := make(map[string]string)
	knownNetNS := sets.New[string]()
	for id, resource := range ephemeralLeases {
		ip := resource.Ip.String()
		if !hostIPs.Has(ip) {
			m.usingInterfaces.Pop(id)
			m.storeMark.Store(true)
			if deleteErr := m.deleteEphemeral(resource.NetNSPath); deleteErr != nil {
				logrus.Warnf("drop stale ephemeral lease %s: %v", id, deleteErr)
			}
			continue
		}
		if m.sandboxRoot != "" {
			sandboxID, idErr := sandboxIDFromEphemeralNetNSPath(resource.NetNSPath)
			if idErr != nil {
				ips.Delete(ip)
				logrus.Warnf("retain invalid ephemeral lease %s: %v", id, idErr)
				continue
			}
			metadataPath := filepath.Join(m.sandboxRoot, sandboxID, config.SandboxMetaFile)
			if _, statErr := os.Stat(metadataPath); os.IsNotExist(statErr) {
				if destroyErr := m.destroyDevice(*resource.Interface); destroyErr != nil {
					ips.Delete(ip)
					logrus.Warnf("retain orphaned ephemeral lease %s: %v", id, destroyErr)
					continue
				}
				hostIPs.Delete(ip)
				m.usingInterfaces.Pop(id)
				m.storeMark.Store(true)
				if deleteErr := m.deleteEphemeral(resource.NetNSPath); deleteErr != nil {
					logrus.Warnf("delete orphaned ephemeral namespace %s: %v", resource.NetNSPath, deleteErr)
				}
				continue
			} else if statErr != nil {
				ips.Delete(ip)
				logrus.Warnf("retain ephemeral lease %s after metadata check failed: %v", id, statErr)
				continue
			}
		}
		ephemeralByIP[ip] = id
		knownNetNS.Insert(filepath.Clean(resource.NetNSPath))
		ips.Delete(ip)
	}

	for ip, dev := range tapByIP {
		link, linkErr := m.links().LinkByName(dev.Name)
		if linkErr != nil {
			return fmt.Errorf("recover pooled TAP %s: %w", dev.Name, linkErr)
		}
		current, resourceErr := m.tapResource(link, net.ParseIP(ip))
		if resourceErr != nil {
			return resourceErr
		}
		if activeID, active := activeTapByIP[ip]; active {
			stored, parseErr := NewNetResource(activeID)
			if parseErr != nil {
				return parseErr
			}
			if stateErr := m.setTapState(stored, true); stateErr != nil {
				return fmt.Errorf("recover active pooled TAP %s: %w", dev.Name, stateErr)
			}
		} else {
			if stateErr := m.setTapState(current, false); stateErr != nil {
				return fmt.Errorf("recover idle pooled TAP %s: %w", dev.Name, stateErr)
			}
			m.interfaces.Push(current.ToString())
		}
		ips.Delete(ip)
	}
	for ip, id := range activeTapByIP {
		if _, found := tapByIP[ip]; !found {
			return fmt.Errorf("active pooled TAP for %s is missing (lease %s)", ip, id)
		}
	}

	// Pooled veth pairs from the pre-TAP cache are safe to remove only when no
	// durable lease owns them. Active legacy leases failed startup above.
	for ip, dev := range peerByIP {
		if !hostIPs.Has(ip) {
			continue
		}
		if _, active := ephemeralByIP[ip]; active {
			return fmt.Errorf("ephemeral veth peer %s unexpectedly remains in the host namespace", dev.Name)
		}
		if destroyErr := m.destroyDevice(dev); destroyErr != nil {
			ips.Delete(ip)
			logrus.Warnf("retain legacy idle veth for %s after cleanup failure: %v", ip, destroyErr)
			continue
		}
		hostIPs.Delete(ip)
		logrus.Infof("deleted legacy idle pooled veth for %s during TAP cache migration", ip)
	}

	// A host end without a durable ephemeral lease can only be left by an
	// interrupted allocation. Delete it rather than making its IP allocatable.
	for ip := range hostIPs {
		if _, active := ephemeralByIP[ip]; active {
			continue
		}
		_, peerName := util.IpToVeth(ip)
		if destroyErr := m.destroyDevice(net.Interface{Name: peerName}); destroyErr != nil {
			ips.Delete(ip)
			logrus.Warnf("retain orphaned host veth for %s after cleanup failure: %v", ip, destroyErr)
		} else {
			logrus.Warnf("deleted orphaned ephemeral host veth for %s", ip)
		}
	}

	entries, readErr := m.ephemeralNamespaces()
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ephemeralNetNSPrefix) {
			continue
		}
		path := filepath.Join(ephemeralNetNSRoot, entry.Name())
		if knownNetNS.Has(path) {
			continue
		}
		if deleteErr := m.deleteEphemeral(path); deleteErr != nil {
			logrus.Warnf("delete orphaned ephemeral namespace %s: %v", path, deleteErr)
		}
	}

	for _, ip := range ips.UnsortedList() {
		if ipv4Net.Contains(net.ParseIP(ip)) {
			m.idleIp.Push(ip)
		}
	}

	logrus.Debugf(
		"load network interface idle num: %v, using num: %v, idle ip: %v",
		m.interfaces.Length(),
		m.usingInterfaces.Count(),
		m.idleIp.Length(),
	)
	return nil
}
