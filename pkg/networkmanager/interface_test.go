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
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	gomonkey "github.com/agiledragon/gomonkey/v2"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func initInterfaceCacheForCleanup() *InterfaceManager {
	im := &InterfaceManager{
		interfaces:      util.New(""),
		usingInterfaces: cmap.New[struct{}](),
	}

	im.interfaces.Push(`{"interface":{"Index":21298,"MTU":1500,"Name":"pv.ac1100ad","HardwareAddr":"+gJCgdfr","Flags":51},"ip":"172.17.0.173","mask":"//8AAA==","gateway":"172.17.0.1","type":"bridge"}`)
	im.interfaces.Push("")
	im.interfaces.Push("invalid interface")

	return im
}

func TestInterfaceCleanupIncludesLeasedInterfaces(t *testing.T) {
	m := &InterfaceManager{
		interfaces:      util.New(""),
		usingInterfaces: cmap.New[struct{}](),
	}
	idle := `{"interface":{"Name":"pv.ac1100ad"},"ip":"172.17.0.173","type":"bridge"}`
	using := `{"interface":{"Name":"pv.ac1100ae"},"ip":"172.17.0.174","type":"bridge"}`
	m.interfaces.Push(idle)
	m.usingInterfaces.Set(using, struct{}{})

	var destroyed []string
	patch := gomonkey.ApplyPrivateMethod(
		m,
		"destroyDevice",
		func(_ *InterfaceManager, device net.Interface) error {
			destroyed = append(destroyed, device.Name)
			return nil
		},
	)
	defer patch.Reset()

	assert.NoError(t, m.cleanup())
	assert.ElementsMatch(t, []string{"pv.ac1100ad", "pv.ac1100ae"}, destroyed)
}

func TestInterfaceCleanup(t *testing.T) {
	m := initInterfaceCacheForCleanup()
	destroyDeviceFailedPatch := gomonkey.ApplyPrivateMethod(m, "destroyDevice", func(*InterfaceManager, net.Interface) error {
		return errors.New("fake destroyDevice error")
	})
	defer destroyDeviceFailedPatch.Reset()

	m.cleanup()

	destroyDeviceSuccessPatch := gomonkey.ApplyPrivateMethod(m, "destroyDevice", func(*InterfaceManager, net.Interface) error {
		return nil
	})
	defer destroyDeviceSuccessPatch.Reset()

	m.cleanup()
}

func TestInterfaceCleanup_IgnoresResourceWithoutInterface(t *testing.T) {
	m := &InterfaceManager{
		interfaces:      util.New(""),
		usingInterfaces: cmap.New[struct{}](),
	}
	m.interfaces.Push((&NetResource{
		Ip:      net.ParseIP("172.17.0.173"),
		Mask:    net.CIDRMask(16, 32),
		Gateway: net.ParseIP("172.17.0.1"),
		Type:    "bridge",
	}).ToString())

	assert.NotPanics(t, func() {
		m.cleanup()
	})
}

func TestCalcluteCacheSize(t *testing.T) {
	rawCacheSize := 10000
	getLocalCpuNumPatches := gomonkey.ApplyFunc(getLocalCpuNum, func() (int, error) {
		return 2, nil
	})
	cacheSize := calcluteCacheSize(rawCacheSize)
	getLocalCpuNumPatches.Reset()
	assert.Equal(t, 4, cacheSize)

	getLocalCpuNumPatches = gomonkey.ApplyFunc(getLocalCpuNum, func() (int, error) {
		return 1, errors.New("fake error for getLocalCpuNum")
	})
	defer getLocalCpuNumPatches.Reset()

	cacheSize = calcluteCacheSize(rawCacheSize)
	assert.Equal(t, rawCacheSize, cacheSize)
}

func TestDestroyDevice(t *testing.T) {
	t.Run("missing link", func(t *testing.T) {
		ops := &fakeLinkOperations{lookupErr: netlink.LinkNotFoundError{}}
		m := &InterfaceManager{linkOps: ops}
		assert.NoError(t, m.destroyDevice(net.Interface{Name: "eth0"}))
		assert.Nil(t, ops.deleted)
	})

	t.Run("delete link", func(t *testing.T) {
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "host-veth"}}
		ops := &fakeLinkOperations{link: link}
		m := &InterfaceManager{linkOps: ops}
		assert.NoError(t, m.destroyDevice(net.Interface{Name: "eth0"}))
		assert.Same(t, link, ops.deleted)
		assert.NotEmpty(t, ops.lookupName)
	})

	t.Run("lookup error", func(t *testing.T) {
		ops := &fakeLinkOperations{lookupErr: errors.New("lookup failed")}
		m := &InterfaceManager{linkOps: ops}
		err := m.destroyDevice(net.Interface{Name: "eth0"})
		assert.ErrorContains(t, err, "lookup failed")
	})

	t.Run("delete error", func(t *testing.T) {
		ops := &fakeLinkOperations{
			link:      &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "host-veth"}},
			deleteErr: errors.New("delete failed"),
		}
		m := &InterfaceManager{linkOps: ops}
		err := m.destroyDevice(net.Interface{Name: "eth0"})
		assert.ErrorContains(t, err, "delete failed")
	})
}

func TestDisablePeerForwarding(t *testing.T) {
	root := t.TempDir()
	peerName := config.PeerVethPrefix + "0afa01f7"
	peerDir := filepath.Join(root, peerName)
	require.NoError(t, os.Mkdir(peerDir, 0755))
	forwardingPath := filepath.Join(peerDir, "forwarding")
	require.NoError(t, os.WriteFile(forwardingPath, []byte("1\n"), 0644))

	m := &InterfaceManager{sysctlRoot: root}
	require.NoError(t, m.disablePeerForwarding(peerName))
	value, err := os.ReadFile(forwardingPath)
	require.NoError(t, err)
	assert.Equal(t, "0\n", string(value))
}

func TestDisablePeerForwardingRejectsNonPeerInterface(t *testing.T) {
	m := &InterfaceManager{sysctlRoot: t.TempDir()}
	err := m.disablePeerForwarding(config.HostVethPrefix + "0afa01f7")
	assert.ErrorContains(t, err, "non-peer interface")
}

type fakeLinkOperations struct {
	link       netlink.Link
	lookupErr  error
	deleteErr  error
	lookupName string
	deleted    netlink.Link
}

type cleanupNetworkManager struct {
	cleanedRanges []string
	cleanupErr    error
}

func (*cleanupNetworkManager) SetupSNATRules(string) error { return nil }
func (m *cleanupNetworkManager) CleanupSNATRules(ipRange string) error {
	m.cleanedRanges = append(m.cleanedRanges, ipRange)
	return m.cleanupErr
}
func (*cleanupNetworkManager) SetupNetworkRulesForActivating(net.IP, string) error { return nil }
func (*cleanupNetworkManager) CleanupNetworkRulesForActivating(net.IP) error       { return nil }
func (*cleanupNetworkManager) SetupDNATRule(string, uint16, string, uint16) error  { return nil }
func (*cleanupNetworkManager) CleanupDNATRule(string, uint16, string, uint16) error {
	return nil
}

func TestInterfaceShutdownCleansSNATAndOwnedBridge(t *testing.T) {
	const backend = "shutdown-cleanup-test"
	nat := &cleanupNetworkManager{}
	NetworkManagers[backend] = nat
	t.Cleanup(func() {
		delete(NetworkManagers, backend)
	})

	bridge := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: BridgeName, Index: 42},
	}
	links := &fakeLinkOperations{link: bridge}
	m := &InterfaceManager{
		interfaces:      util.New(""),
		usingInterfaces: cmap.New[struct{}](),
		idleIp:          util.New(""),
		createReqs:      make(chan *createRequest, 1),
		IpRange:         "172.30.252.1/22",
		bridgeLink:      bridge,
		linkOps:         links,
		natBackend:      backend,
		stopCh:          make(chan struct{}),
		runDoneCh:       make(chan struct{}),
		storeDoneCh:     make(chan struct{}),
	}
	m.keepStoring()
	go m.run()

	assert.NoError(t, m.ShutDown())
	assert.Equal(t, []string{"172.30.252.1/22"}, nat.cleanedRanges)
	assert.Same(t, bridge, links.deleted)

	// Shutdown is idempotent: a second call must not touch host networking.
	assert.NoError(t, m.ShutDown())
	assert.Len(t, nat.cleanedRanges, 1)
}

func TestInterfaceShutdownWaitsForAllocationHandoff(t *testing.T) {
	const backend = "shutdown-allocation-test"
	nat := &cleanupNetworkManager{}
	NetworkManagers[backend] = nat
	t.Cleanup(func() {
		delete(NetworkManagers, backend)
	})

	const resource = `{"interface":{"Name":"pv.ac1100ae"},"ip":"172.17.0.174","type":"bridge"}`
	db := store.NewMockStore()
	m := &InterfaceManager{
		db:              db,
		size:            1,
		interfaces:      util.New(""),
		usingInterfaces: cmap.New[struct{}](),
		idleIp:          util.New(""),
		createReqs:      make(chan *createRequest, 1),
		natBackend:      backend,
		stopCh:          make(chan struct{}),
		runDoneCh:       make(chan struct{}),
	}

	handoffStarted := make(chan struct{})
	finishHandoff := make(chan struct{})
	go func() {
		req := <-m.createReqs
		req.result <- createResult{id: resource}
		close(m.runDoneCh)
	}()

	handoffPatch := gomonkey.ApplyPrivateMethod(
		m,
		"markUsing",
		func(manager *InterfaceManager, value string) (string, error) {
			close(handoffStarted)
			<-finishHandoff
			manager.usingInterfaces.Set(value, struct{}{})
			return value, nil
		},
	)
	defer handoffPatch.Reset()

	var destroyed []string
	destroyPatch := gomonkey.ApplyPrivateMethod(
		m,
		"destroyDevice",
		func(_ *InterfaceManager, device net.Interface) error {
			destroyed = append(destroyed, device.Name)
			return nil
		},
	)
	defer destroyPatch.Reset()

	allocationDone := make(chan error, 1)
	go func() {
		_, err := m.Allocate()
		allocationDone <- err
	}()
	<-handoffStarted

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- m.ShutDown()
	}()

	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before allocation handoff completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(finishHandoff)
	require.NoError(t, <-allocationDone)
	require.NoError(t, <-shutdownDone)
	assert.Equal(t, []string{"pv.ac1100ae"}, destroyed)

	stored, err := db.LoadRaw(config.BridgeIpBucket)
	require.NoError(t, err)
	assert.JSONEq(t, `{"items":[]}`, string(stored))

	_, err = m.Allocate()
	assert.ErrorIs(t, err, errord.ErrUnavailable)
	assert.ErrorIs(t, m.Recycle(resource), errord.ErrUnavailable)
}

func TestInterfaceShutdownRefusesReplacementBridge(t *testing.T) {
	const backend = "shutdown-replacement-test"
	nat := &cleanupNetworkManager{}
	NetworkManagers[backend] = nat
	t.Cleanup(func() {
		delete(NetworkManagers, backend)
	})

	owned := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: BridgeName, Index: 42},
	}
	replacement := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: BridgeName, Index: 43},
	}
	links := &fakeLinkOperations{link: replacement}
	m := &InterfaceManager{
		interfaces:      util.New(""),
		usingInterfaces: cmap.New[struct{}](),
		IpRange:         "172.30.252.1/22",
		bridgeLink:      owned,
		linkOps:         links,
		natBackend:      backend,
	}

	err := m.ShutDown()
	assert.ErrorContains(t, err, "refusing to delete replacement bridge")
	assert.Equal(t, []string{"172.30.252.1/22"}, nat.cleanedRanges)
	assert.Nil(t, links.deleted)
}

func (f *fakeLinkOperations) LinkByName(name string) (netlink.Link, error) {
	f.lookupName = name
	return f.link, f.lookupErr
}

func (f *fakeLinkOperations) LinkDel(link netlink.Link) error {
	f.deleted = link
	return f.deleteErr
}

func TestInterfaceShrinkRollbackOnFailure(t *testing.T) {
	m := &InterfaceManager{
		cacheSize:  0,
		interfaces: util.New(""),
		idleIp:     util.New(""),
	}
	const res = `{"interface":{"Index":21298,"MTU":1500,"Name":"pv.ac1100ad","HardwareAddr":"+gJCgdfr","Flags":51},"ip":"172.17.0.173","mask":"//8AAA==","gateway":"172.17.0.1","type":"bridge"}`
	m.interfaces.Push(res)
	m.total = 1

	// destroyDevice fails: the idle interface must be requeued, total must not
	// drift, and the ip must not be returned (the veth is still live).
	failPatch := gomonkey.ApplyPrivateMethod(m, "destroyDevice", func(*InterfaceManager, net.Interface) error {
		return errors.New("fake destroy failure")
	})
	m.shrink()
	failPatch.Reset()
	assert.Equal(t, 1, m.interfaces.Length(), "failed delete should requeue idle interface")
	assert.Equal(t, 1, m.total, "total must not drift on failed delete")
	assert.Equal(t, 0, m.idleIp.Length(), "ip must not be returned on failed delete")

	// destroyDevice succeeds: trimmed to cacheSize, total decremented, ip freed.
	okPatch := gomonkey.ApplyPrivateMethod(m, "destroyDevice", func(*InterfaceManager, net.Interface) error {
		return nil
	})
	m.shrink()
	okPatch.Reset()
	assert.Equal(t, 0, m.interfaces.Length())
	assert.Equal(t, 0, m.total)
	assert.Equal(t, 1, m.idleIp.Length(), "ip returned to pool on success")
}

func TestValidateIPRangeNoOverlapRejectsExistingDeviceSubnet(t *testing.T) {
	err := validateIPRangeNoOverlap("172.17.0.1/16", []deviceIPNet{
		{Interface: "eth0", Network: deviceCIDR("172.17.0.2", 16)},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ip_range 172.17.0.1/16 overlaps existing interface eth0")
}

func TestValidateIPRangeNoOverlapAllowsDifferentDeviceSubnet(t *testing.T) {
	err := validateIPRangeNoOverlap("10.231.0.1/16", []deviceIPNet{
		{Interface: "eth0", Network: deviceCIDR("172.17.0.2", 16)},
	})

	assert.NoError(t, err)
}

func TestValidateIPRangeNoOverlapRejectsNestedOverlap(t *testing.T) {
	err := validateIPRangeNoOverlap("10.231.1.1/24", []deviceIPNet{
		{Interface: "eth0", Network: deviceCIDR("10.231.0.2", 16)},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "existing interface eth0")
}

func TestValidateIPRangeNoOverlapIgnoresIPv6DeviceSubnet(t *testing.T) {
	err := validateIPRangeNoOverlap("10.231.0.1/16", []deviceIPNet{
		{
			Interface: "eth0",
			Network: &net.IPNet{
				IP:   net.ParseIP("fd00::2"),
				Mask: net.CIDRMask(64, 128),
			},
		},
	})

	assert.NoError(t, err)
}

func TestValidateIPRangeNoOverlapRejectsInvalidRange(t *testing.T) {
	err := validateIPRangeNoOverlap("not-a-cidr", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse ip_range")
}

func deviceCIDR(ip string, ones int) *net.IPNet {
	return &net.IPNet{
		IP:   net.ParseIP(ip),
		Mask: net.CIDRMask(ones, 32),
	}
}
