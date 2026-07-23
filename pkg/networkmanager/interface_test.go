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
	"testing"

	gomonkey "github.com/agiledragon/gomonkey/v2"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func initInterfaceCacheForCleanup() *InterfaceManager {
	im := &InterfaceManager{
		interfaces: util.New(""),
	}

	im.interfaces.Push(`{"interface":{"Index":21298,"MTU":1500,"Name":"pv.ac1100ad","HardwareAddr":"+gJCgdfr","Flags":51},"ip":"172.17.0.173","mask":"//8AAA==","gateway":"172.17.0.1","type":"bridge"}`)
	im.interfaces.Push("")
	im.interfaces.Push("invalid interface")

	return im
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
		interfaces: util.New(""),
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
	cacheSize := calcluteCacheSize(rawCacheSize)
	assert.True(t, cacheSize < rawCacheSize)

	getLocalCpuNumPatches := gomonkey.ApplyFunc(getLocalCpuNum, func() (int, error) {
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

type fakeLinkOperations struct {
	link       netlink.Link
	lookupErr  error
	deleteErr  error
	lookupName string
	deleted    netlink.Link
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
