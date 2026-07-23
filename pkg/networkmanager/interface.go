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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"
)

type InterfaceManager struct {
	// size is the pool ceiling (max): using + idle + in-flight creates never
	// exceed it. Named "size" for historical reasons.
	size      int
	cacheSize int
	IpRange   string
	BridgeIp  net.IP
	idleIp    *util.Queue[string]

	interfaces      *util.Queue[string]
	usingInterfaces cmap.ConcurrentMap[string, struct{}]

	bridgeLink netlink.Link
	linkOps    linkOperations

	mask net.IPMask

	// mu guards total and the slow-path pool decisions (reserve / fill /
	// shrink). The fast paths (Allocate hit, Recycle) only touch the
	// self-locking queues and usingInterfaces map and do not take mu.
	mu sync.Mutex
	// total = usingInterfaces.Count() + interfaces.Length() + in-flight
	// creates. Authoritative count checked against size. Guarded by mu.
	total int
	// createReqs delivers on-demand create requests to the single maintenance
	// goroutine. Buffered to size so a reserved Allocate never blocks on submit.
	createReqs chan *createRequest

	// store resource string.
	db store.DbStore

	// storeMark is used to mark whether the cgroup id need to be stored.
	// If it's true, manager should not exit.
	storeMark atomic.Bool
}

type linkOperations interface {
	LinkByName(string) (netlink.Link, error)
	LinkDel(netlink.Link) error
}

type systemLinkOperations struct{}

func (systemLinkOperations) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (systemLinkOperations) LinkDel(link netlink.Link) error {
	return netlink.LinkDel(link)
}

func (m *InterfaceManager) links() linkOperations {
	if m.linkOps != nil {
		return m.linkOps
	}
	return systemLinkOperations{}
}

// createRequest is submitted by Allocate when the idle pool is empty but the
// pool is still below max. It asks the single maintenance goroutine to create
// one interface on demand; the result is delivered back on result.
type createRequest struct {
	result chan createResult
}

type createResult struct {
	id  string
	err error
}

type deviceIPNet struct {
	Interface string
	Network   *net.IPNet
}

type storedInterfaceIDs struct {
	Items []string `json:"items"`
}

// CacheSizeLimit exposes the configured cache target for metrics reporting.
func (m *InterfaceManager) CacheSizeLimit() int { return m.cacheSize }

func (m *InterfaceManager) ShutDown() error {
	if m.storeMark.Load() {
		m.store()
	}
	m.cleanup()
	return nil
}

// run is the single maintenance goroutine: it performs all create/destroy
// serially. It fills the idle pool to cacheSize once at startup, then serves
// on-demand create requests and periodically shrinks excess idle back to
// cacheSize.
func (m *InterfaceManager) run() {
	m.fillToCacheSize()
	ticker := time.NewTicker(shrinkInterval)
	defer ticker.Stop()
	for {
		select {
		case req := <-m.createReqs:
			id, err := m.doCreate()
			if err != nil {
				logrus.Errorf("create interface on demand failed: %v", err)
				m.mu.Lock()
				m.total-- // release the reservation
				m.mu.Unlock()
				req.result <- createResult{err: err}
				continue
			}
			// Hand the new interface straight to the waiting Allocate; it goes
			// to using (the reservation already accounts for it in total).
			req.result <- createResult{id: id}
		case <-ticker.C:
			m.shrink()
		}
	}
}

// fillToCacheSize creates idle interfaces until idle reaches cacheSize (or max).
func (m *InterfaceManager) fillToCacheSize() {
	for {
		m.mu.Lock()
		if m.interfaces.Length() >= m.cacheSize || m.total >= m.size {
			m.mu.Unlock()
			return
		}
		m.total++
		m.mu.Unlock()

		id, err := m.doCreate()
		if err != nil {
			logrus.Errorf("fill interface pool failed: %v", err)
			m.mu.Lock()
			m.total--
			m.mu.Unlock()
			return
		}
		m.interfaces.Push(id)
	}
}

// shrink trims idle interfaces down to cacheSize. Teardown is paced: Linux
// unregisters net devices asynchronously on a kworker holding the RTNL lock, so
// back-to-back deletes would starve foreground veth creation.
func (m *InterfaceManager) shrink() {
	for {
		m.mu.Lock()
		if m.interfaces.Length() <= m.cacheSize {
			m.mu.Unlock()
			return
		}
		devStr := m.interfaces.Pop()
		if devStr == "" {
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()

		// Decrement total only after the device is really gone. doDestroy
		// mutates nothing on failure, so on error we put the (still-live) idle
		// interface back and keep total intact — no leak, no count drift. Stop
		// this round instead of spinning on a device that won't delete; the
		// next shrink tick retries.
		if err := m.doDestroy(devStr); err != nil {
			logrus.Errorf("shrink: %v; requeue idle interface, retry next cycle", err)
			m.interfaces.Push(devStr)
			return
		}
		m.mu.Lock()
		m.total--
		m.mu.Unlock()

		time.Sleep(interfaceDestroyPacing)
	}
}

// doCreate builds one veth pair and returns the serialized NetResource. Called
// only by run(). It reuses the peer link looked up inside createDevice, so it
// never calls the expensive net.Interfaces() full dump.
func (m *InterfaceManager) doCreate() (string, error) {
	ip := m.idleIp.Pop()
	if ip == "" {
		return "", fmt.Errorf("no idle ip available")
	}
	peerLink, err := m.createDevice(ip)
	if err != nil {
		m.idleIp.Push(ip)
		return "", err
	}
	attrs := peerLink.Attrs()
	netResource := &NetResource{
		Interface: &net.Interface{
			Index:        attrs.Index,
			MTU:          attrs.MTU,
			Name:         attrs.Name,
			HardwareAddr: attrs.HardwareAddr,
			Flags:        attrs.Flags,
		},
		Ip:      net.ParseIP(ip),
		Mask:    m.mask,
		Gateway: m.BridgeIp,
		Type:    "bridge",
	}
	logrus.Debugf("add network interface %v", netResource.ToString())
	return netResource.ToString(), nil
}

// doDestroy tears down one veth pair and returns its ip to the idle ip pool on
// success. Called only by run() (shrink) so it is naturally serialized. On
// error nothing is mutated (the ip is not returned), so the caller can safely
// roll back: the veth is still live and fully described by devStr.
func (m *InterfaceManager) doDestroy(devStr string) error {
	dev, err := NewNetResource(devStr)
	if err != nil {
		return fmt.Errorf("parse net resource %q failed: %v", devStr, err)
	}
	if err := m.destroyDevice(*dev.Interface); err != nil {
		return fmt.Errorf("destroy interface %s failed: %v", dev.ToString(), err)
	}
	logrus.Infof("deleted interface: %s ", dev.Interface.Name)
	m.idleIp.Push(dev.Ip.String())
	return nil
}

func (m *InterfaceManager) cacheNum() int {
	return m.interfaces.Length()
}

// Allocate hands out an idle veth/IP pair as a fully serialised NetResource
// blob. The string form is what sandbox.OccupiedResource carries around and
// what eventually lands in the OCI spec annotations, so callers should
// preserve it verbatim through Recycle.
//
// Fast path: pop the idle queue. On a miss it either reserves a slot and waits
// for the maintenance goroutine to create one on demand (when below max), or
// fails fast with ErrResourceExhausted (at max, no blocking, no timeout).
func (m *InterfaceManager) Allocate() (string, error) {
	if netResourceStr := m.interfaces.Pop(); netResourceStr != "" {
		return m.markUsing(netResourceStr)
	}

	m.mu.Lock()
	if m.total >= m.size {
		m.mu.Unlock()
		return "", errord.ErrResourceExhausted
	}
	m.total++ // reserve a slot for the about-to-be-created interface
	m.mu.Unlock()

	req := &createRequest{result: make(chan createResult, 1)}
	m.createReqs <- req
	res := <-req.result
	if res.err != nil {
		// total was already decremented by the maintenance goroutine.
		return "", res.err
	}
	return m.markUsing(res.id)
}

// markUsing moves a freshly popped/created interface string into the using set.
func (m *InterfaceManager) markUsing(netResourceStr string) (string, error) {
	netResource, err := NewNetResource(netResourceStr)
	if err != nil {
		return "", err
	}
	if netResource.Interface == nil {
		return "", fmt.Errorf("interface is nil for resource %s, this indicates a creation failure", netResourceStr)
	}
	m.usingInterfaces.Set(netResource.ToString(), struct{}{})
	m.storeMark.Store(true)
	return netResource.ToString(), nil
}

func (m *InterfaceManager) Recycle(id string) error {
	m.usingInterfaces.Remove(id)
	netResource := &NetResource{}
	if err := netResource.FromString(id); err == nil {
		logrus.Infof("parse interface when recycle: %s ", netResource.ToString())
	} else {
		logrus.Errorf("parse net resource failed: %v", err)
	}
	// using -> idle, total unchanged.
	m.interfaces.Push(id)
	m.storeMark.Store(true)
	return nil
}

func (m *InterfaceManager) Status() ([]string, []string) {
	var using []string
	var idle []string
	usingList := m.usingInterfaces.Keys()
	idleList := m.interfaces.List()
	for idx := range usingList {
		using = append(using, usingList[idx])
	}
	for idx := range idleList {
		idle = append(idle, idleList[idx])
	}
	return using, idle
}

func (m *InterfaceManager) keepStoring() {
	go func() {
		for {
			select {
			case <-time.After(5 * time.Second):
				if m.storeMark.Load() {
					m.storeMark.Store(false)
					m.store()
				}
			}
		}
	}()
}

func (m *InterfaceManager) store() {
	start := time.Now()
	defer func() {
		logrus.Debugf("store network interface %v using id cost: %v ms", m.usingInterfaces.Count(), time.Since(start).Milliseconds())
	}()
	dm := m.usingInterfaces.Keys()
	dmToStr := make([]string, 0, len(dm))
	for idx := range dm {
		dmToStr = append(dmToStr, dm[idx])
	}
	dataToStore, err := json.Marshal(storedInterfaceIDs{Items: dmToStr})
	if err != nil {
		logrus.Warnf("encode network interface using id failed: %v", err)
		return
	}
	if err := m.db.StoreRaw(config.BridgeIpBucket, dataToStore); err != nil {
		logrus.Warnf("store network interface using id failed: %v", err)
	}
}

// Call it when received SIGTERM sent by pod destroying
// We can't count on auto deleting when netns deleting because we should slow down the deleting
func (m *InterfaceManager) cleanup() {
	logrus.Debugf("start to cleanup interfaces")

	interfaces := m.interfaces.List()
	for _, devStr := range interfaces {
		if devStr == "" {
			logrus.Errorf("no idle interface")
			continue
		}
		dev, err := NewNetResource(devStr)
		if err != nil {
			logrus.Errorf("parse net resource failed: %v", err)
			continue
		}
		if dev.Interface == nil {
			logrus.Errorf("interface metadata missing when cleanup: %s", dev.ToString())
			continue
		}
		if err := m.destroyDevice(*dev.Interface); err != nil {
			logrus.Errorf("destory interface %s failed: %v", dev.ToString(), err)
			continue
		}

		// Slow down the deletion to reduce performance impact to host
		time.Sleep(20 * time.Millisecond)
	}

	logrus.Debugf("finish to cleanup interfaces")
}

func NewInterfaceManager(db store.DbStore, ipRange string, size int, cacheSize int, natBackend string) (*InterfaceManager, error) {
	// load using id from db
	idData, err := db.LoadRaw(config.BridgeIpBucket)
	if err != nil && !errord.IsNotFound(err) {
		return nil, err
	}
	var usingID storedInterfaceIDs
	if idData != nil {
		if err = json.Unmarshal(idData, &usingID); err != nil {
			return nil, err
		} else {
			logrus.Infof("load network interface using id num: %v", len(usingID.Items))
		}
	}

	usingInterfaces := cmap.New[struct{}]()
	for idx := range usingID.Items {
		usingInterfaces.Set(usingID.Items[idx], struct{}{})
	}

	gatewayIp, mask, ips, err := util.GenerateIp(ipRange, maxVethNum)
	if err != nil {
		return nil, err
	}

	bridgeFound, err := bridgeExists()
	if err != nil {
		return nil, fmt.Errorf("query bridge %s: %w", bridgeName, err)
	}
	if !bridgeFound {
		if err := checkIPRangeAvailable(ipRange); err != nil {
			return nil, err
		}
	}

	if err := initBridge(ipRange, natBackend); err != nil {
		if cleanErr := cleanBridge(natBackend); cleanErr != nil {
			logrus.Warnf("clean bridge after init failed: %v", cleanErr)
		}
		return nil, err
	}

	bridgeLink, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return nil, err
	}

	if size > maxVethNum {
		size = maxVethNum
	}

	cacheSize = calcluteCacheSize(cacheSize)

	manager := &InterfaceManager{
		db:              db,
		cacheSize:       cacheSize,
		idleIp:          util.New[string](""),
		size:            size,
		createReqs:      make(chan *createRequest, size),
		IpRange:         ipRange,
		BridgeIp:        gatewayIp,
		interfaces:      util.New[string](""),
		usingInterfaces: usingInterfaces,
		bridgeLink:      bridgeLink,
		mask:            mask,
		storeMark:       atomic.Bool{},
	}

	if err = manager.load(ips); err != nil {
		return nil, err
	}
	manager.total = manager.usingInterfaces.Count() + manager.interfaces.Length()
	manager.keepStoring()
	go manager.run()
	return manager, nil
}

func (m *InterfaceManager) load(ips sets.Set[string]) error {
	_, ipv4Net, err := net.ParseCIDR(m.IpRange)
	if err != nil {
		return err
	}

	// The only place we need a full enumeration of host links: reattaching veths
	// that survived a sandboxd restart. The hot create path never does this.
	devs, err := net.Interfaces()
	if err != nil {
		return err
	}

	existingInterfaces := sets.New[string]()
	for idx := range devs {
		if strings.HasPrefix(devs[idx].Name, config.PeerVethPrefix) {
			// set peer veth up
			link, err := netlink.LinkByName(devs[idx].Name)
			if err != nil {
				logrus.Errorf("get link by name %v failed: %v", devs[idx].Name, err)
				continue
			}
			if err := netlink.LinkSetUp(link); err != nil {
				logrus.Errorf("set link %v up failed: %v", devs[idx].Name, err)
				continue
			}
			ip := util.VethToIp(devs[idx].Name)
			dev := &NetResource{
				Interface: &devs[idx],
				Ip:        ip,
				Mask:      m.mask,
				Gateway:   m.BridgeIp,
				Type:      "bridge",
			}
			existingInterfaces.Insert(dev.ToString())
			if !m.usingInterfaces.Has(dev.ToString()) {
				m.interfaces.Push(dev.ToString())
			}
			ips.Delete(ip.String())
		}
	}

	for _, ip := range ips.UnsortedList() {
		if ipv4Net.Contains(net.ParseIP(ip)) {
			m.idleIp.Push(ip)
		}
	}

	logrus.Debugf("load network interface idle num: %v, using num: %v, idle ip: %v", m.interfaces.Length(), m.usingInterfaces.Count(), m.idleIp.Length())
	return nil
}

func validateIPRangeNoOverlap(ipRange string, devices []deviceIPNet) error {
	_, sandboxNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return fmt.Errorf("parse ip_range %q: %w", ipRange, err)
	}

	for _, dev := range devices {
		if dev.Network == nil {
			continue
		}
		if ipNetOverlaps(sandboxNet, dev.Network) {
			return fmt.Errorf(
				"configured network ip_range %s overlaps existing interface %s address %s; choose a different [plugin.network].ip_range",
				ipRange, dev.Interface, dev.Network.String(),
			)
		}
	}
	return nil
}

func ipNetOverlaps(a, b *net.IPNet) bool {
	if a == nil || b == nil || ipNetVersion(a) != ipNetVersion(b) {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func ipNetVersion(network *net.IPNet) int {
	if network == nil || network.IP == nil {
		return 0
	}
	if network.IP.To4() != nil {
		return 4
	}
	if network.IP.To16() != nil {
		return 6
	}
	return 0
}

func checkIPRangeAvailable(ipRange string) error {
	devices, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}

	networks := make([]deviceIPNet, 0)
	for idx := range devices {
		dev := devices[idx]
		if dev.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := dev.Addrs()
		if err != nil {
			return fmt.Errorf("list addresses for interface %s: %w", dev.Name, err)
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
				continue
			}
			networks = append(networks, deviceIPNet{Interface: dev.Name, Network: ipNet})
		}
	}
	return validateIPRangeNoOverlap(ipRange, networks)
}

func bridgeExists() (bool, error) {
	if _, err := netlink.LinkByName(bridgeName); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// initBridge will create bridge and add iptable rule.
func initBridge(ipRange string, natBackend string) error {
	// check if bridge exists.
	bridgeFound, err := bridgeExists()
	if err != nil {
		logrus.Warnf("check bridge %s exists failed: %v", bridgeName, err)
		return err
	}
	if !bridgeFound {
		// create bridge.
		logrus.Infof("bridge %s not exists, create it", bridgeName)
		if err = netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}); err != nil {
			return err
		}
		// add address.
		addr, err := netlink.ParseAddr(ipRange)
		if err != nil {
			return err
		}
		if err = netlink.AddrAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}, addr); err != nil {
			return err
		}
		// set address and up.
		if err = netlink.LinkSetUp(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}); err != nil {
			return err
		}
	}

	// get link by name again and set mac address.
	bridgeLink, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return err
	}
	macAddress, _ := net.ParseMAC(bridgeMac)
	if err = netlink.LinkSetHardwareAddr(bridgeLink, macAddress); err != nil {
		return err
	}

	if mgr, ok := NetworkManagers[natBackend]; !ok {
		return fmt.Errorf("no corresponding network manager for natBackend: %s", natBackend)
	} else {
		if err = mgr.SetupSNATRules(ipRange); err != nil {
			return err
		}
	}

	return nil
}

// cleanBridge is used to clean bridge and iptable rule after init failed.
func cleanBridge(natBackend string) error {
	// clean bridge if exists.
	if bridge, err := netlink.LinkByName(bridgeName); err != nil {
		if !strings.Contains(err.Error(), "not found") {
			return nil
		}
	} else {
		if err = netlink.LinkDel(bridge); err != nil {
			return err
		}
	}

	if mgr, ok := NetworkManagers[natBackend]; !ok {
		return fmt.Errorf("no corresponding network manager for natBackend: %s", natBackend)
	} else {
		if err := mgr.CleanupSNATRules(defaultIpRange); err != nil {
			return err
		}
	}

	return nil
}

// createDevice adds one veth pair and returns the peer link. Thread not safe;
// called only by the single maintenance goroutine. The returned peer link's
// attrs (Index/MTU/Name/HardwareAddr) let the caller build the NetResource
// without a net.Interfaces() full dump.
func (m *InterfaceManager) createDevice(ip string) (netlink.Link, error) {
	hostVethName, peerVethName := util.IpToVeth(ip)
	/*
		    On Host
			ip link add vethPair.hostVeth type veth peer name vethPair.peerVeth
			ip link set dev vethPair.hostVeth up
			ip link set dev vethPair.hostVeth master br0
			ip link set vethPair.peerVeth netns nsPath
	*/
	// try to get host veth
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return nil, fmt.Errorf("get host device %s failed: %v", hostVethName, err)
	}

	// 3. host device not exists. create it.
	if hostVeth == nil {
		// Generate and add the interface pipe host <-> netns
		hostVeth = &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: hostVethName},
			PeerName:  peerVethName}
		if err = netlink.LinkAdd(hostVeth); err != nil {
			return nil, fmt.Errorf("create ip link failed: %v", err)
		}
	}

	// 4. set host veth up.
	if err = netlink.LinkSetUp(hostVeth); err != nil {
		return nil, fmt.Errorf("set host veth up failed: %v", err)
	}

	// 5. set bridge for host Veth.
	if hostVeth.Attrs().MasterIndex == 0 {
		if err = netlink.LinkSetMaster(hostVeth, m.bridgeLink); err != nil {
			return nil, fmt.Errorf("LinkSetMaster failed: %v", err)
		}
	}

	// get link of peer veth and set it up.
	peerVeth, err := netlink.LinkByName(peerVethName)
	if err != nil {
		return nil, fmt.Errorf("get peer device %s failed: %v", peerVethName, err)
	}

	if err = netlink.LinkSetUp(peerVeth); err != nil {
		return nil, fmt.Errorf("set peer veth up failed: %v", err)
	}

	return peerVeth, nil
}

func (m *InterfaceManager) destroyDevice(dev net.Interface) error {
	ip := util.VethToIp(dev.Name)
	hostVethName, _ := util.IpToVeth(ip.String())
	/*
		    On Host
			ip link del vethPair.hostVeth
	*/
	// try to get host veth
	hostVeth, err := m.links().LinkByName(hostVethName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("get host device %s failed: %w", hostVethName, err)
	}

	// 3. host device exists. delete it.
	if hostVeth != nil {
		if err = m.links().LinkDel(hostVeth); err != nil {
			return err
		}
	}

	return nil
}

type NetResource struct {
	Interface *net.Interface `json:"interface" protobuf:"bytes,0,opt,name=interface"`
	Ip        net.IP         `json:"ip" protobuf:"bytes,1,opt,name=ip"`
	Mask      net.IPMask     `json:"mask" protobuf:"bytes,2,opt,name=mask"`
	Gateway   net.IP         `json:"gateway" protobuf:"bytes,3,opt,name=gateway"`
	Type      string         `json:"type" protobuf:"bytes,4,opt,name=type"`
}

func (n *NetResource) ToString() string {
	// marshal to json
	bytes, _ := json.Marshal(n)
	return string(bytes)
}

func (n *NetResource) FromString(s string) error {
	return json.Unmarshal([]byte(s), n)
}

func NewNetResource(str string) (*NetResource, error) {
	n := &NetResource{}
	err := n.FromString(str)
	return n, err
}

// A sandbox can only run maxTaskCount tasks at the same time.
// So an interface cache larger than maxTaskCount is meaningless.
func calcluteCacheSize(cacheSize int) int {
	cellNum, err := getLocalCpuNum()
	if err != nil {
		logrus.Errorf("get local cpu num failed: %v", err)
		return cacheSize
	}

	minTaskSize := 0.5 // 0.5c
	maxTaskCount := int(math.Ceil(float64(cellNum) / minTaskSize))
	maxInterfaceCount := int(math.Ceil(float64(maxTaskCount) * float64(1.1))) // give 10% buffer

	logrus.Infof("max task count: %v, max calculative interface count: %v", maxTaskCount, maxInterfaceCount)

	if cacheSize > maxTaskCount {
		cacheSize = maxTaskCount
	}

	return cacheSize
}
