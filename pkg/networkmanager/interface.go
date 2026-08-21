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
	"os"
	"path/filepath"
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

	bridgeLink  netlink.Link
	linkOps     linkOperations
	listLinks   func() ([]net.Interface, error)
	listNetNS   func() ([]os.DirEntry, error)
	setupNetNS  func(string, *NetResource) (string, error)
	deleteNetNS func(string) error
	natBackend  string
	sysctlRoot  string
	sandboxRoot string

	mask net.IPMask

	// mu guards total and the slow-path pool decisions (reserve / fill /
	// shrink). The fast paths (Allocate hit, Recycle) only touch the
	// self-locking queues and usingInterfaces map and do not take mu.
	mu sync.Mutex
	// total = usingInterfaces.Count() + interfaces.Length() + in-flight
	// creates. Authoritative count checked against size. Guarded by mu.
	total int
	// deviceMu serializes kernel TAP/veth create and destroy operations. The maintenance
	// goroutine owns normal pool resizing, while Discard may synchronously
	// destroy a poisoned lease from a request rollback.
	deviceMu sync.Mutex
	// leaseMu makes Recycle and Discard mutually exclusive for one leased
	// resource so it can never be both cached and destroyed.
	leaseMu sync.Mutex
	// createReqs delivers on-demand create requests to the single maintenance
	// goroutine. Buffered to size so a reserved Allocate never blocks on submit.
	createReqs chan *createRequest
	// lifecycleMu prevents Allocate and Recycle handoffs from crossing shutdown
	// cleanup. closed is guarded by lifecycleMu.
	lifecycleMu sync.RWMutex
	closed      bool

	// store resource string.
	db      store.DbStore
	storeMu sync.Mutex

	// storeMark is used to mark whether the cgroup id need to be stored.
	// If it's true, manager should not exit.
	storeMark atomic.Bool

	stopCh        chan struct{}
	runDoneCh     chan struct{}
	storeDoneCh   chan struct{}
	shutdownOnce  sync.Once
	shutdownError error
}

const defaultInterfaceSysctlRoot = "/proc/sys/net/ipv4/conf"

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

func (m *InterfaceManager) interfacesOnHost() ([]net.Interface, error) {
	if m.listLinks != nil {
		return m.listLinks()
	}
	return net.Interfaces()
}

func (m *InterfaceManager) setupEphemeral(sandboxID string, resource *NetResource) (string, error) {
	if m.setupNetNS != nil {
		return m.setupNetNS(sandboxID, resource)
	}
	return setupEphemeralNetwork(sandboxID, resource)
}

func (m *InterfaceManager) ephemeralNamespaces() ([]os.DirEntry, error) {
	if m.listNetNS != nil {
		return m.listNetNS()
	}
	return os.ReadDir(ephemeralNetNSRoot)
}

func (m *InterfaceManager) deleteEphemeral(path string) error {
	if m.deleteNetNS != nil {
		return m.deleteNetNS(path)
	}
	return deleteEphemeralNetNS(path)
}

// disablePeerForwarding keeps the host IP stack from routing frames that the
// runtime reads from the peer through AF_PACKET. Without this, a reply routed
// through the bridge can be forwarded back into the same veth pair forever
// when reverse-path filtering is disabled.
func (m *InterfaceManager) disablePeerForwarding(name string) error {
	if !strings.HasPrefix(name, config.PeerVethPrefix) {
		return fmt.Errorf("refuse to change forwarding on non-peer interface %q", name)
	}
	root := m.sysctlRoot
	if root == "" {
		root = defaultInterfaceSysctlRoot
	}
	path := filepath.Join(root, name, "forwarding")
	if err := os.WriteFile(path, []byte("0\n"), 0); err != nil {
		return fmt.Errorf("disable IPv4 forwarding on peer interface %s: %w", name, err)
	}
	return nil
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
	m.shutdownOnce.Do(func() {
		// Wait for allocations and recycles that already entered the manager to
		// finish before stopping the worker and taking the cleanup snapshot.
		m.lifecycleMu.Lock()
		defer m.lifecycleMu.Unlock()
		m.closed = true

		if m.stopCh != nil {
			close(m.stopCh)
		}
		if m.runDoneCh != nil {
			<-m.runDoneCh
		}
		if m.storeDoneCh != nil {
			<-m.storeDoneCh
		}
		cleanupErr := m.cleanup()
		m.usingInterfaces.Clear()
		m.storeMark.Store(false)
		if m.db != nil {
			if err := m.store(); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
		m.shutdownError = errors.Join(cleanupErr, m.cleanupNetworkInfrastructure())
	})
	return m.shutdownError
}

// run is the single maintenance goroutine: it performs all create/destroy
// serially. It fills the idle pool to cacheSize once at startup, then serves
// on-demand create requests and periodically shrinks excess idle back to
// cacheSize.
func (m *InterfaceManager) run() {
	if m.runDoneCh != nil {
		defer close(m.runDoneCh)
	}
	m.fillToCacheSize()
	ticker := time.NewTicker(shrinkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
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
		select {
		case <-m.stopCh:
			return
		default:
		}

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

// doCreate builds one persistent TAP endpoint for the reusable pool.
// deviceMu serializes the maintenance worker and synchronous ephemeral
// allocations.
func (m *InterfaceManager) doCreate() (string, error) {
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()

	ip := m.idleIp.Pop()
	if ip == "" {
		return "", fmt.Errorf("no idle ip available")
	}
	tapLink, err := m.createTapDevice(ip)
	if err != nil {
		m.idleIp.Push(ip)
		return "", err
	}
	netResource, err := m.tapResource(tapLink, net.ParseIP(ip))
	if err != nil {
		_ = netlink.LinkDel(tapLink)
		m.idleIp.Push(ip)
		return "", err
	}
	logrus.Debugf("add network interface %v", netResource.ToString())
	return netResource.ToString(), nil
}

// doCreateEphemeral builds the veth endpoint used exclusively by runc. Unlike
// pooled TAPs, its peer is moved into a named network namespace and destroyed
// when the sandbox is released.
func (m *InterfaceManager) doCreateEphemeral() (string, error) {
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()

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
		SchemaVersion: NetResourceSchemaVersion,
		EndpointType:  EndpointTypeVeth,
		GuestMAC:      append(net.HardwareAddr(nil), attrs.HardwareAddr...),
		Interface: &net.Interface{
			Index:        attrs.Index,
			MTU:          attrs.MTU,
			Name:         attrs.Name,
			HardwareAddr: append(net.HardwareAddr(nil), attrs.HardwareAddr...),
			Flags:        attrs.Flags,
		},
		Ip:      append(net.IP(nil), net.ParseIP(ip)...),
		Mask:    append(net.IPMask(nil), m.mask...),
		Gateway: append(net.IP(nil), m.BridgeIp...),
		Type:    "bridge",
	}
	logrus.Debugf("add network interface %v", netResource.ToString())
	return netResource.ToString(), nil
}

// doDestroy tears down one TAP or veth endpoint and returns its IP to the pool on
// success. deviceMu serializes calls from the maintenance goroutine and
// synchronous Discard operations. On error nothing is mutated (the ip is not
// returned), so the caller can safely roll back: the veth is still live and
// fully described by devStr.
func (m *InterfaceManager) doDestroy(devStr string) error {
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()

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

// Allocate hands out an idle TAP/IP pair as a fully serialised NetResource
// blob. The string form is what sandbox.OccupiedResource carries around and
// what eventually lands in the OCI spec annotations, so callers should
// preserve it verbatim through Recycle.
//
// Fast path: pop the idle queue. On a miss it either reserves a slot and waits
// for the maintenance goroutine to create one on demand (when below max), or
// fails fast with ErrResourceExhausted (at max, no blocking, no timeout).
func (m *InterfaceManager) Allocate() (string, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return "", errord.ErrUnavailable
	}

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

// AllocateEphemeral creates a fresh veth and named network namespace for one
// sandbox. It never consumes or produces an idle interface. When the pooled
// cache already occupies the global limit, one idle pooled interface is
// evicted first so cache capacity cannot starve an ephemeral request.
func (m *InterfaceManager) AllocateEphemeral(sandboxID string) (string, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return "", errord.ErrUnavailable
	}
	if !config.IsValidSandboxID(sandboxID) {
		return "", fmt.Errorf("invalid sandbox ID %q", sandboxID)
	}

	evicted, err := m.reserveEphemeralSlot()
	if err != nil {
		return "", err
	}
	if evicted != "" {
		if err := m.doDestroy(evicted); err != nil {
			m.interfaces.Push(evicted)
			return "", fmt.Errorf("evict idle interface for ephemeral network: %w", err)
		}
	}

	created, err := m.doCreateEphemeral()
	if err != nil {
		m.releaseReservedSlot()
		return "", err
	}
	resource, err := NewNetResource(created)
	if err != nil {
		return "", errors.Join(err, m.rollbackEphemeralCreation(created, ""))
	}
	resource.Lifecycle = InterfaceLifecycleEphemeral
	resource.NetNSPath = ephemeralNetNSPath(sandboxID)
	created = resource.ToString()

	path, err := m.setupEphemeral(sandboxID, resource)
	if err != nil {
		return "", errors.Join(err, m.rollbackEphemeralCreation(created, resource.NetNSPath))
	}
	resource.NetNSPath = path
	created = resource.ToString()
	marked, err := m.markUsing(created)
	if err != nil {
		return "", errors.Join(err, m.rollbackEphemeralCreation(created, path))
	}
	created = marked
	// Unlike the reusable cache, an ephemeral link leaves the host namespace.
	// Persist its lease before handing it to the caller so crash recovery never
	// treats the IP as free during the normal five-second store interval.
	if err := m.store(); err != nil {
		m.usingInterfaces.Pop(created)
		return "", errors.Join(err, m.rollbackEphemeralCreation(created, path))
	}
	return created, nil
}

func (m *InterfaceManager) reserveEphemeralSlot() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.total < m.size {
		m.total++
		return "", nil
	}
	if idle := m.interfaces.Pop(); idle != "" {
		// total is unchanged: the evicted cache entry reserves the slot until
		// the newly created ephemeral interface takes its place.
		return idle, nil
	}
	return "", errord.ErrResourceExhausted
}

func (m *InterfaceManager) releaseReservedSlot() {
	m.mu.Lock()
	if m.total > 0 {
		m.total--
	}
	m.mu.Unlock()
}

func (m *InterfaceManager) rollbackEphemeralCreation(resource, netNSPath string) error {
	destroyErr := m.doDestroy(resource)
	if destroyErr == nil {
		m.releaseReservedSlot()
	} else {
		// Keep an undeletable device quarantined and counted. Startup recovery
		// or shutdown can retry without making its IP allocatable.
		m.usingInterfaces.Set(resource, struct{}{})
		m.storeMark.Store(true)
	}
	return errors.Join(destroyErr, m.deleteEphemeral(netNSPath))
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
	if err := m.setTapState(netResource, true); err != nil {
		// Keep a malformed or externally modified endpoint quarantined and
		// counted. It must never go back to the reusable queue.
		m.usingInterfaces.Set(netResource.ToString(), struct{}{})
		m.storeMark.Store(true)
		return "", err
	}
	m.usingInterfaces.Set(netResource.ToString(), struct{}{})
	m.storeMark.Store(true)
	return netResource.ToString(), nil
}

func (m *InterfaceManager) Recycle(id string) error {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return errord.ErrUnavailable
	}
	m.leaseMu.Lock()
	defer m.leaseMu.Unlock()

	if !m.usingInterfaces.Has(id) {
		return nil
	}
	netResource, err := NewNetResource(id)
	if err != nil {
		return fmt.Errorf("parse net resource for recycle: %w", err)
	}
	if err := m.setTapState(netResource, false); err != nil {
		return err
	}
	m.usingInterfaces.Pop(id)
	logrus.Infof("parse interface when recycle: %s ", netResource.ToString())
	// using -> idle, total unchanged.
	m.interfaces.Push(id)
	m.storeMark.Store(true)

	return nil
}

// Deactivate disconnects a leased pooled TAP without returning it to the idle
// queue. Delete paths call this after the runtime closes its TAP FD and before
// ACL state is removed, eliminating any reuse window with stale policy.
func (m *InterfaceManager) Deactivate(id string) error {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return errord.ErrUnavailable
	}
	m.leaseMu.Lock()
	defer m.leaseMu.Unlock()

	if !m.usingInterfaces.Has(id) {
		return nil
	}
	resource, err := NewNetResource(id)
	if err != nil {
		return fmt.Errorf("parse net resource for deactivation: %w", err)
	}
	if err := m.setTapState(resource, false); err != nil {
		return err
	}
	return nil
}

// Release applies the lifecycle encoded in the lease. Legacy resources omit
// Lifecycle and retain the historical pooled Recycle behavior.
func (m *InterfaceManager) Release(id string) error {
	resource, err := NewNetResource(id)
	if err != nil {
		return err
	}
	if resource.Lifecycle == InterfaceLifecycleEphemeral {
		return m.releaseEphemeral(id, resource)
	}
	return m.Recycle(id)
}

func (m *InterfaceManager) releaseEphemeral(id string, resource *NetResource) error {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return errord.ErrUnavailable
	}
	m.leaseMu.Lock()
	defer m.leaseMu.Unlock()

	if _, active := m.usingInterfaces.Pop(id); !active {
		// A previous attempt may have deleted the pair but failed to remove the
		// namespace mount. Never touch the deterministic host-veth name here: its
		// IP may already have been leased to another sandbox.
		return m.deleteEphemeral(resource.NetNSPath)
	}
	if err := m.doDestroy(id); err != nil {
		m.usingInterfaces.Set(id, struct{}{})
		return err
	}
	m.releaseReservedSlot()
	m.storeMark.Store(true)
	storeErr := m.store()
	return errors.Join(m.deleteEphemeral(resource.NetNSPath), storeErr)
}

// Discard destroys an active interface instead of returning it to the idle
// pool. It is used when ACL cleanup failed: deleting the endpoint removes any
// TC attachment with it and prevents a later sandbox from inheriting that link.
// A failed destroy leaves the resource leased and therefore quarantined.
func (m *InterfaceManager) Discard(id string) error {
	resource, err := NewNetResource(id)
	if err != nil {
		return err
	}
	if resource.Lifecycle == InterfaceLifecycleEphemeral {
		return m.releaseEphemeral(id, resource)
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if m.closed {
		return errord.ErrUnavailable
	}
	m.leaseMu.Lock()
	defer m.leaseMu.Unlock()

	if _, active := m.usingInterfaces.Pop(id); !active {
		return nil
	}
	if err := m.doDestroy(id); err != nil {
		m.usingInterfaces.Set(id, struct{}{})
		return err
	}
	m.mu.Lock()
	m.total--
	m.mu.Unlock()
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
		if m.storeDoneCh != nil {
			defer close(m.storeDoneCh)
		}
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				if m.storeMark.Swap(false) {
					if err := m.store(); err != nil {
						logrus.Warnf("store network interface using id failed: %v", err)
						m.storeMark.Store(true)
						continue
					}
				}
			}
		}
	}()
}

func (m *InterfaceManager) store() error {
	if m.db == nil {
		return nil
	}
	m.storeMu.Lock()
	defer m.storeMu.Unlock()
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
		return fmt.Errorf("encode network interface using id: %w", err)
	}
	if err := m.db.StoreRaw(config.BridgeIpBucket, dataToStore); err != nil {
		return fmt.Errorf("store network interface using id: %w", err)
	}
	return nil
}

// cleanup removes both idle and still-leased TAP/veth endpoints. The server normally
// releases all sandbox leases before this method runs, but including the using
// set keeps a failed sandbox deletion from leaking sandbox network interfaces.
func (m *InterfaceManager) cleanup() error {
	logrus.Debugf("start to cleanup interfaces")

	interfaces := append(m.interfaces.List(), m.usingInterfaces.Keys()...)
	seen := make(map[string]struct{}, len(interfaces))
	var errs []error
	for _, devStr := range interfaces {
		if devStr == "" {
			continue
		}
		dev, err := NewNetResource(devStr)
		if err != nil {
			logrus.Errorf("parse net resource failed: %v", err)
			errs = append(errs, fmt.Errorf("parse network resource: %w", err))
			continue
		}
		if dev.Interface == nil {
			logrus.Errorf("interface metadata missing when cleanup: %s", dev.ToString())
			errs = append(errs, fmt.Errorf("interface metadata missing for network resource %s", dev.ToString()))
			continue
		}
		if _, duplicate := seen[dev.Interface.Name]; duplicate {
			continue
		}
		seen[dev.Interface.Name] = struct{}{}
		if err := m.destroyDevice(*dev.Interface); err != nil {
			logrus.Errorf("destroy interface %s failed: %v", dev.ToString(), err)
			errs = append(errs, fmt.Errorf("destroy interface %s: %w", dev.Interface.Name, err))
			continue
		}
		if dev.Lifecycle == InterfaceLifecycleEphemeral {
			if err := m.deleteEphemeral(dev.NetNSPath); err != nil {
				errs = append(errs, err)
			}
		}

		// Slow down the deletion to reduce performance impact to host
		time.Sleep(20 * time.Millisecond)
	}

	logrus.Debugf("finish to cleanup interfaces")
	return errors.Join(errs...)
}

func (m *InterfaceManager) cleanupNetworkInfrastructure() error {
	var errs []error
	if mgr, ok := NetworkManagers[m.natBackend]; !ok {
		errs = append(errs, fmt.Errorf("no corresponding network manager for natBackend: %s", m.natBackend))
	} else if err := mgr.CleanupSNATRules(m.IpRange); err != nil {
		errs = append(errs, fmt.Errorf("cleanup SNAT rules for %s: %w", m.IpRange, err))
	}

	if m.bridgeLink == nil {
		return errors.Join(errs...)
	}
	current, err := m.links().LinkByName(BridgeName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			errs = append(errs, fmt.Errorf("find bridge %s: %w", BridgeName, err))
		}
		return errors.Join(errs...)
	}
	if current == nil {
		return errors.Join(errs...)
	}
	expectedIndex := m.bridgeLink.Attrs().Index
	currentIndex := current.Attrs().Index
	if expectedIndex != 0 && currentIndex != expectedIndex {
		errs = append(
			errs,
			fmt.Errorf(
				"refusing to delete replacement bridge %s: expected index %d, got %d",
				BridgeName,
				expectedIndex,
				currentIndex,
			),
		)
		return errors.Join(errs...)
	}
	if err := m.links().LinkDel(current); err != nil {
		errs = append(errs, fmt.Errorf("delete bridge %s: %w", BridgeName, err))
	}
	return errors.Join(errs...)
}

func NewInterfaceManager(
	db store.DbStore,
	ipRange string,
	size int,
	cacheSize int,
	natBackend string,
	sandboxRoots ...string,
) (*InterfaceManager, error) {
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
		return nil, fmt.Errorf("query bridge %s: %w", BridgeName, err)
	}
	if !bridgeFound {
		if err := checkIPRangeAvailable(ipRange); err != nil {
			return nil, err
		}
	}

	if err := initBridge(ipRange, natBackend); err != nil {
		if cleanErr := cleanBridge(ipRange, natBackend); cleanErr != nil {
			logrus.Warnf("clean bridge after init failed: %v", cleanErr)
		}
		return nil, err
	}

	bridgeLink, err := netlink.LinkByName(BridgeName)
	if err != nil {
		return nil, err
	}

	if size > maxVethNum {
		size = maxVethNum
	}

	cacheSize = calcluteCacheSize(cacheSize)

	var sandboxRoot string
	if len(sandboxRoots) > 0 {
		sandboxRoot = sandboxRoots[0]
	}
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
		natBackend:      natBackend,
		sandboxRoot:     sandboxRoot,
		mask:            mask,
		storeMark:       atomic.Bool{},
		stopCh:          make(chan struct{}),
		runDoneCh:       make(chan struct{}),
		storeDoneCh:     make(chan struct{}),
	}

	if err = manager.load(ips); err != nil {
		// Never tear down endpoints owned by running sandboxes merely because
		// recovery or a schema migration failed. The operator must drain or fix
		// those sandboxes before startup can continue.
		if manager.usingInterfaces.Count() != 0 {
			return nil, err
		}
		cleanupErr := errors.Join(manager.cleanup(), manager.cleanupNetworkInfrastructure())
		if cleanupErr != nil {
			return nil, errors.Join(err, fmt.Errorf("rollback network initialization: %w", cleanupErr))
		}
		return nil, err
	}
	manager.total = manager.usingInterfaces.Count() + manager.interfaces.Length()
	manager.keepStoring()
	go manager.run()
	return manager, nil
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
	if _, err := netlink.LinkByName(BridgeName); err != nil {
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
		logrus.Warnf("check bridge %s exists failed: %v", BridgeName, err)
		return err
	}
	if !bridgeFound {
		// create bridge.
		logrus.Infof("bridge %s not exists, create it", BridgeName)
		if err = netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: BridgeName}}); err != nil {
			return err
		}
		// add address.
		addr, err := netlink.ParseAddr(ipRange)
		if err != nil {
			return err
		}
		if err = netlink.AddrAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: BridgeName}}, addr); err != nil {
			return err
		}
		// set address and up.
		if err = netlink.LinkSetUp(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: BridgeName}}); err != nil {
			return err
		}
	}

	// get link by name again and set mac address.
	bridgeLink, err := netlink.LinkByName(BridgeName)
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
func cleanBridge(ipRange string, natBackend string) error {
	var errs []error
	bridge, err := netlink.LinkByName(BridgeName)
	if err == nil {
		if err := netlink.LinkDel(bridge); err != nil {
			errs = append(errs, fmt.Errorf("delete bridge %s: %w", BridgeName, err))
		}
	} else {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			errs = append(errs, fmt.Errorf("find bridge %s: %w", BridgeName, err))
		}
	}

	if mgr, ok := NetworkManagers[natBackend]; !ok {
		errs = append(errs, fmt.Errorf("no corresponding network manager for natBackend: %s", natBackend))
	} else {
		if err := mgr.CleanupSNATRules(ipRange); err != nil {
			errs = append(errs, fmt.Errorf("cleanup SNAT rules for %s: %w", ipRange, err))
		}
	}

	return errors.Join(errs...)
}

// createDevice adds one veth pair and returns the peer link. The caller must
// hold deviceMu. The returned peer link's attrs
// (Index/MTU/Name/HardwareAddr) let the caller build the NetResource without a
// net.Interfaces() full dump.
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
	if err = m.disablePeerForwarding(peerVethName); err != nil {
		return nil, err
	}

	return peerVeth, nil
}

func (m *InterfaceManager) destroyDevice(dev net.Interface) error {
	if strings.HasPrefix(dev.Name, config.TapPrefix) {
		tap, err := m.links().LinkByName(dev.Name)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				return nil
			}
			return fmt.Errorf("get TAP device %s failed: %w", dev.Name, err)
		}
		if tap != nil {
			if err := m.links().LinkDel(tap); err != nil {
				return fmt.Errorf("delete TAP device %s: %w", dev.Name, err)
			}
		}
		return nil
	}
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
	SchemaVersion int              `json:"schemaVersion,omitempty" protobuf:"varint,7,opt,name=schemaVersion"`
	EndpointType  string           `json:"endpointType,omitempty" protobuf:"bytes,8,opt,name=endpointType"`
	GuestMAC      net.HardwareAddr `json:"guestMAC,omitempty" protobuf:"bytes,9,opt,name=guestMAC"`
	Interface     *net.Interface   `json:"interface" protobuf:"bytes,0,opt,name=interface"`
	Ip            net.IP           `json:"ip" protobuf:"bytes,1,opt,name=ip"`
	Mask          net.IPMask       `json:"mask" protobuf:"bytes,2,opt,name=mask"`
	Gateway       net.IP           `json:"gateway" protobuf:"bytes,3,opt,name=gateway"`
	Type          string           `json:"type" protobuf:"bytes,4,opt,name=type"`
	NetNSPath     string           `json:"netnsPath,omitempty" protobuf:"bytes,5,opt,name=netnsPath"`
	Lifecycle     string           `json:"lifecycle,omitempty" protobuf:"bytes,6,opt,name=lifecycle"`
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
