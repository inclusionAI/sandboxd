// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bpffsRoot     = "/sys/fs/bpf"
	pinRoot       = bpffsRoot + "/sandboxd/networkacl"
	stateStoreKey = "networkACLState"

	filterPriority = 31900
	ingressHandle  = 0xc1
	egressHandle   = 0xc2
)

type Config struct {
	Backend                            string
	BridgeIP                           net.IP
	ResolverPath                       string
	Store                              store.DbStore
	DNSProxyConcurrencyLimit           int
	DNSProxyPerSandboxConcurrencyLimit int
	DisableProxy                       bool
	DisableAttach                      bool
}

type Binding struct {
	SandboxID string
	IP        net.IP
	HostVeth  string
}

type persistedEntry struct {
	IP         string `json:"ip"`
	HostVeth   string `json:"host_veth"`
	IfIndex    int    `json:"ifindex"`
	Generation uint64 `json:"generation"`
	Policy     Policy `json:"policy"`
	Orphaned   bool   `json:"orphaned,omitempty"`
}

type persistedState struct {
	Entries map[string]persistedEntry `json:"entries"`
}

type bpfObjects struct {
	EgressProgram  *ebpf.Program `ebpf:"sandboxd_acl_egress"`
	IngressProgram *ebpf.Program `ebpf:"sandboxd_acl_ingress"`
	Policies       *ebpf.Map     `ebpf:"POLICY_MAP"`
	Rules          *ebpf.Map     `ebpf:"RULE_MAP"`
	Connections    *ebpf.Map     `ebpf:"CONNECTION_MAP"`
	Fragments      *ebpf.Map     `ebpf:"FRAGMENT_MAP"`
	Config         *ebpf.Map     `ebpf:"CONFIG_MAP"`
}

func (o *bpfObjects) close() error {
	return errors.Join(closeProgram(o.EgressProgram), closeProgram(o.IngressProgram),
		closeMap(o.Policies), closeMap(o.Rules), closeMap(o.Connections),
		closeMap(o.Fragments), closeMap(o.Config))
}

func closeProgram(program *ebpf.Program) error {
	if program == nil {
		return nil
	}
	return program.Close()
}

func closeMap(bpfMap *ebpf.Map) error {
	if bpfMap == nil {
		return nil
	}
	return bpfMap.Close()
}

type policyValue struct {
	Generation     uint64
	SandboxIP      uint32
	TrafficEnabled uint8
	TrafficDefault uint8
	DNSEnabled     uint8
	Mode           uint8
}

type ruleKey struct {
	Generation  uint64
	IfIndex     uint32
	PeerIP      uint32
	PeerPort    uint16
	Direction   uint8
	Protocol    uint8
	SandboxPort uint16
	MatchFlags  uint8
	Reserved    uint8
}

type connectionKey struct {
	Generation  uint64
	IfIndex     uint32
	PeerIP      uint32
	PeerPort    uint16
	SandboxPort uint16
	Protocol    uint8
	Reserved    [3]uint8
}

type fragmentKey struct {
	Generation     uint64
	IfIndex        uint32
	SourceIP       uint32
	DestinationIP  uint32
	Identification uint16
	Protocol       uint8
	Direction      uint8
}

const (
	ruleMatchPeerAny uint8 = 0x01
	ruleMatchValid   uint8 = 0x80
)

type Manager struct {
	mu sync.RWMutex

	store         store.DbStore
	bridgeIP      net.IP
	objects       bpfObjects
	entries       map[string]persistedEntry
	sourceIndex   map[string]string
	ownedQdiscs   map[int]struct{}
	dns           *dnsProxy
	iptables      *iptablesBackend
	disableAttach bool
}

func New(config Config) (*Manager, error) {
	bridgeIP := config.BridgeIP.To4()
	if bridgeIP == nil {
		return nil, fmt.Errorf("network ACL bridge IP must be IPv4")
	}
	manager := &Manager{
		store:         config.Store,
		bridgeIP:      append(net.IP(nil), bridgeIP...),
		entries:       make(map[string]persistedEntry),
		sourceIndex:   make(map[string]string),
		ownedQdiscs:   make(map[int]struct{}),
		disableAttach: config.DisableAttach,
	}
	if err := manager.loadState(); err != nil {
		return nil, err
	}
	backend := config.Backend
	if backend == "" {
		backend = aclBackendBPFNAT
	}
	switch backend {
	case aclBackendIPTables:
		iptablesBackend, backendErr := newIPTablesBackend(bridgeIP)
		if backendErr != nil {
			return nil, backendErr
		}
		manager.iptables = iptablesBackend
	case aclBackendBPFNAT:
		if err := manager.loadBPF(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported network ACL backend %q", backend)
	}
	failed := true
	defer func() {
		if failed {
			_ = manager.objects.close()
			if manager.iptables != nil && len(manager.entries) == 0 {
				_ = manager.iptables.close()
			}
		}
	}()
	if !config.DisableProxy {
		globalLimit := config.DNSProxyConcurrencyLimit
		if globalLimit == 0 {
			globalLimit = DefaultDNSProxyConcurrencyLimit
		}
		perSandboxLimit := config.DNSProxyPerSandboxConcurrencyLimit
		if perSandboxLimit == 0 {
			perSandboxLimit = DefaultDNSProxyPerSandboxConcurrencyLimit
		}
		proxy, err := newDNSProxy(
			bridgeIP,
			config.ResolverPath,
			globalLimit,
			perSandboxLimit,
			manager.authorizeDNS,
		)
		if err != nil {
			return nil, err
		}
		manager.dns = proxy
		logrus.Infof(
			"network ACL DNS proxy concurrency limited to %d globally and %d per sandbox",
			globalLimit,
			perSandboxLimit,
		)
	}
	failed = false
	logrus.Infof("network ACL initialized, backend=%s bridge=%s", backend, bridgeIP)
	return manager, nil
}

func (m *Manager) loadBPF() error {
	if err := ensureBPFFS(); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove BPF memlock limit: %w", err)
	}
	if err := os.MkdirAll(pinRoot, 0700); err != nil {
		return fmt.Errorf("create network ACL pin directory: %w", err)
	}
	spec, err := loadNetworkacl()
	if err != nil {
		return fmt.Errorf("read embedded network ACL object: %w", err)
	}
	if err := spec.LoadAndAssign(&m.objects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinRoot},
	}); err != nil {
		return fmt.Errorf("load embedded network ACL object: %w", err)
	}
	key := uint32(0)
	value := ipv4Value(m.bridgeIP)
	if err := m.objects.Config.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("configure network ACL bridge IP: %w", err)
	}
	return nil
}

func ensureBPFFS() error {
	if err := os.MkdirAll(bpffsRoot, 0755); err != nil {
		return fmt.Errorf("create bpffs mount point: %w", err)
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(bpffsRoot, &stat); err != nil {
		return fmt.Errorf("stat bpffs: %w", err)
	}
	if stat.Type == unix.BPF_FS_MAGIC {
		return nil
	}
	if err := unix.Mount("bpffs", bpffsRoot, "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs at %s: %w", bpffsRoot, err)
	}
	return nil
}

func (m *Manager) loadState() error {
	if m.store == nil {
		return nil
	}
	data, err := m.store.LoadRaw(stateStoreKey)
	if errors.Is(err, errord.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load network ACL state: %w", err)
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode network ACL state: %w", err)
	}
	for sandboxID, entry := range state.Entries {
		m.entries[sandboxID] = entry
	}
	return nil
}

func (m *Manager) persistLocked() error {
	if m.store == nil {
		return nil
	}
	data, err := json.Marshal(persistedState{Entries: m.entries})
	if err != nil {
		return err
	}
	return m.store.StoreRaw(stateStoreKey, data)
}

func (m *Manager) Restore(active map[string]Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	resolved := make(map[string]persistedEntry, len(active))
	entryRestoreOld := make(map[string]persistedEntry, len(active))
	for sandboxID, binding := range active {
		entry, ok := m.entries[sandboxID]
		if !ok {
			return fmt.Errorf("active sandbox %s has no managed network ACL state; drain the node before enabling ACL", sandboxID)
		}
		link, err := netlink.LinkByName(binding.HostVeth)
		if err != nil {
			return fmt.Errorf("restore network ACL for %s: find host endpoint %s: %w", sandboxID, binding.HostVeth, err)
		}
		oldEntry := entry
		entry.IP = binding.IP.String()
		entry.HostVeth = binding.HostVeth
		entry.IfIndex = link.Attrs().Index
		entry.Orphaned = false
		if m.iptables != nil && !entry.Policy.Empty() {
			entry.Generation++
			if entry.Generation == 0 {
				entry.Generation = 1
			}
		} else {
			oldEntry = entry
		}
		entryRestoreOld[sandboxID] = oldEntry
		resolved[sandboxID] = entry
		// Publish the resolved ownership before reconciling inactive entries.
		// cleanupEntryLocked uses this to refuse destructive cleanup when stale
		// metadata collides with an active sandbox's current ifindex.
		m.entries[sandboxID] = entry
	}

	// Clean inactive entries before replacing active filters. An orphan may
	// refer to an ifindex that the kernel has since reused, so cleaning it after
	// active restoration could delete the newly restored policy.
	inactive := make(map[string]persistedEntry)
	for sandboxID, entry := range m.entries {
		if _, ok := resolved[sandboxID]; ok {
			continue
		}
		inactive[sandboxID] = entry
	}
	if err := m.reconcileOrphansLocked(inactive); err != nil {
		return fmt.Errorf("reconcile restored network ACL state: %w", err)
	}

	for sandboxID, entry := range resolved {
		m.entries[sandboxID] = entry
		if err := m.applyLocked(entryRestoreOld[sandboxID], entry); err != nil {
			return errors.Join(
				fmt.Errorf("restore network ACL for %s: %w", sandboxID, err),
				m.persistLocked(),
			)
		}
		m.sourceIndex[entry.IP] = sandboxID
	}
	if err := m.persistLocked(); err != nil {
		return fmt.Errorf("persist restored network ACL state: %w", err)
	}
	return nil
}

func (m *Manager) Register(binding Binding, policy Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if binding.SandboxID == "" || binding.IP.To4() == nil || binding.HostVeth == "" {
		return fmt.Errorf("network ACL binding requires sandbox ID, IPv4 address, and host endpoint")
	}
	link, err := netlink.LinkByName(binding.HostVeth)
	if err != nil {
		return fmt.Errorf("find host endpoint %s: %w", binding.HostVeth, err)
	}
	reconciled := make(map[string]persistedEntry)
	for sandboxID, existing := range m.entries {
		conflicts := sandboxID == binding.SandboxID ||
			existing.IfIndex == link.Attrs().Index ||
			existing.IP == binding.IP.String() ||
			existing.HostVeth == binding.HostVeth
		if !conflicts {
			continue
		}
		if !existing.Orphaned {
			return fmt.Errorf("network ACL state for sandbox %s conflicts with active sandbox %s", binding.SandboxID, sandboxID)
		}
		reconciled[sandboxID] = existing
	}
	if err := m.reconcileOrphansLocked(reconciled); err != nil {
		return fmt.Errorf("reconcile orphaned network ACL: %w", err)
	}
	generation := uint64(0)
	if !policy.Empty() {
		generation = 1
	}
	entry := persistedEntry{
		IP:         binding.IP.String(),
		HostVeth:   binding.HostVeth,
		IfIndex:    link.Attrs().Index,
		Generation: generation,
		Policy:     policy,
	}
	m.entries[binding.SandboxID] = entry
	m.sourceIndex[entry.IP] = binding.SandboxID
	if err := m.persistLocked(); err != nil {
		delete(m.entries, binding.SandboxID)
		delete(m.sourceIndex, entry.IP)
		return fmt.Errorf("persist initial network ACL for %s: %w", binding.SandboxID, err)
	}
	if err := m.applyLocked(persistedEntry{}, entry); err != nil {
		cleanupErr := m.reconcileOrphansLocked(map[string]persistedEntry{
			binding.SandboxID: entry,
		})
		return errors.Join(err, cleanupErr)
	}
	return nil
}

func (m *Manager) SetPolicy(sandboxID string, policy Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.entries[sandboxID]
	if !ok || old.Orphaned {
		return errord.ErrNotFound
	}
	next := old
	next.Policy = policy
	next.Generation++
	if next.Generation == 0 {
		next.Generation = 1
	}
	m.entries[sandboxID] = next
	if err := m.persistLocked(); err != nil {
		m.entries[sandboxID] = old
		return fmt.Errorf("persist network ACL update for %s: %w", sandboxID, err)
	}
	if err := m.applyLocked(old, next); err != nil {
		m.entries[sandboxID] = old
		_ = m.persistLocked()
		return err
	}
	return nil
}

func (m *Manager) Remove(sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[sandboxID]
	if !ok {
		return nil
	}
	return m.reconcileOrphansLocked(map[string]persistedEntry{sandboxID: entry})
}

// reconcileOrphansLocked persists cleanup intent before changing kernel state.
// Kernel cleanup is idempotent and removes only sandboxd-owned map entries,
// rules, and TC filters. If the final metadata write fails, the orphan remains
// durable and in memory so a later reconciliation can safely retry it.
func (m *Manager) reconcileOrphansLocked(candidates map[string]persistedEntry) error {
	if len(candidates) == 0 {
		return nil
	}

	previous := make(map[string]persistedEntry, len(candidates))
	previousPresent := make(map[string]bool, len(candidates))
	previousSourceIndex := make(map[string]string, len(m.sourceIndex))
	intentChanged := false
	for ip, sandboxID := range m.sourceIndex {
		previousSourceIndex[ip] = sandboxID
	}
	for sandboxID, candidate := range candidates {
		entry, ok := m.entries[sandboxID]
		previousPresent[sandboxID] = ok
		if !ok {
			entry = candidate
		}
		previous[sandboxID] = entry
		if !entry.Orphaned {
			entry.Orphaned = true
			intentChanged = true
		}
		delete(m.sourceIndex, entry.IP)
		m.entries[sandboxID] = entry
	}

	// This is the write-ahead barrier. A failed write returns before policy
	// maps, rules, or TC filters are changed, so durable state can never claim
	// that a cleanup-pending entry is still active.
	if intentChanged {
		if err := m.persistLocked(); err != nil {
			for sandboxID, entry := range previous {
				if previousPresent[sandboxID] {
					m.entries[sandboxID] = entry
				} else {
					delete(m.entries, sandboxID)
				}
			}
			m.sourceIndex = previousSourceIndex
			return fmt.Errorf("persist network ACL cleanup intent: %w", err)
		}
	}

	var cleanupErrs []error
	cleaned := make(map[string]persistedEntry, len(candidates))
	for sandboxID := range candidates {
		entry, ok := m.entries[sandboxID]
		if !ok {
			continue
		}
		if err := m.cleanupEntryLocked(sandboxID, entry); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("clean network ACL for %s: %w", sandboxID, err))
			continue
		}
		cleaned[sandboxID] = entry
		delete(m.entries, sandboxID)
	}

	// A failed write leaves the durable cleanup intent intact. Restore the same
	// orphan entries in memory so this process follows the same retry path as a
	// restarted process.
	if err := m.persistLocked(); err != nil {
		for sandboxID, entry := range cleaned {
			m.entries[sandboxID] = entry
		}
		return errors.Join(
			errors.Join(cleanupErrs...),
			fmt.Errorf("persist removal of cleaned network ACL state: %w", err),
		)
	}
	return errors.Join(cleanupErrs...)
}

func (m *Manager) cleanupEntryLocked(sandboxID string, entry persistedEntry) error {
	for otherID, other := range m.entries {
		if otherID == sandboxID || other.Orphaned || other.IfIndex != entry.IfIndex {
			continue
		}
		return fmt.Errorf(
			"refusing cleanup of ifindex %d owned by active sandbox %s",
			entry.IfIndex,
			otherID,
		)
	}
	if m.iptables != nil {
		return m.iptables.cleanup(entry)
	}

	return errors.Join(
		m.removePolicyMapLocked(entry.IfIndex),
		m.detachLocked(entry),
		m.deleteRulesLocked(entry.IfIndex, 0),
		m.deleteDynamicStateLocked(entry.IfIndex, 0),
	)
}

func (m *Manager) applyLocked(old, next persistedEntry) error {
	if m.iptables != nil {
		return m.iptables.apply(old, next)
	}
	if next.Policy.Empty() {
		if old.IfIndex == 0 {
			return nil
		}
		if err := m.removePolicyMapLocked(old.IfIndex); err != nil {
			return err
		}
		if err := m.detachLocked(old); err != nil {
			logrus.Warnf("detach cleared network ACL from %s: %v", old.HostVeth, err)
		}
		if err := m.deleteRulesLocked(old.IfIndex, 0); err != nil {
			logrus.Warnf("delete cleared network ACL rules from %s: %v", old.HostVeth, err)
		}
		if err := m.deleteDynamicStateLocked(old.IfIndex, 0); err != nil {
			logrus.Warnf("delete cleared network ACL state from %s: %v", old.HostVeth, err)
		}
		return nil
	}
	if err := m.writeRulesLocked(next); err != nil {
		return err
	}
	if err := m.attachLocked(next); err != nil {
		_ = m.deleteRulesLocked(next.IfIndex, next.Generation)
		return err
	}
	value := policyValue{
		Generation: next.Generation,
		SandboxIP:  ipv4Value(net.ParseIP(next.IP)),
	}
	if next.Policy.Traffic != nil {
		value.TrafficEnabled = 1
		value.TrafficDefault = next.Policy.Traffic.DefaultAction
		value.Mode = next.Policy.Traffic.Mode
	}
	if next.Policy.DNS != nil {
		value.DNSEnabled = 1
	}
	key := uint32(next.IfIndex)
	if err := m.objects.Policies.Update(&key, &value, ebpf.UpdateAny); err != nil {
		_ = m.deleteRulesLocked(next.IfIndex, next.Generation)
		if old.Policy.Empty() {
			_ = m.detachLocked(next)
		}
		return fmt.Errorf("activate network ACL generation %d: %w", next.Generation, err)
	}
	if old.Generation != 0 && old.Generation != next.Generation {
		if err := m.deleteRulesLocked(old.IfIndex, old.Generation); err != nil {
			logrus.Warnf("delete old network ACL generation %d for %s: %v", old.Generation, next.IP, err)
		}
		if err := m.deleteDynamicStateLocked(old.IfIndex, old.Generation); err != nil {
			logrus.Warnf("delete old network ACL state generation %d for %s: %v", old.Generation, next.IP, err)
		}
	}
	return nil
}

func (m *Manager) writeRulesLocked(entry persistedEntry) error {
	if entry.Policy.Traffic == nil {
		return nil
	}
	for _, rule := range entry.Policy.Traffic.Rules {
		for _, direction := range rule.Directions {
			matchFlags := ruleMatchValid
			if rule.PeerAny {
				matchFlags |= ruleMatchPeerAny
			}
			key := ruleKey{
				Generation:  entry.Generation,
				IfIndex:     uint32(entry.IfIndex),
				PeerIP:      ipv4Value(net.IP(rule.PeerIP[:])),
				PeerPort:    networkPort(rule.PeerPort),
				Direction:   direction,
				Protocol:    rule.Protocol,
				SandboxPort: networkPort(rule.SandboxPort),
				MatchFlags:  matchFlags,
			}
			value := rule.Action
			var existing uint8
			if err := m.objects.Rules.Lookup(&key, &existing); err == nil {
				// Duplicate protobuf rules compile to the same key. Preserve a
				// deny regardless of request ordering.
				if existing == actionDeny || value == actionAllow {
					continue
				}
			} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("inspect staged network ACL rule: %w", err)
			}
			if err := m.objects.Rules.Update(&key, &value, ebpf.UpdateAny); err != nil {
				_ = m.deleteRulesLocked(entry.IfIndex, entry.Generation)
				return fmt.Errorf("stage network ACL generation %d: %w", entry.Generation, err)
			}
		}
	}
	return nil
}

func (m *Manager) deleteRulesLocked(ifindex int, generation uint64) error {
	if ifindex == 0 {
		return nil
	}
	iterator := m.objects.Rules.Iterate()
	var key ruleKey
	var value uint8
	var errs []error
	for iterator.Next(&key, &value) {
		if key.IfIndex != uint32(ifindex) || (generation != 0 && key.Generation != generation) {
			continue
		}
		candidate := key
		if err := m.objects.Rules.Delete(&candidate); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	if err := iterator.Err(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) deleteDynamicStateLocked(ifindex int, generation uint64) error {
	if ifindex == 0 {
		return nil
	}
	var errs []error
	connections := m.objects.Connections.Iterate()
	var connection connectionKey
	var expires uint64
	for connections.Next(&connection, &expires) {
		if connection.IfIndex != uint32(ifindex) || (generation != 0 && connection.Generation != generation) {
			continue
		}
		candidate := connection
		if err := m.objects.Connections.Delete(&candidate); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	if err := connections.Err(); err != nil {
		errs = append(errs, err)
	}
	fragments := m.objects.Fragments.Iterate()
	var fragment fragmentKey
	for fragments.Next(&fragment, &expires) {
		if fragment.IfIndex != uint32(ifindex) || (generation != 0 && fragment.Generation != generation) {
			continue
		}
		candidate := fragment
		if err := m.objects.Fragments.Delete(&candidate); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	if err := fragments.Err(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) removePolicyMapLocked(ifindex int) error {
	if ifindex == 0 {
		return nil
	}
	key := uint32(ifindex)
	err := m.objects.Policies.Delete(&key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (m *Manager) attachLocked(entry persistedEntry) error {
	if m.disableAttach {
		return nil
	}
	link, err := netlink.LinkByIndex(entry.IfIndex)
	if err != nil {
		return fmt.Errorf("find host endpoint index %d: %w", entry.IfIndex, err)
	}
	if link.Attrs() == nil || link.Attrs().Name != entry.HostVeth {
		return fmt.Errorf(
			"refusing to attach network ACL to unexpected link for %s at ifindex %d",
			entry.HostVeth,
			entry.IfIndex,
		)
	}
	if err := m.attachOneLocked(link, netlink.HANDLE_MIN_INGRESS, ingressHandle,
		"sd_acl_out", m.objects.EgressProgram); err != nil {
		_ = m.removeOwnedQdiscLocked(link)
		return err
	}
	if err := m.attachOneLocked(link, netlink.HANDLE_MIN_EGRESS, egressHandle,
		"sd_acl_in", m.objects.IngressProgram); err != nil {
		_ = m.detachOneLocked(link, netlink.HANDLE_MIN_INGRESS, ingressHandle, "sd_acl_out")
		_ = m.removeOwnedQdiscLocked(link)
		return err
	}
	return nil
}

func (m *Manager) attachOneLocked(link netlink.Link, parent uint32, handle uint16, name string, program *ebpf.Program) error {
	created, err := ensureClsact(link)
	if err != nil {
		return err
	}
	if created {
		m.ownedQdiscs[link.Attrs().Index] = struct{}{}
	}
	wantedHandle := netlink.MakeHandle(0, handle)
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    wantedHandle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority,
		},
		Fd: program.FD(), Name: name, DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("attach %s to %s: %w", name, link.Attrs().Name, err)
	}
	return nil
}

func (m *Manager) detachLocked(entry persistedEntry) error {
	if m.disableAttach || entry.IfIndex == 0 {
		return nil
	}
	link, err := netlink.LinkByIndex(entry.IfIndex)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) || errors.Is(err, unix.ENODEV) {
			return nil
		}
		return err
	}
	err = errors.Join(
		m.detachOneLocked(link, netlink.HANDLE_MIN_INGRESS, ingressHandle, "sd_acl_out"),
		m.detachOneLocked(link, netlink.HANDLE_MIN_EGRESS, egressHandle, "sd_acl_in"),
	)
	if err != nil {
		return err
	}
	return m.removeOwnedQdiscLocked(link)
}

func (m *Manager) detachOneLocked(link netlink.Link, parent uint32, handle uint16, name string) error {
	wantedHandle := netlink.MakeHandle(0, handle)
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return err
	}
	for _, candidate := range filters {
		filter, ok := candidate.(*netlink.BpfFilter)
		if !ok || filter.Handle != wantedHandle || filter.Name != name || filter.Priority != filterPriority {
			continue
		}
		if err := netlink.FilterDel(filter); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return nil
}

func ensureClsact(link netlink.Link) (bool, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return false, err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return false, nil
		}
	}
	qdisc := &netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}, QdiscType: "clsact"}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return false, fmt.Errorf("add clsact to %s: %w", link.Attrs().Name, err)
	}
	return true, nil
}

func (m *Manager) removeOwnedQdiscLocked(link netlink.Link) error {
	if _, owned := m.ownedQdiscs[link.Attrs().Index]; !owned {
		return nil
	}
	ingress, ingressErr := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	egress, egressErr := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if ingressErr != nil || egressErr != nil || len(ingress) != 0 || len(egress) != 0 {
		return errors.Join(ingressErr, egressErr)
	}
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
			break
		}
	}
	delete(m.ownedQdiscs, link.Attrs().Index)
	return nil
}

func (m *Manager) authorizeDNS(source net.IP, names []string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sandboxID, ok := m.sourceIndex[source.String()]
	if !ok {
		return false
	}
	entry, ok := m.entries[sandboxID]
	if !ok || entry.Orphaned {
		return false
	}
	for _, name := range names {
		if !entry.Policy.AllowDNS(name) {
			return false
		}
	}
	return true
}

func (m *Manager) Close() error {
	var errs []error
	if m.dns != nil {
		if err := m.dns.close(); err != nil {
			errs = append(errs, err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.objects.close(); err != nil {
		errs = append(errs, err)
	}
	// Shutdown removes live sandboxes before closing the manager, so the
	// normal path reaches this point with no entries. If sandbox cleanup or
	// service initialization failed, keep TC filters and pinned maps in place:
	// a running sandbox must remain fail-closed until the next daemon restores
	// and reconciles its policy.
	if len(m.entries) == 0 {
		for _, name := range []string{
			"POLICY_MAP", "RULE_MAP", "CONNECTION_MAP", "FRAGMENT_MAP", "CONFIG_MAP",
		} {
			if err := os.Remove(filepath.Join(pinRoot, name)); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
		if err := os.Remove(pinRoot); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
		if m.iptables != nil {
			if err := m.iptables.close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func ipv4Value(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

func networkPort(port uint16) uint16 {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], port)
	return binary.LittleEndian.Uint16(encoded[:])
}
