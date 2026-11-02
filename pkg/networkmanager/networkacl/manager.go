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
	"sort"
	"sync"
	"time"

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
	IP           string                 `json:"ip"`
	HostVeth     string                 `json:"host_veth"`
	IfIndex      int                    `json:"ifindex"`
	Generation   uint64                 `json:"generation"`
	Policy       Policy                 `json:"policy"`
	DomainGrants []persistedDomainGrant `json:"domain_grants,omitempty"`
	Orphaned     bool                   `json:"orphaned,omitempty"`
}

type persistedDomainGrant struct {
	Question  string `json:"question"`
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at_unix_nano"`
	RuleIndex uint16 `json:"rule_index"`
}

type persistedState struct {
	Entries map[string]persistedEntry `json:"entries"`
}

type bpfObjects struct {
	EgressProgram  *ebpf.Program `ebpf:"sandboxd_acl_egress"`
	IngressProgram *ebpf.Program `ebpf:"sandboxd_acl_ingress"`
	LegacyPolicies *ebpf.Map     `ebpf:"POLICY_MAP"`
	LegacyRules    *ebpf.Map     `ebpf:"RULE_MAP"`
	Policies       *ebpf.Map     `ebpf:"POLICY_V2_MAP"`
	DomainPolicies *ebpf.Map     `ebpf:"DOMAIN_V2_MAP"`
	Connections    *ebpf.Map     `ebpf:"CONN_V2_MAP"`
	Fragments      *ebpf.Map     `ebpf:"FRAGMENT_MAP"`
	Config         *ebpf.Map     `ebpf:"CONFIG_MAP"`
}

func (o *bpfObjects) close() error {
	return errors.Join(closeProgram(o.EgressProgram), closeProgram(o.IngressProgram),
		closeMap(o.LegacyPolicies), closeMap(o.LegacyRules), closeMap(o.Policies),
		closeMap(o.DomainPolicies), closeMap(o.Connections), closeMap(o.Fragments),
		closeMap(o.Config))
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

const maxCompiledRules = 256

type policyV2Rule struct {
	PeerIP           uint32
	Priority         uint32
	PeerPortFirst    uint16
	PeerPortLast     uint16
	SandboxPortFirst uint16
	SandboxPortLast  uint16
	PeerPrefix       uint8
	Action           uint8
	Directions       uint8
	Protocol         uint8
	MatchFlags       uint8
	Reserved         [3]uint8
}

type policyV2Value struct {
	Generation           uint64
	SandboxIP            uint32
	RuleCount            uint16
	TrafficEnabled       uint8
	IngressDefaultAction uint8
	EgressDefaultAction  uint8
	DNSEnabled           uint8
	Mode                 uint8
	UpdateBarrier        uint8
	Reserved             [4]uint8
	Rules                [maxCompiledRules]policyV2Rule
}

type domainPolicyKey struct {
	Generation uint64
	IfIndex    uint32
	PeerIP     uint32
}

type domainPolicyRule struct {
	ExpiresAt        uint64
	Priority         uint32
	PeerPortFirst    uint16
	PeerPortLast     uint16
	SandboxPortFirst uint16
	SandboxPortLast  uint16
	Action           uint8
	Protocol         uint8
	Reserved         [2]uint8
}

type domainPolicyValue struct {
	RuleCount uint16
	Reserved  [6]uint8
	Rules     [maxCompiledRules]domainPolicyRule
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

type connectionValue struct {
	ExpiresAt              uint64
	AuthorizationExpiresAt uint64
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
	grantStop     chan struct{}
	grantStopOnce sync.Once
	grantWG       sync.WaitGroup
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
		grantStop:     make(chan struct{}),
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
			manager.observeDNS,
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
	manager.grantWG.Add(1)
	go manager.sweepDomainGrants()
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
		if !entry.Policy.Empty() {
			if m.iptables == nil {
				// Pinned BPF state continues to enforce the old generation while
				// the replacement is prepared. Resolve its ownership to the live
				// endpoint, then use a fresh generation so derived domain state
				// can be staged before the policy-map switch.
				oldEntry = entry
			}
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
	next.DomainGrants = nil
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
		rollbackErr := m.rollbackApplyLocked(old, next)
		persistErr := m.persistLocked()
		return errors.Join(
			err,
			wrapOptionalError("roll back network ACL update", rollbackErr),
			wrapOptionalError("persist rolled-back network ACL update", persistErr),
		)
	}
	return nil
}

func (m *Manager) rollbackApplyLocked(old, attempted persistedEntry) error {
	if m.iptables != nil {
		return m.iptables.rollback(old, attempted)
	}
	return m.applyLocked(attempted, old)
}

func wrapOptionalError(message string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
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
	value, err := compileBPFPolicy(next)
	if err != nil {
		return err
	}
	key := uint32(next.IfIndex)
	var active policyV2Value
	lookupErr := m.objects.Policies.Lookup(&key, &active)
	policyAlreadyActive := lookupErr == nil
	previousIfIndex := old.IfIndex
	previousGeneration := old.Generation
	if policyAlreadyActive {
		// Persisted metadata can be one generation ahead after a failed daemon
		// restore. The pinned policy map is authoritative for the generation
		// actually enforcing this endpoint, so clean that dynamic state after
		// the replacement becomes active.
		previousIfIndex = next.IfIndex
		previousGeneration = active.Generation
	}
	if lookupErr != nil && !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("inspect active network ACL policy: %w", lookupErr)
	}

	// A daemon upgrading an active v1 sandbox has old TC programs attached but
	// no POLICY_V2_MAP entry. Stage the complete v2 policy before replacing
	// either program so every packet is evaluated by an initialized map. New
	// sandboxes use the same order before their runtime is started. Once a v2
	// entry exists, keep the normal attach-then-map-update order so replacement
	// remains atomic against the policy already enforced by both directions.
	if !policyAlreadyActive {
		if err := m.objects.Policies.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("stage network ACL generation %d: %w", next.Generation, err)
		}
		empty := next
		empty.DomainGrants = nil
		if err := m.applyDomainGrantsLocked(empty, next); err != nil {
			cleanupDomainErr := m.applyDomainGrantsLocked(next, empty)
			cleanupErr := m.removeV2PolicyMapLocked(next.IfIndex)
			return errors.Join(
				fmt.Errorf("stage derived domain grants for generation %d: %w", next.Generation, err),
				wrapOptionalError("remove staged derived domain grants", cleanupDomainErr),
				wrapOptionalError("remove staged network ACL policy", cleanupErr),
			)
		}
		if err := m.attachLocked(next); err != nil {
			// Keep the staged map and grants: FilterReplace may have installed
			// one direction before the other failed, and that direction must
			// continue to fail closed until lifecycle cleanup retries.
			return err
		}
	} else {
		if err := m.attachLocked(next); err != nil {
			return err
		}
		// Domain policies use generation-scoped keys, so populate the complete
		// next generation while both directions still consult the old policy.
		// This is essential for default-allow policies with domain DENY rules:
		// switching the policy first would create a transient allow window.
		empty := next
		empty.DomainGrants = nil
		if err := m.applyDomainGrantsLocked(empty, next); err != nil {
			cleanupErr := m.applyDomainGrantsLocked(next, empty)
			return errors.Join(
				fmt.Errorf("stage derived domain grants for generation %d: %w", next.Generation, err),
				wrapOptionalError("remove staged derived domain grants", cleanupErr),
			)
		}
		if err := m.objects.Policies.Update(&key, &value, ebpf.UpdateAny); err != nil {
			cleanupErr := m.applyDomainGrantsLocked(next, empty)
			return errors.Join(
				fmt.Errorf("activate network ACL generation %d: %w", next.Generation, err),
				wrapOptionalError("remove inactive derived domain grants", cleanupErr),
			)
		}
	}
	if previousGeneration != 0 && previousGeneration != next.Generation {
		if err := m.deleteRulesLocked(previousIfIndex, previousGeneration); err != nil {
			logrus.Warnf("delete old network ACL generation %d for %s: %v", previousGeneration, next.IP, err)
		}
		if err := m.deleteDynamicStateLocked(previousIfIndex, previousGeneration); err != nil {
			logrus.Warnf("delete old network ACL state generation %d for %s: %v", previousGeneration, next.IP, err)
		}
	}
	return nil
}

func compileBPFPolicy(entry persistedEntry) (policyV2Value, error) {
	value := policyV2Value{
		Generation: entry.Generation,
		SandboxIP:  ipv4Value(net.ParseIP(entry.IP)),
	}
	if entry.Policy.Traffic != nil {
		value.TrafficEnabled = 1
		value.IngressDefaultAction = entry.Policy.Traffic.ActionFor(directionIngress)
		value.EgressDefaultAction = entry.Policy.Traffic.ActionFor(directionEgress)
		value.Mode = entry.Policy.Traffic.Mode
		for _, rule := range entry.Policy.Traffic.Rules {
			if rule.PeerDomain != "" {
				continue
			}
			if value.RuleCount == maxCompiledRules {
				return policyV2Value{}, fmt.Errorf("compiled traffic policy exceeds %d rules", maxCompiledRules)
			}
			peerFirst, peerLast := rule.PeerPorts()
			sandboxFirst, sandboxLast := rule.SandboxPorts()
			peerPrefix := rule.PeerPrefix
			if !rule.PeerAny && entry.Policy.SchemaVersion != networkPolicySchemaV2 && peerPrefix == 0 {
				peerPrefix = 32
			}
			compiled := policyV2Rule{
				PeerIP:           ipv4Value(net.IP(rule.PeerIP[:])),
				Priority:         rule.Priority,
				PeerPortFirst:    peerFirst,
				PeerPortLast:     peerLast,
				SandboxPortFirst: sandboxFirst,
				SandboxPortLast:  sandboxLast,
				PeerPrefix:       peerPrefix,
				Action:           rule.Action,
				Protocol:         rule.Protocol,
			}
			for _, direction := range rule.Directions {
				compiled.Directions |= direction
			}
			if rule.PeerAny {
				compiled.MatchFlags |= ruleMatchPeerAny
			}
			value.Rules[value.RuleCount] = compiled
			value.RuleCount++
		}
	}
	if entry.Policy.NeedsDNSProxy() {
		value.DNSEnabled = 1
	}
	return value, nil
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
			if err := m.objects.LegacyRules.Lookup(&key, &existing); err == nil {
				// Duplicate protobuf rules compile to the same key. Preserve a
				// deny regardless of request ordering.
				if existing == actionDeny || value == actionAllow {
					continue
				}
			} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("inspect staged network ACL rule: %w", err)
			}
			if err := m.objects.LegacyRules.Update(&key, &value, ebpf.UpdateAny); err != nil {
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
	iterator := m.objects.LegacyRules.Iterate()
	var key ruleKey
	var value uint8
	var errs []error
	for iterator.Next(&key, &value) {
		if key.IfIndex != uint32(ifindex) || (generation != 0 && key.Generation != generation) {
			continue
		}
		candidate := key
		if err := m.objects.LegacyRules.Delete(&candidate); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
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
	var connectionState connectionValue
	for connections.Next(&connection, &connectionState) {
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
	var fragmentExpires uint64
	for fragments.Next(&fragment, &fragmentExpires) {
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
	domains := m.objects.DomainPolicies.Iterate()
	var domain domainPolicyKey
	var domainValue domainPolicyValue
	for domains.Next(&domain, &domainValue) {
		if domain.IfIndex != uint32(ifindex) || (generation != 0 && domain.Generation != generation) {
			continue
		}
		candidate := domain
		if err := m.objects.DomainPolicies.Delete(&candidate); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	if err := domains.Err(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) removePolicyMapLocked(ifindex int) error {
	return errors.Join(
		m.removeV2PolicyMapLocked(ifindex),
		m.removeLegacyPolicyMapLocked(ifindex),
	)
}

func (m *Manager) removeV2PolicyMapLocked(ifindex int) error {
	if ifindex == 0 {
		return nil
	}
	key := uint32(ifindex)
	err := m.objects.Policies.Delete(&key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		err = nil
	}
	return err
}

func (m *Manager) removeLegacyPolicyMapLocked(ifindex int) error {
	if ifindex == 0 {
		return nil
	}
	key := uint32(ifindex)
	legacyErr := m.objects.LegacyPolicies.Delete(&key)
	if errors.Is(legacyErr, ebpf.ErrKeyNotExist) {
		legacyErr = nil
	}
	return legacyErr
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

func (m *Manager) sweepDomainGrants() {
	defer m.grantWG.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := m.expireDomainGrants(); err != nil {
				logrus.Warnf("expire network ACL domain grants: %v", err)
			}
		case <-m.grantStop:
			return
		}
	}
}

func (m *Manager) expireDomainGrants() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UnixNano()
	var errs []error
	for sandboxID, current := range m.entries {
		if current.Orphaned || len(current.DomainGrants) == 0 {
			continue
		}
		next := current
		next.DomainGrants = make([]persistedDomainGrant, 0, len(current.DomainGrants))
		for _, grant := range current.DomainGrants {
			if grant.ExpiresAt > now {
				next.DomainGrants = append(next.DomainGrants, grant)
			}
		}
		if len(next.DomainGrants) == len(current.DomainGrants) {
			continue
		}
		if err := m.applyDomainGrantsLocked(current, next); err != nil {
			rollbackErr := m.applyDomainGrantsLocked(next, current)
			errs = append(errs, errors.Join(
				fmt.Errorf("apply expired grants for %s: %w", sandboxID, err),
				rollbackErr,
			))
			continue
		}
		m.entries[sandboxID] = next
		if err := m.persistLocked(); err != nil {
			m.entries[sandboxID] = current
			rollbackErr := m.applyDomainGrantsLocked(next, current)
			errs = append(errs, errors.Join(
				fmt.Errorf("persist expired grants for %s: %w", sandboxID, err), rollbackErr,
			))
		}
	}
	return errors.Join(errs...)
}

const maxDerivedDomainGrants = 4096

func (m *Manager) observeDNS(
	source net.IP, queryNames, grantNames []string, response []byte,
) ([]byte, error) {
	m.mu.RLock()
	sandboxID, ok := m.sourceIndex[source.String()]
	entry, entryOK := m.entries[sandboxID]
	hasDomainRules := entryOK && !entry.Orphaned && policyHasDomainRules(entry.Policy)
	queryAllowed := entryOK && !entry.Orphaned
	if queryAllowed {
		for _, name := range queryNames {
			if !entry.Policy.AllowDNS(name) {
				queryAllowed = false
				break
			}
		}
	}
	m.mu.RUnlock()
	if !ok || !entryOK || entry.Orphaned {
		return nil, fmt.Errorf("DNS response source %s is not an active sandbox", source)
	}
	if !queryAllowed {
		return nil, fmt.Errorf("network policy changed while resolving DNS for %s", source)
	}
	if !hasDomainRules {
		return response, nil
	}

	rewritten, resolved, err := resolveDNSResponse(response, grantNames)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	replacedQuestions := make(map[string]struct{}, len(grantNames))
	for _, name := range grantNames {
		replacedQuestions[canonicalDNSName(name)] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	sandboxID, ok = m.sourceIndex[source.String()]
	current, ok := m.entries[sandboxID]
	if !ok || current.Orphaned || current.Generation != entry.Generation {
		return nil, fmt.Errorf("network policy changed while resolving DNS for %s", source)
	}
	for _, name := range queryNames {
		if !current.Policy.AllowDNS(name) {
			return nil, fmt.Errorf("network policy changed while resolving DNS for %s", source)
		}
	}
	previous := current
	next := current
	next.DomainGrants = make([]persistedDomainGrant, 0, len(current.DomainGrants))
	for _, grant := range current.DomainGrants {
		if grant.ExpiresAt <= now.UnixNano() {
			continue
		}
		if _, replace := replacedQuestions[grant.Question]; replace {
			continue
		}
		next.DomainGrants = append(next.DomainGrants, grant)
	}
	for question, addresses := range resolved {
		for ruleIndex, rule := range current.Policy.Traffic.Rules {
			if rule.PeerDomain == "" || !domainMatches(question, rule.PeerDomain, rule.PeerWildcard) {
				continue
			}
			for _, address := range addresses {
				next.DomainGrants = append(next.DomainGrants, persistedDomainGrant{
					Question:  question,
					IP:        net.IP(address.IP[:]).String(),
					ExpiresAt: now.Add(time.Duration(address.TTL) * time.Second).UnixNano(),
					RuleIndex: uint16(ruleIndex),
				})
			}
		}
	}
	next.DomainGrants = deduplicateDomainGrants(next.DomainGrants)
	if len(next.DomainGrants) > maxDerivedDomainGrants {
		return nil, fmt.Errorf("sandbox %s has %d derived domain grants; maximum is %d", sandboxID, len(next.DomainGrants), maxDerivedDomainGrants)
	}
	if err := m.applyDomainGrantsLocked(previous, next); err != nil {
		rollbackErr := m.applyDomainGrantsLocked(next, previous)
		return nil, errors.Join(err, rollbackErr)
	}
	m.entries[sandboxID] = next
	if err := m.persistLocked(); err != nil {
		m.entries[sandboxID] = previous
		rollbackErr := m.applyDomainGrantsLocked(next, previous)
		return nil, errors.Join(fmt.Errorf("persist DNS grants for %s: %w", sandboxID, err), rollbackErr)
	}
	return rewritten, nil
}

func policyHasDomainRules(policy Policy) bool {
	if policy.Traffic == nil {
		return false
	}
	for _, rule := range policy.Traffic.Rules {
		if rule.PeerDomain != "" {
			return true
		}
	}
	return false
}

func deduplicateDomainGrants(grants []persistedDomainGrant) []persistedDomainGrant {
	type grantKey struct {
		question string
		ip       string
		rule     uint16
	}
	unique := make(map[grantKey]persistedDomainGrant, len(grants))
	for _, grant := range grants {
		key := grantKey{question: grant.Question, ip: grant.IP, rule: grant.RuleIndex}
		if previous, ok := unique[key]; !ok || grant.ExpiresAt > previous.ExpiresAt {
			unique[key] = grant
		}
	}
	out := make([]persistedDomainGrant, 0, len(unique))
	for _, grant := range unique {
		out = append(out, grant)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Question != out[j].Question {
			return out[i].Question < out[j].Question
		}
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].RuleIndex < out[j].RuleIndex
	})
	return out
}

func (m *Manager) applyDomainGrantsLocked(previous, next persistedEntry) (returnErr error) {
	if m.iptables != nil {
		return m.iptables.applyDomainGrants(previous, next)
	}
	wallNow := time.Now()
	monotonicNow, err := monotonicNanoseconds()
	if err != nil {
		return err
	}
	previousValues, err := compileDomainPoliciesAt(previous, wallNow, monotonicNow, true)
	if err != nil {
		return err
	}
	nextValues, err := compileDomainPoliciesAt(next, wallNow, monotonicNow, false)
	if err != nil {
		return err
	}
	originalPolicy, err := m.beginDomainGrantUpdateLocked(next)
	if err != nil {
		return err
	}
	releaseBarrier := true
	if originalPolicy != nil {
		defer func() {
			if !releaseBarrier {
				return
			}
			returnErr = errors.Join(
				returnErr,
				wrapOptionalError(
					"remove derived-domain update barrier",
					m.endDomainGrantUpdateLocked(next.IfIndex, *originalPolicy),
				),
			)
		}()
	}
	touched := make([]domainPolicyKey, 0, len(nextValues))
	rollback := func() error {
		var errs []error
		for _, key := range touched {
			if value, ok := previousValues[key]; ok {
				candidate, previousValue := key, value
				if updateErr := m.objects.DomainPolicies.Update(&candidate, &previousValue, ebpf.UpdateAny); updateErr != nil {
					errs = append(errs, updateErr)
				}
			} else {
				candidate := key
				if deleteErr := m.objects.DomainPolicies.Delete(&candidate); deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
					errs = append(errs, deleteErr)
				}
			}
		}
		return errors.Join(errs...)
	}
	failUpdate := func(cause error) error {
		// Keep an active generation fail-closed until the caller's explicit
		// reverse update repairs the complete map. Even when this local
		// rollback succeeds, releasing the barrier here would create a packet
		// window between this return and that reverse update. If recovery also
		// fails, retaining the barrier is the only safe terminal state.
		if originalPolicy != nil {
			releaseBarrier = false
		}
		return errors.Join(cause, rollback())
	}
	for key, value := range nextValues {
		candidate, nextValue := key, value
		if err := m.objects.DomainPolicies.Update(&candidate, &nextValue, ebpf.UpdateAny); err != nil {
			return failUpdate(fmt.Errorf("update derived domain policy: %w", err))
		}
		touched = append(touched, key)
	}
	for key := range previousValues {
		if _, keep := nextValues[key]; keep {
			continue
		}
		candidate := key
		if err := m.objects.DomainPolicies.Delete(&candidate); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return failUpdate(fmt.Errorf("remove replaced domain policy: %w", err))
		}
		touched = append(touched, key)
	}
	changedPeers := make(map[uint32]struct{})
	for key, previousValue := range previousValues {
		if nextValue, ok := nextValues[key]; !ok || nextValue != previousValue {
			changedPeers[key.PeerIP] = struct{}{}
		}
	}
	for key, nextValue := range nextValues {
		if previousValue, ok := previousValues[key]; !ok || previousValue != nextValue {
			changedPeers[key.PeerIP] = struct{}{}
		}
	}
	if err := m.deleteConnectionsForPeersLocked(next.IfIndex, next.Generation, changedPeers); err != nil {
		return failUpdate(fmt.Errorf("remove stale derived-domain state: %w", err))
	}
	return nil
}

// beginDomainGrantUpdateLocked installs a short fail-closed barrier only when
// the generation being edited is already active. A next policy generation is
// staged under unused map keys and therefore needs no barrier. The barrier
// prevents packets from racing domain-map replacement and stale state removal,
// especially for default-allow policies with domain DENY rules.
func (m *Manager) beginDomainGrantUpdateLocked(entry persistedEntry) (*policyV2Value, error) {
	if entry.IfIndex == 0 || entry.Generation == 0 {
		return nil, nil
	}
	key := uint32(entry.IfIndex)
	var active policyV2Value
	if err := m.objects.Policies.Lookup(&key, &active); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect active policy before derived-domain update: %w", err)
	}
	if active.Generation != entry.Generation {
		return nil, nil
	}
	if active.UpdateBarrier != 0 {
		// Updates are serialized by Manager.mu. A pre-existing barrier can only
		// be the fail-closed residue of an earlier failed update in this process
		// (or one recovered from pinned state). Reuse it so the reverse update
		// can repair the full map before clearing the barrier.
		original := active
		original.UpdateBarrier = 0
		return &original, nil
	}
	blocked := active
	blocked.UpdateBarrier = 1
	if err := m.objects.Policies.Update(&key, &blocked, ebpf.UpdateExist); err != nil {
		return nil, fmt.Errorf("install derived-domain update barrier: %w", err)
	}
	return &active, nil
}

func (m *Manager) endDomainGrantUpdateLocked(ifindex int, original policyV2Value) error {
	key := uint32(ifindex)
	if err := m.objects.Policies.Update(&key, &original, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("restore active policy after derived-domain update: %w", err)
	}
	return nil
}

func compileDomainPolicies(entry persistedEntry) (map[domainPolicyKey]domainPolicyValue, error) {
	wallNow := time.Now()
	monotonicNow, err := monotonicNanoseconds()
	if err != nil {
		return nil, err
	}
	return compileDomainPoliciesAt(entry, wallNow, monotonicNow, false)
}

func compileDomainPoliciesAt(
	entry persistedEntry, wallNow time.Time, monotonicNow uint64, includeExpired bool,
) (map[domainPolicyKey]domainPolicyValue, error) {
	values := make(map[domainPolicyKey]domainPolicyValue)
	if entry.Generation == 0 || entry.Policy.Traffic == nil {
		return values, nil
	}
	type expiryByRule map[uint16]int64
	byPeer := make(map[uint32]expiryByRule)
	for _, grant := range entry.DomainGrants {
		if (!includeExpired && grant.ExpiresAt <= wallNow.UnixNano()) ||
			int(grant.RuleIndex) >= len(entry.Policy.Traffic.Rules) {
			continue
		}
		rule := entry.Policy.Traffic.Rules[grant.RuleIndex]
		if rule.PeerDomain == "" {
			continue
		}
		ip := net.ParseIP(grant.IP).To4()
		if ip == nil {
			return nil, fmt.Errorf("persisted domain grant IP %q is not IPv4", grant.IP)
		}
		peer := ipv4Value(ip)
		if byPeer[peer] == nil {
			byPeer[peer] = make(expiryByRule)
		}
		if grant.ExpiresAt > byPeer[peer][grant.RuleIndex] {
			byPeer[peer][grant.RuleIndex] = grant.ExpiresAt
		}
	}
	for peer, expiries := range byPeer {
		indices := make([]int, 0, len(expiries))
		for index := range expiries {
			indices = append(indices, int(index))
		}
		sort.Ints(indices)
		if len(indices) > maxCompiledRules {
			return nil, fmt.Errorf("peer %s has %d derived rules; maximum is %d", uint32IPv4(peer), len(indices), maxCompiledRules)
		}
		var value domainPolicyValue
		for _, rawIndex := range indices {
			index := uint16(rawIndex)
			rule := entry.Policy.Traffic.Rules[index]
			peerFirst, peerLast := rule.PeerPorts()
			sandboxFirst, sandboxLast := rule.SandboxPorts()
			expiresAt := uint64(0)
			if expiries[index] > wallNow.UnixNano() {
				remaining := time.Duration(expiries[index] - wallNow.UnixNano())
				expiresAt = monotonicNow + uint64(remaining)
			}
			value.Rules[value.RuleCount] = domainPolicyRule{
				ExpiresAt:        expiresAt,
				Priority:         rule.Priority,
				PeerPortFirst:    peerFirst,
				PeerPortLast:     peerLast,
				SandboxPortFirst: sandboxFirst,
				SandboxPortLast:  sandboxLast,
				Action:           rule.Action,
				Protocol:         rule.Protocol,
			}
			value.RuleCount++
		}
		values[domainPolicyKey{Generation: entry.Generation, IfIndex: uint32(entry.IfIndex), PeerIP: peer}] = value
	}
	return values, nil
}

func monotonicNanoseconds() (uint64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &value); err != nil {
		return 0, fmt.Errorf("read monotonic clock: %w", err)
	}
	return uint64(value.Nano()), nil
}

func uint32IPv4(value uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], value)
	return net.IP(bytes[:])
}

func (m *Manager) deleteConnectionsForPeersLocked(ifindex int, generation uint64, peers map[uint32]struct{}) error {
	if len(peers) == 0 || ifindex == 0 {
		return nil
	}
	iterator := m.objects.Connections.Iterate()
	var key connectionKey
	var connectionState connectionValue
	var errs []error
	for iterator.Next(&key, &connectionState) {
		if key.IfIndex != uint32(ifindex) || key.Generation != generation {
			continue
		}
		if _, changed := peers[key.PeerIP]; !changed {
			continue
		}
		candidate := key
		if err := m.objects.Connections.Delete(&candidate); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	if err := iterator.Err(); err != nil {
		errs = append(errs, err)
	}
	fragments := m.objects.Fragments.Iterate()
	var fragment fragmentKey
	var fragmentState uint64
	for fragments.Next(&fragment, &fragmentState) {
		if fragment.IfIndex != uint32(ifindex) || fragment.Generation != generation {
			continue
		}
		_, sourceChanged := peers[fragment.SourceIP]
		_, destinationChanged := peers[fragment.DestinationIP]
		if !sourceChanged && !destinationChanged {
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

func (m *Manager) Close() error {
	var errs []error
	m.grantStopOnce.Do(func() { close(m.grantStop) })
	m.grantWG.Wait()
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
			"POLICY_MAP", "RULE_MAP", "POLICY_V2_MAP", "DOMAIN_V2_MAP",
			"CONNECTION_MAP", "CONN_V2_MAP", "FRAGMENT_MAP", "CONFIG_MAP",
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
