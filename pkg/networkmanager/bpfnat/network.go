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

package bpfnat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bpffsRoot = "/sys/fs/bpf"
	pinRoot   = bpffsRoot + "/sandboxd/bpfnat"

	filterPriority = 32000

	protocolICMP = 1
	protocolTCP  = 6
	protocolUDP  = 17

	natTypeSNAT = 0
	natTypeDNAT = 1

	natDirEgress  = 0
	natDirIngress = 1

	ctCreate    = 1
	ctEstablish = 2
	ctClose     = 3

	defaultTimeoutNonTCP   = 60
	defaultTimeoutTCPSYN   = 60
	defaultTimeoutTCPEst   = 21600
	defaultTimeoutTCPClose = 10

	gcInterval = time.Minute
)

type gcMode string

const (
	gcModeUserspace gcMode = "userspace"
	gcModeBPFTimer  gcMode = "bpf_timer"
)

type programHelperProbe func(ebpf.ProgramType, asm.BuiltinFunc) error

const (
	physicalIngressHandle = 0xb1
	physicalEgressHandle  = 0xb2
	localIngressHandle    = 0xb3
	bridgeIngressHandle   = 0xb4
)

type bpfObjects struct {
	EgressProgram  *ebpf.Program `ebpf:"sandboxd_egress_bpfnat"`
	IngressProgram *ebpf.Program `ebpf:"sandboxd_ingress_bpfnat"`
	LocalProgram   *ebpf.Program `ebpf:"sandboxd_local_ingress_bpfnat"`
	BridgeProgram  *ebpf.Program `ebpf:"sandboxd_bridge_ingress_bpfnat"`
	SNATMappings   *ebpf.Map     `ebpf:"SNAT_MAPPING_IPV4"`
	EgressPolicies *ebpf.Map     `ebpf:"EGRESS_POLICY_MAP"`
	DNATRules      *ebpf.Map     `ebpf:"DNAT_RULES_MAP"`
	SNATConfig     *ebpf.Map     `ebpf:"SNAT_CONFIG_MAP"`
	HostPorts      *ebpf.Map     `ebpf:"POD_PORT_MAP"`
	LocalRedirect  *ebpf.Map     `ebpf:"LOCAL_REDIRECT_MAP"`
}

func (o *bpfObjects) close() error {
	return errors.Join(
		closeProgram(o.EgressProgram),
		closeProgram(o.IngressProgram),
		closeProgram(o.LocalProgram),
		closeProgram(o.BridgeProgram),
		closeMap(o.SNATMappings),
		closeMap(o.EgressPolicies),
		closeMap(o.DNATRules),
		closeMap(o.SNATConfig),
		closeMap(o.HostPorts),
		closeMap(o.LocalRedirect),
	)
}

func closeProgram(program *ebpf.Program) error {
	if program == nil {
		return nil
	}
	return program.Close()
}

func closeMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	return m.Close()
}

func selectGCMode(probe programHelperProbe) (gcMode, error) {
	if probe == nil {
		probe = features.HaveProgramHelper
	}
	for _, helper := range []asm.BuiltinFunc{
		asm.FnTimerInit,
		asm.FnTimerSetCallback,
		asm.FnTimerStart,
	} {
		if err := probe(ebpf.SchedCLS, helper); errors.Is(err, ebpf.ErrNotSupported) {
			return gcModeUserspace, nil
		} else if err != nil {
			return "", fmt.Errorf("probe bpfnat BPF timer helper %s: %w", helper, err)
		}
	}
	return gcModeBPFTimer, nil
}

func pinPathForMode(mode gcMode) string {
	return filepath.Join(pinRoot, string(mode))
}

func loadEmbeddedSpec(mode gcMode) (*ebpf.CollectionSpec, error) {
	switch mode {
	case gcModeUserspace:
		return loadBpfnat_legacy()
	case gcModeBPFTimer:
		return loadBpfnat_timer()
	default:
		return nil, fmt.Errorf("unsupported bpfnat GC mode %q", mode)
	}
}

type attachment struct {
	linkIndex int
	parent    uint32
	handle    uint32
	name      string
}

func readSysctl(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read sysctl %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func requireSysctl(path, name, value string) error {
	current, err := readSysctl(path)
	if err != nil {
		return err
	}
	if current != value {
		return fmt.Errorf(
			"bpfnat requires %s=%s, got %q; configure the host before starting sandboxd",
			name, value, current,
		)
	}
	return nil
}

func setSysctl(path, name, value string) error {
	current, err := readSysctl(path)
	if err != nil {
		return err
	}
	if current == value {
		return nil
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0644); err != nil {
		return fmt.Errorf("set %s=%s: %w", name, value, err)
	}
	return nil
}

type Manager struct {
	mu sync.Mutex

	config      networkmanager.BackendConfig
	initialized bool
	device      netlink.Link
	deviceIP    [4]byte
	ipRange     string
	objects     bpfObjects
	attachments map[string]attachment
	ownedQdiscs map[int]struct{}
	gcMode      gcMode
	pinPath     string

	gcStop chan struct{}
	gcDone chan struct{}

	probeProgramHelper programHelperProbe
}

var defaultManager = &Manager{}

var (
	_ networkmanager.NetworkManager             = (*Manager)(nil)
	_ networkmanager.ConfigurableNetworkManager = (*Manager)(nil)
	_ networkmanager.LocalDNATManager           = (*Manager)(nil)
)

func (m *Manager) Configure(cfg networkmanager.BackendConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.initialized && m.config != cfg {
		return fmt.Errorf("bpfnat is already initialized with a different configuration")
	}
	m.config = cfg
	return nil
}

func (m *Manager) SetupSNATRules(ipRange string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		if m.ipRange != ipRange {
			return fmt.Errorf("bpfnat already manages IP range %s", m.ipRange)
		}
		return nil
	}
	if err := m.validateHostSysctlsLocked(); err != nil {
		return err
	}

	if err := ensureBPFFS(); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove BPF memlock limit: %w", err)
	}
	mode, err := selectGCMode(m.probeProgramHelper)
	if err != nil {
		return err
	}
	selectedPinPath := pinPathForMode(mode)
	if err := os.MkdirAll(selectedPinPath, 0700); err != nil {
		return fmt.Errorf("create bpfnat pin directory: %w", err)
	}

	device, deviceIP, err := selectExternalDevice(m.config.Device)
	if err != nil {
		return err
	}

	spec, err := loadEmbeddedSpec(mode)
	if err != nil {
		return fmt.Errorf("read embedded bpfnat object: %w", err)
	}
	var objects bpfObjects
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: selectedPinPath},
	}); err != nil {
		return fmt.Errorf("load embedded bpfnat object with gc_mode=%s: %w", mode, err)
	}

	m.objects = objects
	m.device = device
	m.deviceIP = deviceIP
	m.ipRange = ipRange
	m.attachments = make(map[string]attachment)
	m.ownedQdiscs = make(map[int]struct{})
	m.gcMode = mode
	m.pinPath = selectedPinPath
	m.initialized = true

	if err := m.initializeMapsLocked(ipRange); err != nil {
		return m.rollbackInitializationLocked(err)
	}
	if err := m.attachLocked(device, netlink.HANDLE_MIN_INGRESS, physicalIngressHandle,
		"sd_bpfnat_in", m.objects.IngressProgram); err != nil {
		return m.rollbackInitializationLocked(err)
	}
	if err := m.attachLocked(device, netlink.HANDLE_MIN_EGRESS, physicalEgressHandle,
		"sd_bpfnat_out", m.objects.EgressProgram); err != nil {
		return m.rollbackInitializationLocked(err)
	}
	if m.config.EnableLocalDNAT {
		if err := m.attachLocalPathLocked(); err != nil {
			return m.rollbackInitializationLocked(err)
		}
	}

	if mode == gcModeUserspace {
		m.gcStop = make(chan struct{})
		m.gcDone = make(chan struct{})
		go m.runGC(m.gcStop, m.gcDone, m.objects.SNATMappings, m.objects.SNATConfig)
	}

	logrus.Infof("bpfnat initialized on %s (%s), pins=%s gc_mode=%s local_dnat=%t",
		device.Attrs().Name, net.IP(deviceIP[:]), selectedPinPath, mode,
		m.config.EnableLocalDNAT)
	return nil
}

func (m *Manager) rollbackInitializationLocked(cause error) error {
	detachErr := m.detachAllLocked()
	unpinErr := m.unpinMapsLocked()
	closeErr := m.objects.close()
	removePinErr := removePinDirectories(m.pinPath)
	m.objects = bpfObjects{}
	m.device = nil
	m.ipRange = ""
	m.attachments = nil
	m.ownedQdiscs = nil
	m.gcMode = ""
	m.pinPath = ""
	m.initialized = false
	return errors.Join(cause, detachErr, unpinErr, closeErr, removePinErr)
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

func selectExternalDevice(name string) (netlink.Link, [4]byte, error) {
	var link netlink.Link
	var err error
	if name != "" {
		link, err = netlink.LinkByName(name)
		if err != nil {
			return nil, [4]byte{}, fmt.Errorf("find configured bpfnat device %s: %w", name, err)
		}
	} else {
		routes, routeErr := netlink.RouteGet(net.ParseIP("1.1.1.1"))
		if routeErr != nil {
			return nil, [4]byte{}, fmt.Errorf("resolve IPv4 default route: %w", routeErr)
		}
		for _, route := range routes {
			if route.LinkIndex > 0 {
				link, err = netlink.LinkByIndex(route.LinkIndex)
				if err != nil {
					return nil, [4]byte{}, fmt.Errorf("find default-route device index %d: %w", route.LinkIndex, err)
				}
				break
			}
		}
		if link == nil {
			return nil, [4]byte{}, fmt.Errorf("IPv4 default route has no output device")
		}
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, [4]byte{}, fmt.Errorf("list IPv4 addresses on %s: %w", link.Attrs().Name, err)
	}
	for _, addr := range addrs {
		ip := addr.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		var result [4]byte
		copy(result[:], ip)
		return link, result, nil
	}
	return nil, [4]byte{}, fmt.Errorf("bpfnat device %s has no usable IPv4 address", link.Attrs().Name)
}

type egressPolicyKey struct {
	PrefixLen uint32
	Source    [4]byte
	Dest      [4]byte
}

func makeEgressPolicy(ipRange string) (egressPolicyKey, error) {
	ip, network, err := net.ParseCIDR(ipRange)
	if err != nil {
		return egressPolicyKey{}, fmt.Errorf("parse SNAT IP range %q: %w", ipRange, err)
	}
	ip = ip.To4()
	if ip == nil {
		return egressPolicyKey{}, fmt.Errorf("bpfnat only supports IPv4 SNAT ranges: %s", ipRange)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return egressPolicyKey{}, fmt.Errorf("bpfnat only supports IPv4 SNAT ranges: %s", ipRange)
	}
	key := egressPolicyKey{PrefixLen: uint32(ones)}
	copy(key.Source[:], network.IP.To4())
	return key, nil
}

func (m *Manager) initializeMapsLocked(ipRange string) error {
	key, err := makeEgressPolicy(ipRange)
	if err != nil {
		return err
	}
	if err := m.objects.EgressPolicies.Update(&key, &m.deviceIP, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("install SNAT policy for %s: %w", ipRange, err)
	}

	portMin, err := hostEphemeralPortEnd()
	if err != nil {
		return err
	}
	portMin++
	if portMin >= 65536 {
		return fmt.Errorf("host ephemeral port range leaves no ports for bpfnat")
	}
	minKey, maxKey := uint32(1), uint32(2)
	maxValue := uint32(65536)
	if err := m.objects.SNATConfig.Update(&minKey, &portMin, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("set bpfnat source-port minimum: %w", err)
	}
	if err := m.objects.SNATConfig.Update(&maxKey, &maxValue, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("set bpfnat source-port maximum: %w", err)
	}
	if err := m.refreshHostPortsLocked(portMin); err != nil {
		return err
	}
	return nil
}

func hostEphemeralPortEnd() (uint32, error) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, fmt.Errorf("read host ephemeral port range: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, fmt.Errorf("parse host ephemeral port range %q", strings.TrimSpace(string(data)))
	}
	end, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || end > 65535 {
		return 0, fmt.Errorf("parse host ephemeral port maximum %q", fields[1])
	}
	return uint32(end), nil
}

func (m *Manager) refreshHostPortsLocked(portMin uint32) error {
	iter := m.objects.HostPorts.Iterate()
	var key uint32
	var value uint8
	for iter.Next(&key, &value) {
		if err := m.objects.HostPorts.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("clear bpfnat host-port map: %w", err)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate bpfnat host-port map: %w", err)
	}

	for _, source := range []struct {
		path     string
		protocol uint8
	}{
		{path: "/proc/net/tcp", protocol: protocolTCP},
		{path: "/proc/net/udp", protocol: protocolUDP},
	} {
		ports, err := listeningPorts(source.path)
		if err != nil {
			return err
		}
		for _, port := range ports {
			if uint32(port) < portMin {
				continue
			}
			portKey := uint32(port)<<16 | uint32(source.protocol)
			one := uint8(1)
			if err := m.objects.HostPorts.Update(&portKey, &one, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("reserve host port %d/%d in bpfnat: %w", port, source.protocol, err)
			}
		}
	}
	return nil
}

func listeningPorts(path string) ([]uint16, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read listening ports from %s: %w", path, err)
	}
	var ports []uint16
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// TCP LISTEN is 0A; an unconnected UDP socket is 07.
		if fields[3] != "0A" && fields[3] != "07" {
			continue
		}
		address := strings.Split(fields[1], ":")
		if len(address) != 2 {
			continue
		}
		port, err := strconv.ParseUint(address[1], 16, 16)
		if err != nil {
			return nil, fmt.Errorf("parse port in %s: %w", path, err)
		}
		ports = append(ports, uint16(port))
	}
	return ports, nil
}

func (m *Manager) validateHostSysctlsLocked() error {
	if err := requireSysctl(
		"/proc/sys/net/ipv4/ip_forward",
		"net.ipv4.ip_forward",
		"1",
	); err != nil {
		return err
	}
	if !m.config.EnableLocalDNAT {
		return nil
	}
	// Linux uses the maximum of the all and per-interface rp_filter values.
	// Host setup owns the global policy; configureLocalSysctlsLocked owns the
	// sandbox bridge value after that interface has been created.
	return requireSysctl(
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"net.ipv4.conf.all.rp_filter",
		"0",
	)
}

func (m *Manager) configureLocalSysctlsLocked() error {
	bridgePath := "/proc/sys/net/ipv4/conf/" + networkmanager.BridgeName
	if err := setSysctl(
		bridgePath+"/accept_local",
		"net.ipv4.conf."+networkmanager.BridgeName+".accept_local",
		"1",
	); err != nil {
		return err
	}
	return setSysctl(
		bridgePath+"/rp_filter",
		"net.ipv4.conf."+networkmanager.BridgeName+".rp_filter",
		"0",
	)
}

func ensureClsact(link netlink.Link) (bool, error) {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, fmt.Errorf("add clsact qdisc to %s: %w", link.Attrs().Name, err)
	}
	return true, nil
}

func attachmentKey(linkIndex int, parent, handle uint32) string {
	return fmt.Sprintf("%d/%d/%d", linkIndex, parent, handle)
}

func (m *Manager) attachLocked(
	link netlink.Link,
	parent uint32,
	handle uint16,
	name string,
	program *ebpf.Program,
) error {
	createdQdisc, err := ensureClsact(link)
	if err != nil {
		return err
	}
	if createdQdisc {
		m.ownedQdiscs[link.Attrs().Index] = struct{}{}
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return fmt.Errorf("list existing filters on %s: %w", link.Attrs().Name, err)
	}
	wantedHandle := netlink.MakeHandle(0, handle)
	for _, candidate := range filters {
		attrs := candidate.Attrs()
		if attrs.Handle != wantedHandle || attrs.Priority != filterPriority {
			continue
		}
		filter, ok := candidate.(*netlink.BpfFilter)
		if !ok || filter.Name != name {
			return fmt.Errorf("TC filter handle %x priority %d on %s is already in use",
				wantedHandle, filterPriority, link.Attrs().Name)
		}
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    wantedHandle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  filterPriority,
		},
		Fd:           program.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("attach %s to %s: %w", name, link.Attrs().Name, err)
	}
	item := attachment{
		linkIndex: link.Attrs().Index,
		parent:    parent,
		handle:    filter.Handle,
		name:      name,
	}
	m.attachments[attachmentKey(item.linkIndex, item.parent, item.handle)] = item
	return nil
}

func (m *Manager) attachLocalPathLocked() error {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find loopback device for local DNAT: %w", err)
	}
	bridge, err := netlink.LinkByName(networkmanager.BridgeName)
	if err != nil {
		return fmt.Errorf("find sandbox bridge for local DNAT: %w", err)
	}
	redirectKey := uint32(0)
	redirectIfindex := uint32(bridge.Attrs().Index)
	if err := m.objects.LocalRedirect.Update(&redirectKey, &redirectIfindex, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("configure local DNAT redirect to %s: %w", networkmanager.BridgeName, err)
	}
	if err := m.configureLocalSysctlsLocked(); err != nil {
		return err
	}
	if err := m.attachLocked(bridge, netlink.HANDLE_MIN_INGRESS, bridgeIngressHandle,
		"sd_bpfnat_rev", m.objects.BridgeProgram); err != nil {
		return err
	}
	// Attach the local-origin path last so packets are not redirected until
	// the bridge reverse path and its interface sysctls are ready.
	return m.attachLocked(loopback, netlink.HANDLE_MIN_INGRESS, localIngressHandle,
		"sd_bpfnat_loc", m.objects.LocalProgram)
}

func (m *Manager) detachAllLocked() error {
	var errs []error
	for key, item := range m.attachments {
		link, err := netlink.LinkByIndex(item.linkIndex)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if !errors.As(err, &notFound) && !errors.Is(err, unix.ENODEV) {
				errs = append(errs, fmt.Errorf("find link index %d to detach bpfnat: %w", item.linkIndex, err))
			}
			delete(m.attachments, key)
			continue
		}
		filters, err := netlink.FilterList(link, item.parent)
		if err != nil {
			errs = append(errs, fmt.Errorf("list bpfnat filters on %s: %w", link.Attrs().Name, err))
			continue
		}
		for _, candidate := range filters {
			filter, ok := candidate.(*netlink.BpfFilter)
			if !ok || filter.Name != item.name || filter.Handle != item.handle ||
				filter.Priority != filterPriority {
				continue
			}
			if err := netlink.FilterDel(filter); err != nil && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, fmt.Errorf("detach %s from %s: %w", item.name, link.Attrs().Name, err))
			}
		}
		delete(m.attachments, key)
	}
	if err := m.removeOwnedQdiscsLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) removeOwnedQdiscsLocked() error {
	var errs []error
	for linkIndex := range m.ownedQdiscs {
		link, err := netlink.LinkByIndex(linkIndex)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if !errors.As(err, &notFound) && !errors.Is(err, unix.ENODEV) {
				errs = append(errs, fmt.Errorf("find link index %d to remove clsact: %w", linkIndex, err))
			}
			delete(m.ownedQdiscs, linkIndex)
			continue
		}
		ingress, ingressErr := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
		egress, egressErr := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
		if ingressErr != nil || egressErr != nil {
			errs = append(errs, errors.Join(ingressErr, egressErr))
			continue
		}
		if len(ingress) != 0 || len(egress) != 0 {
			delete(m.ownedQdiscs, linkIndex)
			continue
		}
		qdiscs, err := netlink.QdiscList(link)
		if err != nil {
			errs = append(errs, fmt.Errorf("list qdiscs on %s: %w", link.Attrs().Name, err))
			continue
		}
		for _, qdisc := range qdiscs {
			if qdisc.Type() != "clsact" {
				continue
			}
			if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, fmt.Errorf("remove clsact from %s: %w", link.Attrs().Name, err))
			}
			break
		}
		delete(m.ownedQdiscs, linkIndex)
	}
	return errors.Join(errs...)
}

func protocolNumber(protocol string) (uint8, error) {
	switch strings.ToLower(protocol) {
	case "tcp", "6":
		return protocolTCP, nil
	case "udp", "17":
		return protocolUDP, nil
	case "icmp", "1":
		return protocolICMP, nil
	default:
		return 0, fmt.Errorf("unsupported bpfnat protocol %q", protocol)
	}
}

func makeDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) ([4]byte, [8]byte, error) {
	var key [4]byte
	var value [8]byte
	protocolID, err := protocolNumber(protocol)
	if err != nil {
		return key, value, err
	}
	ip := net.ParseIP(targetIP).To4()
	if ip == nil {
		return key, value, fmt.Errorf("bpfnat DNAT target must be IPv4: %q", targetIP)
	}
	binary.BigEndian.PutUint16(key[0:2], dstPort)
	key[2] = protocolID
	copy(value[0:4], ip)
	binary.BigEndian.PutUint16(value[4:6], targetPort)
	return key, value, nil
}

func (m *Manager) SetupDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error {
	key, value, err := makeDNATRule(protocol, dstPort, targetIP, targetPort)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.initialized {
		return fmt.Errorf("bpfnat is not initialized")
	}
	var current [8]byte
	err = m.objects.DNATRules.Lookup(&key, &current)
	if err == nil {
		if current == value {
			return nil
		}
		return fmt.Errorf("bpfnat port %s/%d already targets %s:%d",
			protocol, dstPort, net.IP(current[0:4]), binary.BigEndian.Uint16(current[4:6]))
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("lookup bpfnat DNAT rule: %w", err)
	}
	if err := m.objects.DNATRules.Update(&key, &value, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("install bpfnat DNAT rule: %w", err)
	}
	return nil
}

func (m *Manager) CleanupDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error {
	key, value, err := makeDNATRule(protocol, dstPort, targetIP, targetPort)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.initialized {
		return nil
	}
	var current [8]byte
	if err := m.objects.DNATRules.Lookup(&key, &current); errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("lookup bpfnat DNAT rule for cleanup: %w", err)
	}
	if current != value {
		return nil
	}
	if err := m.objects.DNATRules.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete bpfnat DNAT rule: %w", err)
	}
	return nil
}

func (m *Manager) SetupLocalDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error {
	if _, _, err := makeDNATRule(protocol, dstPort, targetIP, targetPort); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.initialized {
		return fmt.Errorf("bpfnat is not initialized")
	}
	if !m.config.EnableLocalDNAT {
		return fmt.Errorf("local DNAT is not enabled for bpfnat")
	}
	// External and local paths intentionally share DNAT_RULES_MAP. The local
	// method validates that its TC path is active; SetupDNATRule owns the map.
	return nil
}

func (m *Manager) CleanupLocalDNATRule(string, uint16, string, uint16) error {
	// CleanupDNATRule owns the shared map entry and is called immediately after
	// this method by the server.
	return nil
}

func (m *Manager) SetupNetworkRulesForActivating(net.IP, string) error { return nil }

func (m *Manager) CleanupNetworkRulesForActivating(net.IP) error { return nil }

func (m *Manager) CleanupSNATRules(string) error {
	m.mu.Lock()
	if !m.initialized {
		m.mu.Unlock()
		return nil
	}
	stop, done := m.gcStop, m.gcDone
	m.gcStop, m.gcDone = nil, nil
	m.mu.Unlock()

	if stop != nil {
		close(stop)
		<-done
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	if key, err := makeEgressPolicy(m.ipRange); err != nil {
		errs = append(errs, err)
	} else if err := m.objects.EgressPolicies.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, fmt.Errorf("delete bpfnat SNAT policy: %w", err))
	}
	if err := m.detachAllLocked(); err != nil {
		errs = append(errs, err)
	}
	if err := m.unpinMapsLocked(); err != nil {
		errs = append(errs, err)
	}
	if err := m.objects.close(); err != nil {
		errs = append(errs, fmt.Errorf("close bpfnat objects: %w", err))
	}
	if err := removePinDirectories(m.pinPath); err != nil {
		errs = append(errs, err)
	}
	m.objects = bpfObjects{}
	m.device = nil
	m.ipRange = ""
	m.attachments = nil
	m.ownedQdiscs = nil
	m.gcMode = ""
	m.pinPath = ""
	m.initialized = false
	return errors.Join(errs...)
}

func (m *Manager) unpinMapsLocked() error {
	var errs []error
	for _, pinnedMap := range []*ebpf.Map{
		m.objects.SNATMappings,
		m.objects.EgressPolicies,
		m.objects.DNATRules,
		m.objects.SNATConfig,
		m.objects.HostPorts,
		m.objects.LocalRedirect,
	} {
		if pinnedMap != nil {
			if err := pinnedMap.Unpin(); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("unpin bpfnat map: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}

func removePinDirectories(selectedPinPath string) error {
	var errs []error
	if selectedPinPath == "" {
		return nil
	}
	if err := os.Remove(selectedPinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove bpfnat pin directory: %w", err))
	}
	if err := os.Remove(pinRoot); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOTEMPTY) {
		errs = append(errs, fmt.Errorf("remove bpfnat pin root: %w", err))
	}
	parent := filepath.Dir(pinRoot)
	if err := os.Remove(parent); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOTEMPTY) {
		errs = append(errs, fmt.Errorf("remove sandboxd pin directory: %w", err))
	}
	return errors.Join(errs...)
}

type ipv4Tuple struct {
	DestAddr   uint32
	SourceAddr uint32
	DestPort   uint16
	SourcePort uint16
	Protocol   uint8
	Flags      uint8
	Pad        uint16
}

type ipv4NATEntry struct {
	Created        uint64
	HostLocal      uint64
	Pad1           uint64
	Pad2           uint64
	TargetAddr     uint32
	TargetPort     uint16
	TargetPad      uint16
	LastAccessTime uint32
	Status         int32
	Type           int32
	Pad3           uint32
}

func (m *Manager) runGC(stop <-chan struct{}, done chan<- struct{}, mappings, cfg *ebpf.Map) {
	m.runGCWithInterval(stop, done, mappings, cfg, gcInterval)
}

func (m *Manager) runGCWithInterval(
	stop <-chan struct{},
	done chan<- struct{},
	mappings, cfg *ebpf.Map,
	interval time.Duration,
) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := collectExpired(mappings, cfg); err != nil {
				logrus.Warnf("bpfnat connection GC failed: %v", err)
			}
		}
	}
}

func bootTimeSeconds() (uint32, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return uint32(ts.Sec), nil
}

func connectionTimeout(tuple ipv4Tuple, entry ipv4NATEntry, configured uint32) uint32 {
	if tuple.Protocol != protocolTCP {
		if configured != 0 {
			return configured
		}
		return defaultTimeoutNonTCP
	}
	switch entry.Status {
	case ctCreate:
		return defaultTimeoutTCPSYN
	case ctEstablish:
		if configured != 0 {
			return configured
		}
		return defaultTimeoutTCPEst
	case ctClose:
		return defaultTimeoutTCPClose
	default:
		if configured != 0 {
			return configured
		}
		return defaultTimeoutNonTCP
	}
}

func reverseTuple(tuple ipv4Tuple, entry ipv4NATEntry) ipv4Tuple {
	reverse := ipv4Tuple{
		DestAddr:   tuple.SourceAddr,
		SourceAddr: tuple.DestAddr,
		DestPort:   tuple.SourcePort,
		SourcePort: tuple.DestPort,
		Protocol:   tuple.Protocol,
		Flags:      natDirIngress,
	}
	if tuple.Flags == natDirIngress {
		reverse.Flags = natDirEgress
	}
	if entry.Type == natTypeSNAT {
		reverse.DestAddr = entry.TargetAddr
		reverse.DestPort = entry.TargetPort
	} else {
		reverse.SourceAddr = entry.TargetAddr
		reverse.SourcePort = entry.TargetPort
	}
	return reverse
}

func collectExpired(mappings, cfg *ebpf.Map) error {
	now, err := bootTimeSeconds()
	if err != nil {
		return fmt.Errorf("read boot time: %w", err)
	}
	var configured uint32
	timeoutKey := uint32(0)
	if err := cfg.Lookup(&timeoutKey, &configured); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("read bpfnat timeout: %w", err)
	}

	iter := mappings.Iterate()
	var tuple ipv4Tuple
	var entry ipv4NATEntry
	for iter.Next(&tuple, &entry) {
		isOriginal := entry.Type == natTypeSNAT && tuple.Flags == natDirEgress ||
			entry.Type == natTypeDNAT && tuple.Flags == natDirIngress
		if !isOriginal || entry.LastAccessTime+connectionTimeout(tuple, entry, configured) > now {
			continue
		}
		reverse := reverseTuple(tuple, entry)
		if err := mappings.Delete(&reverse); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete reverse bpfnat mapping: %w", err)
		}
		if err := mappings.Delete(&tuple); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete bpfnat mapping: %w", err)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate bpfnat mappings: %w", err)
	}
	return nil
}

func init() {
	networkmanager.Register(config.NatBackendBpfnat, defaultManager)
}
