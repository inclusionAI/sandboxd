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

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	kataNetworkStateFile  = "kata-network.json"
	kataNetworkQueuePairs = 1
	kataNetworkQueueSize  = 256
)

type kataDANConfig struct {
	NetNS   *string         `json:"netns"`
	Devices []kataDANDevice `json:"devices"`
}

type kataDANDevice struct {
	Name        string             `json:"name"`
	GuestMAC    string             `json:"guest_mac"`
	Device      kataDANDeviceSpec  `json:"device"`
	NetworkInfo kataDANNetworkInfo `json:"network_info"`
}

type kataDANDeviceSpec struct {
	Type      string `json:"type"`
	TapName   string `json:"tap_name"`
	QueueNum  int    `json:"queue_num"`
	QueueSize int    `json:"queue_size"`
}

type kataDANNetworkInfo struct {
	Interface kataDANInterface  `json:"interface"`
	Routes    []kataDANRoute    `json:"routes"`
	Neighbors []kataDANNeighbor `json:"neighbors"`
}

type kataDANInterface struct {
	IPAddresses []string `json:"ip_addresses"`
	MTU         int      `json:"mtu"`
	Type        string   `json:"ntype"`
	Flags       int      `json:"flags"`
}

type kataDANRoute struct {
	Destination string `json:"dest"`
	Gateway     string `json:"gateway"`
	Source      string `json:"source"`
	Scope       int    `json:"scope"`
	Flags       int    `json:"flags"`
	MTU         int    `json:"mtu"`
}

type kataDANNeighbor struct {
	IPAddress    *string `json:"ip_address"`
	HardwareAddr string  `json:"hardware_addr"`
	State        int     `json:"state"`
	Flags        int     `json:"flags"`
}

type kataNetworkState struct {
	TapName      string `json:"tap_name"`
	PeerVethName string `json:"peer_veth_name"`
	DANConfig    string `json:"dan_config"`
}

func prepareKataNetwork(
	sandboxID string,
	bundlePath string,
	resource *networkmanager.NetResource,
	danConfigDir string,
) (func(), error) {
	if err := validateKataNetworkResource(resource); err != nil {
		return nil, err
	}
	cleanupKataNetwork(bundlePath)

	tapName := resource.Interface.Name
	danConfigPath := filepath.Join(danConfigDir, sandboxID+".json")
	tap, err := netlink.LinkByName(tapName)
	if err != nil {
		return nil, fmt.Errorf("find cached Kata TAP %s: %w", tapName, err)
	}
	if tap.Type() != "tuntap" {
		return nil, fmt.Errorf("cached Kata endpoint %s has type %q, want tuntap", tapName, tap.Type())
	}

	cleanup := func() {
		if err := os.Remove(danConfigPath); err != nil && !os.IsNotExist(err) {
			logrus.Warnf("kata: remove DAN config %s: %v", danConfigPath, err)
		}
		_ = os.Remove(filepath.Join(bundlePath, kataNetworkStateFile))
	}
	if err := writeKataDANConfig(danConfigPath, tapName, resource); err != nil {
		cleanup()
		return nil, err
	}
	state := kataNetworkState{
		TapName:   tapName,
		DANConfig: danConfigPath,
	}
	if err := writeKataNetworkState(bundlePath, state); err != nil {
		cleanup()
		return nil, err
	}
	if err := removeKataNetworkNamespace(bundlePath); err != nil {
		cleanup()
		return nil, err
	}

	logrus.Infof(
		"kata: configured DAN sandbox=%s cached_tap=%s bridge=%s ip=%s",
		sandboxID,
		tapName,
		networkmanager.BridgeName,
		resource.Ip,
	)
	return cleanup, nil
}

func validateKataNetworkResource(resource *networkmanager.NetResource) error {
	if resource == nil || resource.Interface == nil || resource.Interface.Name == "" {
		return fmt.Errorf("Kata network interface is missing")
	}
	if resource.SchemaVersion != networkmanager.NetResourceSchemaVersion ||
		resource.EndpointType != networkmanager.EndpointTypeTap {
		return fmt.Errorf(
			"Kata DAN requires a versioned TAP endpoint, got schema=%d endpoint=%q",
			resource.SchemaVersion, resource.EndpointType,
		)
	}
	if resource.Ip.To4() == nil {
		return fmt.Errorf("Kata DAN requires an IPv4 address")
	}
	if resource.Gateway.To4() == nil {
		return fmt.Errorf("Kata DAN requires an IPv4 gateway")
	}
	ones, bits := resource.Mask.Size()
	if bits != 32 || ones < 0 {
		return fmt.Errorf("Kata DAN requires an IPv4 network mask")
	}
	if len(resource.GuestHardwareAddr()) == 0 {
		return fmt.Errorf("Kata DAN requires a guest MAC address")
	}
	return nil
}

func deleteKataTap(name string) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}
	if err := netlink.LinkDel(link); err != nil {
		logrus.Warnf("kata: delete TAP %s: %v", name, err)
	}
}

func writeKataDANConfig(
	path string,
	tapName string,
	resource *networkmanager.NetResource,
) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create Kata DAN config directory: %w", err)
	}
	ones, _ := resource.Mask.Size()
	mtu := resource.Interface.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	config := kataDANConfig{
		NetNS: nil,
		Devices: []kataDANDevice{{
			Name:     "eth0",
			GuestMAC: resource.GuestHardwareAddr().String(),
			Device: kataDANDeviceSpec{
				Type:      "host-tap",
				TapName:   tapName,
				QueueNum:  kataNetworkQueuePairs,
				QueueSize: kataNetworkQueueSize,
			},
			NetworkInfo: kataDANNetworkInfo{
				Interface: kataDANInterface{
					IPAddresses: []string{fmt.Sprintf("%s/%d", resource.Ip.String(), ones)},
					MTU:         mtu,
					Type:        "tuntap",
				},
				Routes: []kataDANRoute{{
					Destination: "0.0.0.0/0",
					Gateway:     resource.Gateway.String(),
				}},
				Neighbors: []kataDANNeighbor{},
			},
		}},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	temporaryPath := path + ".tmp"
	if err := os.WriteFile(temporaryPath, data, 0644); err != nil {
		return fmt.Errorf("write Kata DAN config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish Kata DAN config: %w", err)
	}
	return nil
}

func writeKataNetworkState(bundlePath string, state kataNetworkState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(bundlePath, kataNetworkStateFile), data, 0600)
}

func cleanupKataNetwork(bundlePath string) {
	statePath := filepath.Join(bundlePath, kataNetworkStateFile)
	data, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logrus.Warnf("kata: read network state %s: %v", statePath, err)
		}
		return
	}
	var state kataNetworkState
	if err := json.Unmarshal(data, &state); err != nil {
		logrus.Warnf("kata: decode network state %s: %v", statePath, err)
		return
	}
	if state.PeerVethName != "" {
		if peer, err := netlink.LinkByName(state.PeerVethName); err == nil {
			_ = netlink.LinkSetUp(peer)
		}
		deleteKataTap(state.TapName)
	}
	if state.DANConfig != "" {
		if err := os.Remove(state.DANConfig); err != nil && !os.IsNotExist(err) {
			logrus.Warnf("kata: remove DAN config %s: %v", state.DANConfig, err)
		}
	}
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		logrus.Warnf("kata: remove network state %s: %v", statePath, err)
	}
}

func removeKataNetworkNamespace(bundlePath string) error {
	configPath := filepath.Join(bundlePath, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var spec Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return err
	}
	if spec.Linux == nil {
		return nil
	}
	namespaces := make([]LinuxNamespace, 0, len(spec.Linux.Namespaces))
	for _, namespace := range spec.Linux.Namespaces {
		if namespace.Type != NetworkNamespace {
			namespaces = append(namespaces, namespace)
		}
	}
	spec.Linux.Namespaces = namespaces
	return writeKataSpec(configPath, &spec)
}
