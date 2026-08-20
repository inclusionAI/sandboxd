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
	"fmt"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	// InterfaceLifecycleEphemeral identifies a link which must be destroyed on
	// release instead of being returned to InterfaceManager's idle cache.
	InterfaceLifecycleEphemeral = "ephemeral"

	ephemeralNetNSRoot   = "/var/run/netns"
	ephemeralNetNSPrefix = "runc-"
	ephemeralPeerName    = "eth0"
)

func ephemeralNetNSName(sandboxID string) string {
	return ephemeralNetNSPrefix + sandboxID
}

func ephemeralNetNSPath(sandboxID string) string {
	return filepath.Join(ephemeralNetNSRoot, ephemeralNetNSName(sandboxID))
}

func sandboxIDFromEphemeralNetNSPath(path string) (string, error) {
	if err := ValidateEphemeralNetNSPath(path); err != nil {
		return "", err
	}
	return strings.TrimPrefix(filepath.Base(filepath.Clean(path)), ephemeralNetNSPrefix), nil
}

// ValidateEphemeralNetNSPath prevents a persisted resource from turning
// namespace cleanup into an arbitrary path operation.
func ValidateEphemeralNetNSPath(path string) error {
	clean := filepath.Clean(path)
	if filepath.Dir(clean) != ephemeralNetNSRoot {
		return fmt.Errorf("network namespace %q is outside %s", path, ephemeralNetNSRoot)
	}
	name := filepath.Base(clean)
	if !strings.HasPrefix(name, ephemeralNetNSPrefix) {
		return fmt.Errorf("network namespace %q is not owned by runc", path)
	}
	if !config.IsValidSandboxID(strings.TrimPrefix(name, ephemeralNetNSPrefix)) {
		return fmt.Errorf("network namespace %q has an invalid sandbox ID", path)
	}
	return nil
}

// setupEphemeralNetwork creates the namespace after the veth pair has been
// created on the host, moves the peer in once, and configures it for runc.
// Teardown deletes the pair; the peer is intentionally never moved back.
func setupEphemeralNetwork(sandboxID string, resource *NetResource) (_ string, retErr error) {
	if !config.IsValidSandboxID(sandboxID) {
		return "", fmt.Errorf("invalid sandbox ID %q", sandboxID)
	}
	if resource == nil || resource.Interface == nil || resource.Interface.Name == "" {
		return "", fmt.Errorf("ephemeral network interface is missing")
	}
	if resource.Ip.To4() == nil || resource.Gateway.To4() == nil {
		return "", fmt.Errorf("ephemeral network requires IPv4 address and gateway")
	}
	ones, bits := resource.Mask.Size()
	if bits != 32 || ones < 0 {
		return "", fmt.Errorf("ephemeral network requires an IPv4 mask")
	}

	name := ephemeralNetNSName(sandboxID)
	path := ephemeralNetNSPath(sandboxID)
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("network namespace %s already exists", path)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect network namespace %s: %w", path, err)
	}

	peer, err := netlink.LinkByName(resource.Interface.Name)
	if err != nil {
		return "", fmt.Errorf("find ephemeral peer veth %s: %w", resource.Interface.Name, err)
	}
	peerIndex := peer.Attrs().Index

	namespace, err := createNamedNetNS(name)
	if err != nil {
		return "", err
	}
	defer namespace.Close()
	keepNamespace := false
	defer func() {
		if !keepNamespace {
			retErr = errors.Join(retErr, deleteEphemeralNetNS(path))
		}
	}()

	if err := netlink.LinkSetDown(peer); err != nil {
		return "", fmt.Errorf("set ephemeral peer veth down: %w", err)
	}
	if err := netlink.LinkSetNsFd(peer, int(namespace)); err != nil {
		return "", fmt.Errorf("move ephemeral peer veth into netns: %w", err)
	}

	handle, err := netlink.NewHandleAt(namespace)
	if err != nil {
		return "", fmt.Errorf("open ephemeral netns netlink handle: %w", err)
	}
	defer handle.Close()
	peer, err = handle.LinkByIndex(peerIndex)
	if err != nil {
		return "", fmt.Errorf("find ephemeral peer veth in netns: %w", err)
	}
	if peer.Attrs().Name != ephemeralPeerName {
		if err := handle.LinkSetName(peer, ephemeralPeerName); err != nil {
			return "", fmt.Errorf("rename ephemeral peer veth: %w", err)
		}
		peer, err = handle.LinkByName(ephemeralPeerName)
		if err != nil {
			return "", fmt.Errorf("find renamed ephemeral peer veth: %w", err)
		}
	}
	address := &netlink.Addr{IPNet: &net.IPNet{IP: resource.Ip, Mask: resource.Mask}}
	if err := handle.AddrReplace(peer, address); err != nil {
		return "", fmt.Errorf("configure ephemeral sandbox address: %w", err)
	}
	if err := handle.LinkSetUp(peer); err != nil {
		return "", fmt.Errorf("set ephemeral sandbox interface up: %w", err)
	}
	loopback, err := handle.LinkByName("lo")
	if err != nil {
		return "", fmt.Errorf("find ephemeral loopback: %w", err)
	}
	if err := handle.LinkSetUp(loopback); err != nil {
		return "", fmt.Errorf("set ephemeral loopback up: %w", err)
	}
	if err := handle.RouteReplace(&netlink.Route{
		LinkIndex: peer.Attrs().Index,
		Gw:        resource.Gateway,
	}); err != nil {
		return "", fmt.Errorf("configure ephemeral default route: %w", err)
	}

	keepNamespace = true
	return path, nil
}

func createNamedNetNS(name string) (netns.NsHandle, error) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		return netns.None(), fmt.Errorf("open current network namespace: %w", err)
	}
	defer original.Close()
	namespace, err := netns.NewNamed(name)
	if err != nil {
		return netns.None(), fmt.Errorf("create named network namespace %s: %w", name, err)
	}
	if err := netns.Set(original); err != nil {
		_ = namespace.Close()
		_ = netns.DeleteNamed(name)
		return netns.None(), fmt.Errorf("restore current network namespace: %w", err)
	}
	return namespace, nil
}

func deleteEphemeralNetNS(path string) error {
	if path == "" {
		return nil
	}
	if err := ValidateEphemeralNetNSPath(path); err != nil {
		return err
	}
	name := filepath.Base(filepath.Clean(path))
	if err := netns.DeleteNamed(name); err != nil &&
		!os.IsNotExist(err) &&
		!strings.Contains(strings.ToLower(err.Error()), "no such") {
		return fmt.Errorf("delete network namespace %s: %w", path, err)
	}
	return nil
}
