// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/util"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

const sandboxHostnameLimit = 64

var defaultSandboxFileDestinations = []string{
	"/etc/hosts",
	"/etc/hostname",
	"/etc/resolv.conf",
}

type preparedSandboxFiles struct {
	root   string
	mounts []*runtime.Mount
}

func (p *preparedSandboxFiles) Mounts() []*runtime.Mount {
	if p == nil {
		return nil
	}
	return p.mounts
}

func (p *preparedSandboxFiles) Rollback() {
	if p == nil || p.root == "" {
		return
	}
	_ = os.RemoveAll(p.root)
}

func (h *sandboxService) prepareSandboxFiles(
	sandboxID string,
	defaults svc.SandboxDefaults,
	networkIP net.IP,
	mounts []*runtime.Mount,
) (*preparedSandboxFiles, error) {
	hostname := defaults.Hostname
	if hostname == "" {
		hostname = svc.DefaultSandboxHostname
	}
	if err := validateSandboxHostname(hostname); err != nil {
		return nil, err
	}
	root, err := util.JoinWithinRoot(h.config.RootDir, "containers", sandboxID, "sandbox-files")
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox file directory: %w", err)
	}
	prepared := &preparedSandboxFiles{
		root:   root,
		mounts: append([]*runtime.Mount(nil), mounts...),
	}
	owners := append([]string(nil), defaults.MountDestinations...)
	for _, mount := range mounts {
		owners = append(owners, mount.GetTarget())
	}
	needsHosts := !mountDestinationsOwn(owners, "/etc/hosts")
	needsHostname := !mountDestinationsOwn(owners, "/etc/hostname")
	needsResolver := h.aclMgr != nil || !mountDestinationsOwn(owners, "/etc/resolv.conf")
	if !needsHosts && !needsHostname && !needsResolver {
		return prepared, nil
	}
	if err := os.RemoveAll(root); err != nil {
		return nil, fmt.Errorf("remove stale sandbox files: %w", err)
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, fmt.Errorf("create sandbox file directory: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			prepared.Rollback()
		}
	}()
	if needsHosts {
		if networkIP == nil || net.ParseIP(networkIP.String()) == nil {
			return nil, fmt.Errorf("sandbox network IP is required for /etc/hosts")
		}
		content := fmt.Sprintf(
			"127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n%s %s\n",
			networkIP.String(), hostname,
		)
		source := filepath.Join(root, "hosts")
		if err := atomicWriteSandboxFile(source, []byte(content)); err != nil {
			return nil, fmt.Errorf("write sandbox hosts: %w", err)
		}
		prepared.mounts = append(prepared.mounts, sandboxFileMount("/etc/hosts", source))
	}
	if needsHostname {
		source := filepath.Join(root, "hostname")
		if err := atomicWriteSandboxFile(source, []byte(hostname+"\n")); err != nil {
			return nil, fmt.Errorf("write sandbox hostname: %w", err)
		}
		prepared.mounts = append(prepared.mounts, sandboxFileMount("/etc/hostname", source))
	}
	if needsResolver {
		resolver := h.config.ResolvConfPath
		if resolver == "" {
			resolver = "/etc/resolv.conf"
		}
		info, err := os.Stat(resolver)
		if err != nil {
			return nil, fmt.Errorf("inspect resolver source %s: %w", resolver, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("resolver source %s is not a regular file", resolver)
		}
		if h.aclMgr == nil {
			prepared.mounts = append(prepared.mounts, sandboxFileMount("/etc/resolv.conf", resolver))
		} else {
			if h.interfaceMgr == nil || h.interfaceMgr.BridgeIp.To4() == nil {
				return nil, fmt.Errorf("sandbox bridge IPv4 address is required for managed DNS")
			}
			content, err := managedResolverContent(h.interfaceMgr.BridgeIp, resolver)
			if err != nil {
				return nil, err
			}
			source := filepath.Join(root, "resolv.conf")
			if err := atomicWriteSandboxFile(source, content); err != nil {
				return nil, fmt.Errorf("write managed resolver: %w", err)
			}
			prepared.mounts = append(prepared.mounts, sandboxFileMount("/etc/resolv.conf", source))
		}
	}
	failed = false
	return prepared, nil
}

func validateManagedResolverMounts(mounts []*runtime.Mount) error {
	for _, mount := range mounts {
		if mount == nil {
			continue
		}
		if mountDestinationsOwn([]string{mount.GetTarget()}, "/etc/resolv.conf") {
			return fmt.Errorf("mount target %q conflicts with managed DNS", mount.GetTarget())
		}
	}
	return nil
}

func managedResolverContent(gateway net.IP, resolverPath string) ([]byte, error) {
	data, err := os.ReadFile(resolverPath)
	if err != nil {
		return nil, fmt.Errorf("read resolver source %s: %w", resolverPath, err)
	}
	lines := []string{"nameserver " + gateway.String()}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "search", "domain", "options":
			lines = append(lines, strings.Join(fields, " "))
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func validateSandboxHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("sandbox hostname is empty")
	}
	if len(hostname) > sandboxHostnameLimit {
		return fmt.Errorf("sandbox hostname %q exceeds %d bytes", hostname, sandboxHostnameLimit)
	}
	for _, value := range hostname {
		if unicode.IsSpace(value) || unicode.IsControl(value) || value == '/' || value == '\\' {
			return fmt.Errorf("sandbox hostname %q contains an invalid character", hostname)
		}
	}
	return nil
}

func mountDestinationsOwn(destinations []string, target string) bool {
	target = path.Clean(target)
	for _, value := range destinations {
		destination := path.Clean(value)
		if destination == target || destination == "/" ||
			strings.HasPrefix(target, destination+"/") {
			return true
		}
	}
	return false
}

func sandboxFileMount(destination, source string) *runtime.Mount {
	return &runtime.Mount{
		Target:  destination,
		Type:    "bind",
		Options: []string{"bind", "ro"},
		Source:  &runtime.Mount_HostPath{HostPath: source},
	}
}

func atomicWriteSandboxFile(target string, content []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(target), ".sandbox-file-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0644); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, target)
}
