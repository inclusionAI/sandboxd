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
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager/networkacl"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func TestBuildImageProcessSpec(t *testing.T) {
	tests := []struct {
		name   string
		config *imageconfig.Process
		want   *imageProcessSpec
	}{
		{
			name: "entrypoint and cmd",
			config: &imageconfig.Process{
				Entrypoint: []string{"/entrypoint", "--flag"},
				Cmd:        []string{"serve", "8080"},
				Cwd:        "/app",
				User:       "1000:1000",
			},
			want: &imageProcessSpec{
				Version: 1,
				Args:    []string{"/entrypoint", "--flag", "serve", "8080"},
				Cwd:     "/app",
				User:    "1000:1000",
			},
		},
		{
			name:   "cmd only",
			config: &imageconfig.Process{Cmd: []string{"sleep", "1"}},
			want:   &imageProcessSpec{Version: 1, Args: []string{"sleep", "1"}, Cwd: "/"},
		},
		{
			name:   "no startup command",
			config: &imageconfig.Process{},
			want:   &imageProcessSpec{Version: 1, Args: []string{}, Cwd: "/"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := buildImageProcessSpec(test.config)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("buildImageProcessSpec() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestBuildImageProcessSpecRejectsInvalidConfig(t *testing.T) {
	for _, config := range []*imageconfig.Process{
		nil,
		{Entrypoint: []string{""}},
		{Cmd: []string{"echo", "bad\x00arg"}},
		{Cmd: []string{"echo"}, Cwd: "relative"},
		{Cmd: []string{"echo"}, User: "bad\x00user"},
	} {
		if _, err := buildImageProcessSpec(config); err == nil {
			t.Fatalf("buildImageProcessSpec(%#v) error = nil", config)
		}
	}
}

func TestPrepareSandboxFilesInjectsImageProcessConfig(t *testing.T) {
	service := &sandboxService{config: config.Config{RootDir: t.TempDir()}}
	target := "/run/yuanrong/image-process.json"
	want := &imageProcessSpec{
		Version: 1,
		Args:    []string{"/entrypoint", "serve"},
		Cwd:     "/app",
		User:    "1000:1000",
	}
	prepared, err := service.prepareSandboxFiles(
		"sbox-test",
		svc.SandboxDefaults{
			Hostname:          svc.DefaultSandboxHostname,
			MountDestinations: defaultSandboxFileDestinations,
		},
		nil,
		false,
		nil,
		want,
		target,
		sandboxHostsPolicy{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Rollback()
	if len(prepared.Mounts()) != 1 {
		t.Fatalf("mounts = %+v", prepared.Mounts())
	}
	mount := prepared.Mounts()[0]
	if mount.GetTarget() != target ||
		!reflect.DeepEqual(mount.GetOptions(), []string{"bind", "ro"}) {
		t.Fatalf("image process mount = %+v", mount)
	}
	data, err := os.ReadFile(mount.GetHostPath())
	if err != nil {
		t.Fatal(err)
	}
	got := &imageProcessSpec{}
	if err := json.Unmarshal(data, got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("image process file = %#v, want %#v", got, want)
	}
}

func TestPrepareSandboxFilesRejectsImageProcessMountConflict(t *testing.T) {
	service := &sandboxService{config: config.Config{RootDir: t.TempDir()}}
	configTarget := "/run/yuanrong/image-process.json"
	for _, target := range []string{"/", "/run", "/run/yuanrong", configTarget} {
		_, err := service.prepareSandboxFiles(
			"sbox-test",
			svc.SandboxDefaults{Hostname: svc.DefaultSandboxHostname},
			nil,
			false,
			[]*runtime.Mount{{Target: target}},
			&imageProcessSpec{Version: 1, Args: []string{}, Cwd: "/"},
			configTarget,
			sandboxHostsPolicy{},
		)
		if err == nil || !strings.Contains(err.Error(), "managed image process config") {
			t.Fatalf("mount target %q error = %v", target, err)
		}
	}
}

func TestValidateImageProcessMounts(t *testing.T) {
	configTarget := "/run/yuanrong/image-process.json"
	for _, target := range []string{"/", "/run", "/run/yuanrong", configTarget} {
		err := validateImageProcessMounts([]*runtime.Mount{{Target: target}}, configTarget)
		if err == nil {
			t.Fatalf("mount target %q did not conflict with image process config", target)
		}
	}
	if err := validateImageProcessMounts([]*runtime.Mount{{Target: "/workspace"}}, configTarget); err != nil {
		t.Fatalf("unrelated mount rejected: %v", err)
	}
}

func TestValidateImageProcessTarget(t *testing.T) {
	for _, target := range []string{"relative.json", "/", "/run/../tmp/config.json", "/run/config.json/"} {
		if err := validateImageProcessTarget(target); err == nil {
			t.Fatalf("target %q accepted", target)
		}
	}
	if err := validateImageProcessTarget("/run/yuanrong/image-process.json"); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
}

func TestPrepareSandboxFiles(t *testing.T) {
	root := t.TempDir()
	resolver := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolver, []byte("nameserver 1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	service := &sandboxService{config: config.Config{
		RootDir: root,
		PluginConfig: config.PluginConfig{RuntimeConfig: config.RuntimeConfig{
			ResolvConfPath: resolver,
		}},
	}}
	prepared, err := service.prepareSandboxFiles(
		"sbox-test",
		svc.SandboxDefaults{Hostname: "configured-host"},
		net.ParseIP("10.88.0.2"),
		false,
		nil,
		nil,
		"",
		sandboxHostsPolicy{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Mounts()) != 3 {
		t.Fatalf("mounts = %+v", prepared.Mounts())
	}
	hostname, err := os.ReadFile(filepath.Join(prepared.root, "hostname"))
	if err != nil {
		t.Fatal(err)
	}
	if string(hostname) != "configured-host\n" {
		t.Fatalf("hostname = %q", hostname)
	}
	hosts, err := os.ReadFile(filepath.Join(prepared.root, "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	wantHosts := "127.0.0.1 localhost\n" +
		"::1 localhost ip6-localhost ip6-loopback\n" +
		"10.88.0.2 configured-host\n"
	if string(hosts) != wantHosts {
		t.Fatalf("hosts = %q, want %q", hosts, wantHosts)
	}
}

func TestPrepareSandboxFilesHonorsParentMount(t *testing.T) {
	service := &sandboxService{config: config.Config{RootDir: t.TempDir()}}
	explicit := &runtime.Mount{
		Target: "/etc",
		Source: &runtime.Mount_HostPath{HostPath: "/custom/etc"},
	}
	prepared, err := service.prepareSandboxFiles(
		"sbox-test",
		svc.SandboxDefaults{Hostname: svc.DefaultSandboxHostname},
		nil,
		false,
		[]*runtime.Mount{explicit},
		nil,
		"",
		sandboxHostsPolicy{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Mounts()) != 1 || prepared.Mounts()[0] != explicit {
		t.Fatalf("explicit mount changed: %+v", prepared.Mounts())
	}
}

func TestPrepareSandboxFilesHonorsBaseResolverMount(t *testing.T) {
	service := &sandboxService{config: config.Config{RootDir: t.TempDir()}}
	prepared, err := service.prepareSandboxFiles(
		"sbox-test",
		svc.SandboxDefaults{
			Hostname:          svc.DefaultSandboxHostname,
			MountDestinations: []string{"/etc/resolv.conf"},
		},
		net.ParseIP("10.88.0.2"),
		false,
		nil,
		nil,
		"",
		sandboxHostsPolicy{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Mounts()) != 2 {
		t.Fatalf("mounts = %+v", prepared.Mounts())
	}
}

func TestPrepareSandboxFilesUsesManagedResolverForNetworkACL(t *testing.T) {
	root := t.TempDir()
	resolver := filepath.Join(t.TempDir(), "resolv.conf")
	content := "nameserver 1.1.1.1\nsearch svc.example\noptions ndots:2 timeout:1\n"
	if err := os.WriteFile(resolver, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	service := &sandboxService{
		config: config.Config{
			RootDir: root,
			PluginConfig: config.PluginConfig{RuntimeConfig: config.RuntimeConfig{
				ResolvConfPath: resolver,
			}},
		},
		aclMgr:       &networkacl.Manager{},
		interfaceMgr: &networkmanager.InterfaceManager{BridgeIp: net.ParseIP("10.88.0.1")},
	}
	prepared, err := service.prepareSandboxFiles(
		"sbox-test",
		svc.SandboxDefaults{
			Hostname:          svc.DefaultSandboxHostname,
			MountDestinations: []string{"/etc/resolv.conf"},
		},
		net.ParseIP("10.88.0.2"),
		true,
		nil,
		nil,
		"",
		sandboxHostsPolicy{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Rollback()
	managed, err := os.ReadFile(filepath.Join(prepared.root, "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := "nameserver 10.88.0.1\nsearch svc.example\noptions ndots:2 timeout:1\n"
	if string(managed) != want {
		t.Fatalf("managed resolver = %q, want %q", managed, want)
	}
	if len(prepared.Mounts()) != 3 || prepared.Mounts()[2].GetTarget() != "/etc/resolv.conf" {
		t.Fatalf("managed resolver mount missing: %+v", prepared.Mounts())
	}
}

func TestPrepareSandboxFilesSelectsResolverByDNSMode(t *testing.T) {
	root := t.TempDir()
	nodeResolver := filepath.Join(root, "node-resolv.conf")
	directResolver := filepath.Join(root, "direct-resolv.conf")
	missingResolver := filepath.Join(root, "missing-resolv.conf")
	for path, content := range map[string]string{
		nodeResolver:   "nameserver 127.0.0.11\nsearch node.example\noptions ndots:2\n",
		directResolver: "nameserver 192.0.2.53\nsearch direct.example\noptions ndots:5\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	wantManaged := "nameserver 10.88.0.1\nsearch node.example\noptions ndots:2\n"
	for _, test := range []struct {
		name         string
		managedDNS   bool
		nodeSource   string
		directSource string
		wantSource   string
		wantFile     string
		wantError    string
	}{
		{name: "direct override", nodeSource: nodeResolver, directSource: directResolver, wantSource: directResolver},
		{name: "direct inherits node resolver", nodeSource: nodeResolver, wantSource: nodeResolver},
		{name: "direct inherits system resolver", wantSource: "/etc/resolv.conf"},
		{name: "direct ignores unused node source", nodeSource: missingResolver, directSource: directResolver, wantSource: directResolver},
		{name: "managed ignores direct override", managedDNS: true, nodeSource: nodeResolver, directSource: directResolver, wantFile: wantManaged},
		{name: "managed without override", managedDNS: true, nodeSource: nodeResolver, wantFile: wantManaged},
		{name: "managed ignores missing direct source", managedDNS: true, nodeSource: nodeResolver, directSource: missingResolver, wantFile: wantManaged},
		{name: "managed ignores nonregular direct source", managedDNS: true, nodeSource: nodeResolver, directSource: root, wantFile: wantManaged},
		{name: "direct missing source fails without fallback", nodeSource: nodeResolver, directSource: missingResolver, wantError: "inspect resolver source " + missingResolver},
		{name: "direct nonregular source fails without fallback", nodeSource: nodeResolver, directSource: root, wantError: "is not a regular file"},
		{name: "direct missing inherited source fails", nodeSource: missingResolver, wantError: "inspect resolver source " + missingResolver},
		{name: "managed missing node source fails", managedDNS: true, nodeSource: missingResolver, directSource: directResolver, wantError: "inspect resolver source " + missingResolver},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &sandboxService{config: config.Config{
				RootDir: t.TempDir(),
				PluginConfig: config.PluginConfig{RuntimeConfig: config.RuntimeConfig{
					ResolvConfPath:       test.nodeSource,
					DirectResolvConfPath: test.directSource,
				}},
			}}
			if test.managedDNS {
				service.interfaceMgr = &networkmanager.InterfaceManager{BridgeIp: net.ParseIP("10.88.0.1")}
			}
			prepared, err := service.prepareSandboxFiles(
				"sbox-test",
				svc.SandboxDefaults{Hostname: svc.DefaultSandboxHostname},
				net.ParseIP("10.88.0.2"),
				test.managedDNS,
				nil,
				nil,
				"",
				sandboxHostsPolicy{},
			)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				if _, err := os.Stat(filepath.Join(service.config.RootDir, "containers", "sbox-test", "sandbox-files")); !os.IsNotExist(err) {
					t.Fatalf("failed preparation left sandbox files: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Rollback()
			var source string
			for _, mount := range prepared.Mounts() {
				if mount.GetTarget() == "/etc/resolv.conf" {
					if source != "" || !reflect.DeepEqual(mount.GetOptions(), []string{"bind", "ro"}) {
						t.Fatalf("unexpected resolver mount: %+v", mount)
					}
					source = mount.GetHostPath()
				}
			}
			if source == "" {
				t.Fatal("resolver mount missing")
			}
			if test.wantSource != "" && source != test.wantSource {
				t.Fatalf("resolver source = %q, want %q", source, test.wantSource)
			}
			if test.wantFile != "" {
				content, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				if string(content) != test.wantFile {
					t.Fatalf("managed resolver = %q, want %q", content, test.wantFile)
				}
			}
		})
	}
}

func TestValidateManagedResolverMounts(t *testing.T) {
	for _, target := range []string{"/", "/etc", "/etc/resolv.conf"} {
		err := validateManagedResolverMounts([]*runtime.Mount{{Target: target}})
		if err == nil {
			t.Fatalf("mount target %q did not conflict with managed DNS", target)
		}
	}
	if err := validateManagedResolverMounts([]*runtime.Mount{{Target: "/etc/hosts"}}); err != nil {
		t.Fatalf("unrelated mount rejected: %v", err)
	}
}

func TestPrepareSandboxFilesWithoutNetworkACLOnACLNode(t *testing.T) {
	for _, test := range []struct {
		name         string
		baseMounts   []string
		explicitPath string
		noBridge     bool
	}{
		{name: "direct resolver"},
		{name: "direct resolver without bridge", noBridge: true},
		{name: "runtime resolver", baseMounts: []string{"/etc/resolv.conf"}},
		{name: "runtime parent", baseMounts: []string{"/etc"}},
		{name: "explicit resolver", explicitPath: "/etc/resolv.conf"},
		{name: "explicit parent", explicitPath: "/etc"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			resolver := filepath.Join(root, "direct-resolv.conf")
			content := "nameserver 192.0.2.53\nsearch svc.example\noptions ndots:2 timeout:1\n"
			if err := os.WriteFile(resolver, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
			directSource := resolver
			if test.explicitPath != "" || len(test.baseMounts) > 0 {
				// An owned resolver must bypass validation of the unused default.
				directSource = filepath.Join(root, "missing-direct-resolv.conf")
			}
			service := &sandboxService{
				config: config.Config{
					RootDir: root,
					PluginConfig: config.PluginConfig{RuntimeConfig: config.RuntimeConfig{
						ResolvConfPath:       filepath.Join(root, "missing-node-resolv.conf"),
						DirectResolvConfPath: directSource,
					}},
				},
				aclMgr:       &networkacl.Manager{},
				interfaceMgr: &networkmanager.InterfaceManager{BridgeIp: net.ParseIP("10.88.0.1")},
			}
			if test.noBridge {
				service.interfaceMgr = nil
			}
			var mounts []*runtime.Mount
			if test.explicitPath != "" {
				mounts = []*runtime.Mount{{
					Target: test.explicitPath,
					Source: &runtime.Mount_HostPath{HostPath: "/custom/resolver"},
				}}
			}
			// Runc skips ACL registration even when the node has an ACL manager.
			// It must not need a managed-DNS bridge or override an owned resolver.
			prepared, err := service.prepareSandboxFiles(
				"sbox-runc",
				svc.SandboxDefaults{Hostname: svc.DefaultSandboxHostname, MountDestinations: test.baseMounts},
				net.ParseIP("10.88.0.2"),
				false,
				mounts,
				nil,
				"",
				sandboxHostsPolicy{},
			)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Rollback()
			if _, err := os.Stat(filepath.Join(prepared.root, "resolv.conf")); !os.IsNotExist(err) {
				t.Fatalf("unexpected managed resolver: %v", err)
			}
			if test.explicitPath != "" && prepared.Mounts()[0] != mounts[0] {
				t.Fatalf("explicit mount changed: %+v", prepared.Mounts())
			}
			var injected []*runtime.Mount
			for _, mount := range prepared.Mounts()[len(mounts):] {
				if mount.GetTarget() == "/etc/resolv.conf" {
					injected = append(injected, mount)
				}
			}
			if test.explicitPath != "" || len(test.baseMounts) > 0 {
				if len(injected) != 0 {
					t.Fatalf("owned resolver was overridden: %+v", injected)
				}
				return
			}
			if len(injected) != 1 || injected[0].GetHostPath() != resolver ||
				!reflect.DeepEqual(injected[0].GetOptions(), []string{"bind", "ro"}) {
				t.Fatalf("direct resolver mount = %+v", injected)
			}
			got, err := os.ReadFile(injected[0].GetHostPath())
			if err != nil || string(got) != content {
				t.Fatalf("direct resolver = %q, %v", got, err)
			}
		})
	}
}

func TestPrepareSandboxFilesRejectsInvalidHostname(t *testing.T) {
	service := &sandboxService{config: config.Config{RootDir: t.TempDir()}}
	_, err := service.prepareSandboxFiles(
		"sbox-test",
		svc.SandboxDefaults{Hostname: "bad\nhost"},
		nil,
		false,
		[]*runtime.Mount{{Target: "/etc"}},
		nil,
		"",
		sandboxHostsPolicy{},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("invalid hostname error = %v", err)
	}
}

func managedHostsTestService(t *testing.T) *sandboxService {
	t.Helper()
	resolver := filepath.Join(t.TempDir(), "resolver")
	if err := os.WriteFile(resolver, []byte("nameserver 1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return &sandboxService{config: config.Config{
		RootDir: t.TempDir(), PluginConfig: config.PluginConfig{RuntimeConfig: config.RuntimeConfig{ResolvConfPath: resolver}},
	}}
}

func TestPrepareManagedHostsLayouts(t *testing.T) {
	for _, test := range []struct {
		name, runtime string
		readonly      bool
		mount         string
		baseMount     string
		layout        svc.HostsLayout
		initial       bool
		legacy        bool
	}{
		{name: "runsc", runtime: "runsc", layout: svc.HostsLayoutPrivateRootfs, initial: true},
		{name: "firecracker unchanged", runtime: "firecracker", legacy: true},
		{name: "readonly", runtime: "runsc", readonly: true, layout: svc.HostsLayoutLegacy, legacy: true},
		{name: "explicit hosts", runtime: "runsc", mount: "/etc/hosts", layout: svc.HostsLayoutExternal},
		{name: "parent owns", runtime: "runsc", mount: "/etc", layout: svc.HostsLayoutExternal},
		{name: "base owns", runtime: "runsc", baseMount: "/etc", layout: svc.HostsLayoutExternal},
		{name: "external before readonly", runtime: "runsc", readonly: true, mount: "/etc/hosts", layout: svc.HostsLayoutExternal},
		{name: "runc unchanged", runtime: "runc", legacy: true},
		{name: "kata unchanged", runtime: "kata", legacy: true},
		{name: "pvm unchanged", runtime: "firecracker-pvm", legacy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := managedHostsTestService(t)
			defaults := svc.SandboxDefaults{Hostname: "configured-host"}
			if test.baseMount != "" {
				defaults.MountDestinations = []string{test.baseMount}
			}
			var mounts []*runtime.Mount
			if test.mount != "" {
				mounts = []*runtime.Mount{{Target: test.mount}}
			}
			prepared, err := service.prepareSandboxFiles("sandbox-test", defaults, net.ParseIP("10.88.0.2"), false, mounts, nil, "", sandboxHostsPolicy{runtime: test.runtime, rootReadonly: test.readonly})
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Rollback()
			state := prepared.ManagedHosts()
			if test.layout == "" {
				if state != nil {
					t.Fatalf("unexpected state: %+v", state)
				}
			} else if state == nil || state.Layout != test.layout || state.Runtime != test.runtime || state.RootReadonly != test.readonly {
				t.Fatalf("state: %+v", state)
			}
			if (len(prepared.InitialFiles()) == 1) != test.initial {
				t.Fatalf("initial files: %+v", prepared.InitialFiles())
			}
			if test.initial {
				file := prepared.InitialFiles()[0]
				if file.Path != "/etc/hosts" || file.Mode != 0644 || string(file.Content) != "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n10.88.0.2 configured-host\n" {
					t.Fatalf("initial file: %+v", file)
				}
			}
			platformHostMount := false
			for _, mount := range prepared.Mounts() {
				if mount.Target == "/etc/hosts" && mount.GetHostPath() != "" {
					platformHostMount = true
				}
			}
			if platformHostMount != test.legacy {
				t.Fatalf("platform hosts mount: %v", platformHostMount)
			}
			if !test.legacy {
				if _, err := os.Stat(filepath.Join(prepared.root, "hosts")); !os.IsNotExist(err) {
					t.Fatalf("unexpected hosts backing file: %v", err)
				}
			}
		})
	}
}

func TestPrepareRestoredManagedHostsDoesNotInitialize(t *testing.T) {
	checkpoint := t.TempDir()
	state := &svc.ManagedHostsState{
		Version: svc.ManagedHostsVersion, Layout: svc.HostsLayoutPrivateRootfs, Runtime: "runsc",
		Seed: &svc.RootfsSeed{File: svc.RootfsSeedName, SHA256: strings.Repeat("a", 64), AnnotationKey: svc.GVisorRootfsTarUpperAnnotation, AnnotationValue: svc.RootfsSeedName},
	}
	if err := svc.WriteManagedHostsState(checkpoint, state); err != nil {
		t.Fatal(err)
	}
	service := managedHostsTestService(t)
	// No IP is needed to restore hosts: empty/deleted state must not be seeded.
	prepared, err := service.prepareSandboxFiles("restored", svc.SandboxDefaults{}, nil, false, nil, nil, "", sandboxHostsPolicy{runtime: "runsc", checkpointDir: checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.InitialFiles()) != 0 {
		t.Fatal("restored hosts initialized")
	}
	for _, mount := range prepared.Mounts() {
		if mount.Target == "/etc/hosts" {
			t.Fatal("restored hosts remounted")
		}
	}
	if !reflect.DeepEqual(state, prepared.ManagedHosts()) {
		t.Fatalf("lost restore state: %+v", prepared.ManagedHosts())
	}
}

func TestPrepareManagedHostsRestoreRejectsLayoutConflicts(t *testing.T) {
	checkpoint := t.TempDir()
	state := &svc.ManagedHostsState{Version: svc.ManagedHostsVersion, Layout: svc.HostsLayoutPrivateRootfs, Runtime: "runsc", Seed: &svc.RootfsSeed{File: svc.RootfsSeedName, SHA256: strings.Repeat("a", 64), AnnotationKey: svc.GVisorRootfsTarUpperAnnotation, AnnotationValue: svc.RootfsSeedName}}
	if err := svc.WriteManagedHostsState(checkpoint, state); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		runtime  string
		readonly bool
		mount    string
	}{
		{"runsc", true, ""}, {"runsc", false, "/etc"}, {"runsc", false, "/etc/hosts"},
	} {
		service := managedHostsTestService(t)
		var mounts []*runtime.Mount
		if test.mount != "" {
			mounts = []*runtime.Mount{{Target: test.mount}}
		}
		_, err := service.prepareSandboxFiles("restored", svc.SandboxDefaults{}, nil, false, mounts, nil, "", sandboxHostsPolicy{runtime: test.runtime, rootReadonly: test.readonly, checkpointDir: checkpoint})
		if err == nil {
			t.Fatalf("incompatible layout accepted: %+v", test)
		}
	}
}

func TestPrepareOldCheckpointKeepsLegacyMountAndOwnership(t *testing.T) {
	for _, owned := range []bool{false, true} {
		service := managedHostsTestService(t)
		defaults := svc.SandboxDefaults{}
		if owned {
			defaults.MountDestinations = []string{"/etc/hosts"}
		}
		prepared, err := service.prepareSandboxFiles("old-restored", defaults, net.ParseIP("10.88.0.3"), false, nil, nil, "", sandboxHostsPolicy{runtime: "runsc", checkpointDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if prepared.ManagedHosts() != nil || len(prepared.InitialFiles()) != 0 {
			t.Fatal("old snapshot converted to new layout")
		}
		count := 0
		for _, mount := range prepared.Mounts() {
			if mount.Target == "/etc/hosts" {
				count++
				if !reflect.DeepEqual(mount.Options, []string{"bind", "ro"}) {
					t.Fatal("old hosts became writable")
				}
			}
		}
		if (count == 1) == owned {
			t.Fatalf("old ownership lost: owned=%v mounts=%+v", owned, prepared.Mounts())
		}
	}
}

func TestOtherRuntimesIgnoreManagedHostsSidecars(t *testing.T) {
	for _, runtimeName := range []string{"firecracker", "firecracker-pvm", "runc", "kata"} {
		t.Run(runtimeName, func(t *testing.T) {
			checkpoint := t.TempDir()
			if err := os.WriteFile(filepath.Join(checkpoint, svc.ManagedHostsStateFile), []byte("not a managed hosts artifact"), 0600); err != nil {
				t.Fatal(err)
			}
			service := managedHostsTestService(t)
			prepared, err := service.prepareSandboxFiles("unchanged", svc.SandboxDefaults{}, net.ParseIP("10.88.0.3"), false, nil, nil, "", sandboxHostsPolicy{runtime: runtimeName, checkpointDir: checkpoint})
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Rollback()
			if prepared.ManagedHosts() != nil || len(prepared.InitialFiles()) != 0 {
				t.Fatal("non-runsc runtime opted into managed hosts")
			}
			hosts := 0
			for _, mount := range prepared.Mounts() {
				if mount.Target == "/etc/hosts" {
					hosts++
					if !reflect.DeepEqual(mount.Options, []string{"bind", "ro"}) {
						t.Fatal("existing hosts mount changed")
					}
				}
			}
			if hosts != 1 {
				t.Fatalf("existing hosts mount lost: %d", hosts)
			}
		})
	}
}
