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

// stubWritableHostsMount replaces the privileged tmpfs mount with a no-op so
// unit tests exercise the writable-hosts plumbing without host mounts. Tests
// that verify real capacity live in the privileged runtime E2E.
func stubWritableHostsMount(t *testing.T) {
	t.Helper()
	previous := mountWritableHostsTmpfs
	mountWritableHostsTmpfs = func(string) error { return nil }
	t.Cleanup(func() { mountWritableHostsTmpfs = previous })
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
		false,
		nil,
		want,
		target,
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
			false,
			[]*runtime.Mount{{Target: target}},
			&imageProcessSpec{Version: 1, Args: []string{}, Cwd: "/"},
			configTarget,
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
		false,
		nil,
		nil,
		"",
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
		false,
		[]*runtime.Mount{explicit},
		nil,
		"",
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
		false,
		nil,
		nil,
		"",
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
		false,
		nil,
		nil,
		"",
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
		{name: "node resolver"},
		{name: "node resolver without bridge", noBridge: true},
		{name: "runtime resolver", baseMounts: []string{"/etc/resolv.conf"}},
		{name: "explicit resolver", explicitPath: "/etc/resolv.conf"},
		{name: "explicit parent", explicitPath: "/etc"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			resolver := filepath.Join(root, "node-resolv.conf")
			content := "nameserver 192.0.2.53\nsearch svc.example\noptions ndots:2 timeout:1\n"
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
				false,
				mounts,
				nil,
				"",
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
				t.Fatalf("node resolver mount = %+v", injected)
			}
			got, err := os.ReadFile(injected[0].GetHostPath())
			if err != nil || string(got) != content {
				t.Fatalf("node resolver = %q, %v", got, err)
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
		false,
		[]*runtime.Mount{{Target: "/etc"}},
		nil,
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("invalid hostname error = %v", err)
	}
}

func TestPrepareSandboxFilesWritableHosts(t *testing.T) {
	stubWritableHostsMount(t)
	resolver := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolver, []byte("nameserver 1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	service := &sandboxService{config: config.Config{
		RootDir: t.TempDir(),
		PluginConfig: config.PluginConfig{RuntimeConfig: config.RuntimeConfig{
			ResolvConfPath: resolver,
		}},
	}}
	prepared, err := service.prepareSandboxFiles(
		"sbox-writable",
		svc.SandboxDefaults{
			Hostname: svc.DefaultSandboxHostname,
		},
		net.ParseIP("10.88.0.2"),
		false,
		true,
		nil,
		nil,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Rollback()
	var hosts, hostname, resolverMount *runtime.Mount
	for _, mount := range prepared.Mounts() {
		switch mount.GetTarget() {
		case "/etc/hosts":
			hosts = mount
		case "/etc/hostname":
			hostname = mount
		case "/etc/resolv.conf":
			resolverMount = mount
		}
	}
	if hosts == nil || hostname == nil || resolverMount == nil {
		t.Fatalf("missing managed mounts: %+v", prepared.Mounts())
	}
	if !reflect.DeepEqual(hosts.GetOptions(), []string{"bind"}) {
		t.Fatalf("writable hosts mount options = %v", hosts.GetOptions())
	}
	if !reflect.DeepEqual(hostname.GetOptions(), []string{"bind", "ro"}) ||
		!reflect.DeepEqual(resolverMount.GetOptions(), []string{"bind", "ro"}) {
		t.Fatalf("hostname/resolver lost read-only protection: %+v %+v", hostname, resolverMount)
	}
	hostsContent, err := os.ReadFile(hosts.GetHostPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hostsContent), "127.0.0.1 localhost") ||
		!strings.Contains(string(hostsContent), "10.88.0.2 "+svc.DefaultSandboxHostname) {
		t.Fatalf("hosts initial content = %q", hostsContent)
	}
	// P1: the writable hosts file lives on the size-bounded private tmpfs
	// directory so root-overlay quota bypass is not possible.
	if prepared.writableHostsDir == "" {
		t.Fatalf("writable hosts directory was not prepared")
	}
	if want := filepath.Join(prepared.root, "hosts-rw"); prepared.writableHostsDir != want {
		t.Fatalf("writable hosts dir = %q, want %q", prepared.writableHostsDir, want)
	}
	if hosts.GetHostPath() != filepath.Join(prepared.writableHostsDir, "hosts") {
		t.Fatalf("hosts source %q is not inside the bounded directory", hosts.GetHostPath())
	}
	if !strings.HasPrefix(hosts.GetHostPath(), prepared.writableHostsDir) {
		t.Fatalf("hosts source escaped the bounded directory")
	}
}

func TestPrepareSandboxFilesWritableHostsIsolatedPerSandbox(t *testing.T) {
	stubWritableHostsMount(t)
	service := &sandboxService{config: config.Config{RootDir: t.TempDir()}}
	sources := make([]string, 0, 2)
	for _, id := range []string{"sbox-a", "sbox-b"} {
		prepared, err := service.prepareSandboxFiles(
			id,
			svc.SandboxDefaults{
				Hostname: svc.DefaultSandboxHostname,
			},
			net.ParseIP("10.88.0.2"),
			false,
			true,
			nil,
			nil,
			"",
		)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Rollback()
		for _, mount := range prepared.Mounts() {
			if mount.GetTarget() == "/etc/hosts" {
				sources = append(sources, mount.GetHostPath())
			}
		}
	}
	if len(sources) != 2 {
		t.Fatalf("expected one hosts mount per sandbox, got %v", sources)
	}
	if sources[0] == sources[1] {
		t.Fatalf("sandboxes share one hosts source: %v", sources)
	}
}

func TestPrepareSandboxFilesHonorsExplicitHostsMountOverWritablePolicy(t *testing.T) {
	stubWritableHostsMount(t)
	service := &sandboxService{config: config.Config{RootDir: t.TempDir()}}
	explicit := &runtime.Mount{
		Target:  "/etc/hosts",
		Type:    "bind",
		Options: []string{"bind", "ro"},
		Source:  &runtime.Mount_HostPath{HostPath: "/custom/hosts"},
	}
	prepared, err := service.prepareSandboxFiles(
		"sbox-test",
		svc.SandboxDefaults{
			Hostname: svc.DefaultSandboxHostname,
		},
		net.ParseIP("10.88.0.2"),
		false,
		true,
		[]*runtime.Mount{explicit},
		nil,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Rollback()
	hostsCount := 0
	for _, mount := range prepared.Mounts() {
		if mount.GetTarget() == "/etc/hosts" {
			hostsCount++
			if !reflect.DeepEqual(mount, explicit) {
				t.Fatalf("explicit read-only hosts mount was altered: %+v", mount)
			}
		}
	}
	if hostsCount != 1 {
		t.Fatalf("expected exactly one hosts mount, got %d in %+v", hostsCount, prepared.Mounts())
	}
}
