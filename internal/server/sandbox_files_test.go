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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

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
		nil,
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
		[]*runtime.Mount{explicit},
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
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Mounts()) != 2 {
		t.Fatalf("mounts = %+v", prepared.Mounts())
	}
}

func TestPrepareSandboxFilesRejectsInvalidHostname(t *testing.T) {
	service := &sandboxService{config: config.Config{RootDir: t.TempDir()}}
	_, err := service.prepareSandboxFiles(
		"sbox-test",
		svc.SandboxDefaults{Hostname: "bad\nhost"},
		nil,
		[]*runtime.Mount{{Target: "/etc"}},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("invalid hostname error = %v", err)
	}
}
