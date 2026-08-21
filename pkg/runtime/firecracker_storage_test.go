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
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
)

func TestPrepareFirecrackerStorage(t *testing.T) {
	root := fakeEROFSImage(t, "root.erofs")
	mounted := fakeEROFSImage(t, "runtime.erofs")
	injected := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(injected, []byte("nameserver 1.1.1.1\n"), 0640); err != nil {
		t.Fatal(err)
	}
	spec := &Spec{
		Root: &Root{Path: root},
		Process: &Process{
			Args: []string{"/bin/sh", "-c", "sleep 30"},
			Env:  []string{"PATH=/bin"},
			Cwd:  "/work",
			User: User{UID: 1000, GID: 1001},
		},
		Hostname: "guest",
		Mounts: []Mount{
			{Type: "proc", Destination: "/proc"},
			{
				Type:        "tmpfs",
				Source:      "tmpfs",
				Destination: "/work/cache",
				Options:     []string{"rw", "nosuid", "size=1m"},
			},
			{
				Type:        "bind",
				Source:      injected,
				Destination: "/etc/resolv.conf",
				Options:     []string{"bind", "ro"},
			},
			{
				Type:        "erofs",
				Source:      mounted,
				Destination: "/opt/runtime",
				Options:     []string{"ro", "noexec"},
			},
		},
	}
	plan, err := prepareFirecrackerStorage(spec, StartConfig{
		Network: firecrackerTestNetwork(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.rootDrive.Path != root || !plan.rootDrive.ReadOnly {
		t.Fatalf("root drive = %+v", plan.rootDrive)
	}
	if len(plan.mountDrives) != 1 ||
		plan.mountDrives[0].ID != "mount_0" ||
		plan.mountDrives[0].Path != mounted {
		t.Fatalf("mount drives = %+v", plan.mountDrives)
	}
	if len(plan.configure.Mounts) != 2 ||
		plan.configure.Mounts[0].FSType != "tmpfs" ||
		plan.configure.Mounts[0].Target != "/work/cache" ||
		strings.Join(plan.configure.Mounts[0].Options, ",") !=
			"rw,nosuid,size=1m" ||
		plan.configure.Mounts[1].Device != "/dev/vdc" ||
		plan.configure.Mounts[1].Target != "/opt/runtime" {
		t.Fatalf("guest mounts = %+v", plan.configure.Mounts)
	}
	if len(plan.configure.Files) != 1 ||
		!plan.configure.Files[0].Readonly ||
		string(plan.configure.Files[0].Content) != "nameserver 1.1.1.1\n" ||
		plan.configure.Files[0].Mode != 0640 {
		t.Fatalf("injected files = %+v", plan.configure.Files)
	}
	if plan.configure.Network.Interface != "eth0" ||
		plan.configure.Network.Address != "10.42.0.2" ||
		plan.configure.Network.Gateway != "10.42.0.1" ||
		plan.configure.Network.MAC != "02:fc:0a:2a:00:02" {
		t.Fatalf("guest network = %+v", plan.configure.Network)
	}
	if plan.configure.Process.UID != 1000 ||
		plan.configure.Process.GID != 1001 {
		t.Fatalf("guest process = %+v", plan.configure.Process)
	}
}

func TestPrepareFirecrackerStorageUsesLastMountForTarget(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first-resolv.conf")
	if err := os.WriteFile(first, []byte("nameserver 1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	last := filepath.Join(t.TempDir(), "managed-resolv.conf")
	if err := os.WriteFile(last, []byte("nameserver 10.0.0.1\n"), 0640); err != nil {
		t.Fatal(err)
	}

	spec := &Spec{
		Root:    &Root{Path: fakeEROFSImage(t, "root.erofs")},
		Process: &Process{Args: []string{"/bin/true"}},
		Mounts: []Mount{
			{
				Type:        "bind",
				Source:      first,
				Destination: "/etc/./resolv.conf",
				Options:     []string{"bind", "ro"},
			},
			{
				Type:        "bind",
				Source:      last,
				Destination: "/etc/resolv.conf",
				Options:     []string{"bind", "ro"},
			},
		},
	}
	plan, err := prepareFirecrackerStorage(
		spec,
		StartConfig{Network: firecrackerTestNetwork()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.configure.Files) != 1 {
		t.Fatalf("injected files = %+v", plan.configure.Files)
	}
	file := plan.configure.Files[0]
	if file.Target != "/etc/resolv.conf" ||
		string(file.Content) != "nameserver 10.0.0.1\n" ||
		file.Mode != 0640 {
		t.Fatalf("injected file = %+v", file)
	}
}

func TestPrepareFirecrackerStorageRejectsWritableBind(t *testing.T) {
	source := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(source, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := prepareFirecrackerStorage(
		&Spec{
			Root:    &Root{Path: fakeEROFSImage(t, "root.erofs")},
			Process: &Process{Args: []string{"/bin/true"}},
			Mounts: []Mount{{
				Type:        "bind",
				Source:      source,
				Destination: "/data",
				Options:     []string{"rbind", "rw"},
			}},
		},
		StartConfig{Network: firecrackerTestNetwork()},
	)
	if err == nil || !strings.Contains(err.Error(), "explicitly read-only") {
		t.Fatalf("writable bind error = %v", err)
	}
}

func TestPrepareFirecrackerStorageRejectsDirectoryRoot(t *testing.T) {
	_, err := prepareFirecrackerStorage(
		&Spec{
			Root:    &Root{Path: t.TempDir()},
			Process: &Process{Args: []string{"/bin/true"}},
		},
		StartConfig{Network: firecrackerTestNetwork()},
	)
	if err == nil || !strings.Contains(err.Error(), "not a regular EROFS image") {
		t.Fatalf("directory root error = %v", err)
	}
}

func TestPrepareFirecrackerStorageRejectsDirectoryBind(t *testing.T) {
	_, err := prepareFirecrackerStorage(
		&Spec{
			Root:    &Root{Path: fakeEROFSImage(t, "root.erofs")},
			Process: &Process{Args: []string{"/bin/true"}},
			Mounts: []Mount{{
				Type:        "bind",
				Source:      t.TempDir(),
				Destination: "/data",
				Options:     []string{"ro"},
			}},
		},
		StartConfig{Network: firecrackerTestNetwork()},
	)
	if err == nil || !strings.Contains(err.Error(), "regular-file") {
		t.Fatalf("directory bind error = %v", err)
	}
}

func TestPrepareFirecrackerStorageRejectsUnsafeTmpfsOption(t *testing.T) {
	_, err := prepareFirecrackerStorage(
		&Spec{
			Root:    &Root{Path: fakeEROFSImage(t, "root.erofs")},
			Process: &Process{Args: []string{"/bin/true"}},
			Mounts: []Mount{{
				Type:        "tmpfs",
				Source:      "tmpfs",
				Destination: "/scratch",
				Options:     []string{"context=unconfined_u:object_r:tmp_t:s0"},
			}},
		},
		StartConfig{Network: firecrackerTestNetwork()},
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported tmpfs option") {
		t.Fatalf("unsafe tmpfs error = %v", err)
	}
}

func fakeEROFSImage(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	data := make([]byte, 2048)
	binary.LittleEndian.PutUint32(data[1024:], firecrackerEROFSMagic)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func firecrackerTestNetwork() *networkmanager.NetResource {
	return &networkmanager.NetResource{
		SchemaVersion: networkmanager.NetResourceSchemaVersion,
		EndpointType:  networkmanager.EndpointTypeTap,
		GuestMAC: net.HardwareAddr{
			0x02, 0xfc, 0x0a, 0x2a, 0x00, 0x02,
		},
		Interface: &net.Interface{
			Name:         "tap-test",
			HardwareAddr: net.HardwareAddr{0x02, 0xfd, 0x0a, 0x2a, 0x00, 0x02},
		},
		Ip:      net.IPv4(10, 42, 0, 2),
		Mask:    net.CIDRMask(24, 32),
		Gateway: net.IPv4(10, 42, 0, 1),
	}
}
