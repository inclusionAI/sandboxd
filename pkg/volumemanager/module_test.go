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

package volumemanager

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/loopdevice"
)

func TestModuleStartUsesOrdinaryDirectoryWithoutSize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "filestore")
	m := NewModule(dir, "", false, 1)
	m.ensureMount = func(string, string, bool, *loopdevice.Manager) (*loopdevice.Device, error) {
		t.Fatal("bounded mount called without size")
		return nil, nil
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if !m.Healthy() {
		t.Fatal("module is unhealthy")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("filestore stat = (%v, %v)", info, err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("ordinary filestore was removed: %v", err)
	}
}

func TestModuleStartFailsWhenConfiguredMountFails(t *testing.T) {
	m := NewModule(filepath.Join(t.TempDir(), "filestore"), "1G", false, 1)
	m.ensureMount = func(string, string, bool, *loopdevice.Manager) (*loopdevice.Device, error) {
		return nil, errors.New("loop unavailable")
	}
	if err := m.Start(); err == nil {
		t.Fatal("Start succeeded")
	}
	if m.Healthy() {
		t.Fatal("module is healthy after failed start")
	}
}

func TestModuleStartUsesExt4ByDefault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "filestore")
	m := NewModule(dir, "1G", false, 1)
	m.ensureMount = func(gotDir, gotSize string, gotXFS bool, _ *loopdevice.Manager) (*loopdevice.Device, error) {
		if gotDir != dir || gotSize != "1G" || gotXFS {
			t.Fatalf("ensureMount(%q, %q, %t)", gotDir, gotSize, gotXFS)
		}
		return nil, nil
	}
	m.cleanupMount = func(string, bool, *loopdevice.Device) error { return nil }
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if !m.Healthy() {
		t.Fatal("module is unhealthy")
	}
}

func TestModuleStartUsesXFSWhenEnabled(t *testing.T) {
	m := NewModule(filepath.Join(t.TempDir(), "filestore"), "1G", true, 1)
	m.ensureMount = func(_ string, _ string, gotXFS bool, _ *loopdevice.Manager) (*loopdevice.Device, error) {
		if !gotXFS {
			t.Fatal("XFS was not enabled")
		}
		return nil, nil
	}
	m.cleanupMount = func(string, bool, *loopdevice.Device) error { return nil }
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if !m.Healthy() {
		t.Fatal("module is unhealthy")
	}
}

func TestEphemeralStorageCapacity(t *testing.T) {
	m := NewModule(t.TempDir(), "", false, 1)
	capacity, allocatable, err := m.EphemeralStorageCapacity()
	if err != nil {
		t.Fatal(err)
	}
	if capacity == 0 || allocatable == 0 || allocatable > capacity {
		t.Fatalf("capacity=%d allocatable=%d", capacity, allocatable)
	}
}

func TestEphemeralStorageCapacityRequiresFilestore(t *testing.T) {
	m := NewModule("", "", false, 1)
	if _, _, err := m.EphemeralStorageCapacity(); err == nil {
		t.Fatal("expected unconfigured filestore error")
	}
}

func TestScaleStorageBytes(t *testing.T) {
	maxUint64 := ^uint64(0)
	for _, test := range []struct {
		name          string
		physicalBytes uint64
		ratio         float64
		want          uint64
		wantErr       bool
	}{
		{name: "identity", physicalBytes: maxUint64, ratio: 1, want: maxUint64},
		{name: "integer", physicalBytes: 300, ratio: 2, want: 600},
		{name: "fractional floors", physicalBytes: 3, ratio: 1.5, want: 4},
		{name: "invalid ratio", physicalBytes: 300, ratio: 0.5, wantErr: true},
		{
			name:          "overflow",
			physicalBytes: maxUint64,
			ratio:         math.Nextafter(1, 2),
			wantErr:       true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := scaleStorageBytes(test.physicalBytes, test.ratio)
			if (err != nil) != test.wantErr {
				t.Fatalf("scaleStorageBytes(%d, %g) error = %v", test.physicalBytes, test.ratio, err)
			}
			if err == nil && got != test.want {
				t.Fatalf("scaleStorageBytes(%d, %g) = %d, want %d", test.physicalBytes, test.ratio, got, test.want)
			}
		})
	}
}

func TestEphemeralStorageSnapshotUsesPhysicalOccupancy(t *testing.T) {
	stat := syscall.Statfs_t{Bsize: 4096, Blocks: 100, Bavail: 25}
	for _, ratio := range []float64{1, 1.5, 2} {
		capacity, available, disk, err := ephemeralStorageSnapshot(stat, ratio)
		if err != nil {
			t.Fatal(err)
		}
		if capacity != uint64(409600*ratio) || available != uint64(102400*ratio) || disk == nil || *disk != .75 {
			t.Fatalf("ratio=%v capacity=%d available=%d disk=%v", ratio, capacity, available, disk)
		}
	}
	_, _, disk, err := ephemeralStorageSnapshot(syscall.Statfs_t{Bsize: 4096}, 1)
	if err != nil || disk != nil {
		t.Fatalf("empty filesystem: disk=%v err=%v", disk, err)
	}
	for _, invalid := range []syscall.Statfs_t{
		{Bsize: 0}, {Bsize: 4096, Blocks: 100, Bavail: 101}, {Bsize: 4096, Blocks: math.MaxUint64},
	} {
		if _, _, _, err := ephemeralStorageSnapshot(invalid, 1); err == nil {
			t.Fatalf("accepted invalid statfs: %+v", invalid)
		}
	}
}

func TestEphemeralStorageSnapshotReadsConfiguredFilestore(t *testing.T) {
	m := NewModule(t.TempDir(), "", false, 2)
	capacity, available, disk, err := m.EphemeralStorageSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if capacity == 0 || available > capacity || disk == nil || *disk < 0 || *disk > 1 {
		t.Fatalf("invalid snapshot: %d %d %v", capacity, available, disk)
	}
	m.FilestoreDir = filepath.Join(t.TempDir(), "missing")
	if _, _, disk, err := m.EphemeralStorageSnapshot(); err == nil || disk != nil {
		t.Fatalf("missing filestore: disk=%v err=%v", disk, err)
	}
}
