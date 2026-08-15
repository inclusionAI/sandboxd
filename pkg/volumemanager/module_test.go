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
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/loopdevice"
)

func TestModuleStartUsesOrdinaryDirectoryWithoutSize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "filestore")
	m := NewModule(dir, "", false)
	m.ensureMount = func(string, string, bool, *loopdevice.Manager) (*loopdevice.Device, error) {
		t.Fatal("bounded mount called without size")
		return nil, nil
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if !m.Healthy() || m.ForkSupported() {
		t.Fatalf("healthy=%t fork=%t", m.Healthy(), m.ForkSupported())
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
	m := NewModule(filepath.Join(t.TempDir(), "filestore"), "1G", false)
	m.ensureMount = func(string, string, bool, *loopdevice.Manager) (*loopdevice.Device, error) {
		return nil, errors.New("loop unavailable")
	}
	if err := m.Start(); err == nil {
		t.Fatal("Start succeeded")
	}
	if m.Healthy() || m.ForkSupported() {
		t.Fatalf("healthy=%t fork=%t", m.Healthy(), m.ForkSupported())
	}
}

func TestModuleStartUsesExt4ByDefault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "filestore")
	m := NewModule(dir, "1G", false)
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
	if !m.Healthy() || m.ForkSupported() {
		t.Fatalf("healthy=%t fork=%t", m.Healthy(), m.ForkSupported())
	}
}

func TestModuleStartEnablesForkOnlyForXFS(t *testing.T) {
	m := NewModule(filepath.Join(t.TempDir(), "filestore"), "1G", true)
	m.ensureMount = func(string, string, bool, *loopdevice.Manager) (*loopdevice.Device, error) {
		return nil, nil
	}
	m.cleanupMount = func(string, bool, *loopdevice.Device) error { return nil }
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if !m.Healthy() || !m.ForkSupported() {
		t.Fatalf("healthy=%t fork=%t", m.Healthy(), m.ForkSupported())
	}
}

func TestEphemeralStorageCapacity(t *testing.T) {
	m := NewModule(t.TempDir(), "", false)
	capacity, allocatable, err := m.EphemeralStorageCapacity()
	if err != nil {
		t.Fatal(err)
	}
	if capacity == 0 || allocatable == 0 || allocatable > capacity {
		t.Fatalf("capacity=%d allocatable=%d", capacity, allocatable)
	}
}

func TestEphemeralStorageCapacityRequiresFilestore(t *testing.T) {
	m := NewModule("", "", false)
	if _, _, err := m.EphemeralStorageCapacity(); err == nil {
		t.Fatal("expected unconfigured filestore error")
	}
}
