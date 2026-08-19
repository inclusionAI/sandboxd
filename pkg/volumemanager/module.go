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
	"fmt"
	"math"
	"os"
	"sync/atomic"
	"syscall"

	"github.com/inclusionAI/sandboxd/pkg/loopdevice"
	"github.com/sirupsen/logrus"
)

// Module owns a shared filestore and its optional loop-backed filesystem.
// An ordinary directory supports normal sandbox starts. A bounded ext4
// filesystem adds an aggregate capacity limit, while XFS is available for
// deployments that require it.
type Module struct {
	FilestoreDir    string
	Size            string
	XFSEnabled      bool
	LoopDeviceDir   string
	overcommitRatio float64

	loopDevice   *loopdevice.Device
	ensureMount  func(string, string, bool, *loopdevice.Manager) (*loopdevice.Device, error)
	cleanupMount func(string, bool, *loopdevice.Device) error

	started atomic.Bool
	healthy atomic.Bool
}

// NewModule constructs a Module rooted at filestoreDir.
func NewModule(
	filestoreDir, size string,
	xfsEnabled bool,
	overcommitRatio float64,
	loopDeviceDir ...string,
) *Module {
	deviceDir := "/dev"
	if len(loopDeviceDir) > 0 && loopDeviceDir[0] != "" {
		deviceDir = loopDeviceDir[0]
	}
	return &Module{
		FilestoreDir:    filestoreDir,
		Size:            size,
		XFSEnabled:      xfsEnabled,
		LoopDeviceDir:   deviceDir,
		overcommitRatio: overcommitRatio,
		ensureMount:     ensureFilestoreMount,
		cleanupMount:    cleanupFilestoreMount,
	}
}

// Start creates an ordinary directory when size is empty. A configured size
// selects a loop-backed ext4 or XFS filesystem and fails closed on setup errors.
func (m *Module) Start() error {
	m.started.Store(false)
	m.healthy.Store(false)
	if m.FilestoreDir == "" {
		m.started.Store(true)
		m.healthy.Store(true)
		return nil
	}
	if err := os.MkdirAll(m.FilestoreDir, 0755); err != nil {
		return fmt.Errorf("create filestore directory %s: %w", m.FilestoreDir, err)
	}
	if m.Size == "" {
		logrus.Infof("volumemanager: using ordinary filestore directory %s", m.FilestoreDir)
		m.started.Store(true)
		m.healthy.Store(true)
		return nil
	}
	manager, err := loopdevice.New(m.LoopDeviceDir)
	if err != nil {
		return fmt.Errorf("initialize loop manager: %w", err)
	}
	device, err := m.ensureMount(m.FilestoreDir, m.Size, m.XFSEnabled, manager)
	if err != nil {
		return fmt.Errorf("mount filestore: %w", err)
	}
	m.loopDevice = device
	m.started.Store(true)
	m.healthy.Store(true)
	return nil
}

// Stop tears down a bounded filestore. Ordinary directories are preserved.
func (m *Module) Stop() error {
	if !m.started.Load() {
		return nil
	}
	m.healthy.Store(false)
	if m.Size == "" {
		m.started.Store(false)
		return nil
	}
	err := m.cleanupMount(m.FilestoreDir, m.XFSEnabled, m.loopDevice)
	if err == nil {
		m.loopDevice = nil
		m.started.Store(false)
	}
	return err
}

// Healthy reports whether Start established the selected filestore mode.
func (m *Module) Healthy() bool { return m.healthy.Load() }

// EphemeralStorageCapacity reports logical total and available bytes on the
// filestore. The overcommit ratio is applied exactly once here, at the boundary
// between physical filesystem statistics and scheduler-visible storage.
func (m *Module) EphemeralStorageCapacity() (uint64, uint64, error) {
	if m.FilestoreDir == "" {
		return 0, 0, fmt.Errorf("filestore_dir is not configured")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(m.FilestoreDir, &stat); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", m.FilestoreDir, err)
	}
	if stat.Bsize <= 0 {
		return 0, 0, fmt.Errorf("statfs %s returned invalid block size %d", m.FilestoreDir, stat.Bsize)
	}
	blockSize := uint64(stat.Bsize)
	physicalCapacity := stat.Blocks * blockSize
	physicalAvailable := stat.Bavail * blockSize
	capacity, err := scaleStorageBytes(physicalCapacity, m.overcommitRatio)
	if err != nil {
		return 0, 0, fmt.Errorf("scale filestore capacity: %w", err)
	}
	available, err := scaleStorageBytes(physicalAvailable, m.overcommitRatio)
	if err != nil {
		return 0, 0, fmt.Errorf("scale filestore available bytes: %w", err)
	}
	return capacity, available, nil
}

func scaleStorageBytes(physicalBytes uint64, ratio float64) (uint64, error) {
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 1 {
		return 0, fmt.Errorf("overcommit ratio must be finite and at least 1.0, got %g", ratio)
	}
	if ratio == 1 {
		return physicalBytes, nil
	}
	scaled := float64(physicalBytes) * ratio
	if scaled >= math.Ldexp(1, 64) {
		return 0, fmt.Errorf(
			"logical storage overflows uint64: physical bytes %d, ratio %g",
			physicalBytes,
			ratio,
		)
	}
	return uint64(scaled), nil
}
