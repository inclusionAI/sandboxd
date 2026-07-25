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

// Package loopdevice allocates Linux loop devices through loop-control.
package loopdevice

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

const allocationRetries = 64

type operations interface {
	open(string, int, uint32) (int, error)
	close(int) error
	getFree(int) (int, error)
	makeDevice(string, int) error
	configure(int, *unix.LoopConfig) error
	clear(int) error
}

type systemOperations struct{}

func (systemOperations) open(path string, flags int, mode uint32) (int, error) {
	return unix.Open(path, flags, mode)
}

func (systemOperations) close(fd int) error {
	return unix.Close(fd)
}

func (systemOperations) getFree(fd int) (int, error) {
	return unix.IoctlRetInt(fd, unix.LOOP_CTL_GET_FREE)
}

func (systemOperations) makeDevice(path string, number int) error {
	device := int(unix.Mkdev(7, uint32(number)))
	return unix.Mknod(path, unix.S_IFBLK|0600, device)
}

func (systemOperations) configure(fd int, config *unix.LoopConfig) error {
	return unix.IoctlLoopConfigure(fd, config)
}

func (systemOperations) clear(fd int) error {
	return unix.IoctlSetInt(fd, unix.LOOP_CLR_FD, 0)
}

// Manager allocates loop devices from a devtmpfs directory.
type Manager struct {
	deviceDir string
	ops       operations
}

// New creates a loop device manager.
func New(deviceDir string) (*Manager, error) {
	if !filepath.IsAbs(deviceDir) || filepath.Clean(deviceDir) == "/" {
		return nil, fmt.Errorf("loop device directory must be an absolute non-root path")
	}
	return &Manager{
		deviceDir: filepath.Clean(deviceDir),
		ops:       systemOperations{},
	}, nil
}

// Device is an attached loop mapping. AUTOCLEAR removes the mapping after its
// final mount disappears.
type Device struct {
	path string
	fd   int
	ops  operations
	once sync.Once
	err  error
}

// Path returns the loop block-device path.
func (d *Device) Path() string {
	return d.path
}

// Release closes the manager's descriptor after the filesystem is mounted.
func (d *Device) Release() error {
	if d == nil {
		return nil
	}
	d.once.Do(func() {
		d.err = d.ops.close(d.fd)
	})
	return d.err
}

// Detach clears an unmounted loop mapping and closes its descriptor.
func (d *Device) Detach() error {
	if d == nil {
		return nil
	}
	d.once.Do(func() {
		clearErr := d.ops.clear(d.fd)
		if errors.Is(clearErr, unix.ENXIO) {
			clearErr = nil
		}
		d.err = errors.Join(clearErr, d.ops.close(d.fd))
	})
	return d.err
}

// AttachReadOnly atomically maps a file to a read-only, autoclearing loop
// device. The caller must keep the returned descriptor open until the
// filesystem has been mounted.
func (m *Manager) AttachReadOnly(backingPath string) (*Device, error) {
	backingFD, err := m.ops.open(backingPath, unix.O_CLOEXEC|unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open loop backing file %s: %w", backingPath, err)
	}
	defer m.ops.close(backingFD)
	if uint64(backingFD) > math.MaxUint32 {
		return nil, fmt.Errorf("backing file descriptor %d exceeds loop ABI", backingFD)
	}

	controlPath := filepath.Join(m.deviceDir, "loop-control")
	controlFD, err := m.ops.open(controlPath, unix.O_CLOEXEC|unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open loop control %s: %w", controlPath, err)
	}
	defer m.ops.close(controlFD)

	for attempt := 0; attempt < allocationRetries; attempt++ {
		number, err := m.ops.getFree(controlFD)
		if err != nil {
			return nil, fmt.Errorf("get free loop device: %w", err)
		}
		loopPath := filepath.Join(m.deviceDir, "loop"+strconv.Itoa(number))
		loopFD, err := m.ops.open(loopPath, unix.O_CLOEXEC|unix.O_RDWR, 0)
		if errors.Is(err, unix.ENOENT) {
			if nodeErr := m.ops.makeDevice(loopPath, number); nodeErr != nil &&
				!errors.Is(nodeErr, unix.EEXIST) {
				return nil, fmt.Errorf("create loop device %s: %w", loopPath, nodeErr)
			}
			loopFD, err = m.ops.open(loopPath, unix.O_CLOEXEC|unix.O_RDWR, 0)
		}
		if err != nil {
			return nil, fmt.Errorf("open loop device %s: %w", loopPath, err)
		}
		config := &unix.LoopConfig{Fd: uint32(backingFD)}
		config.Info.Flags = unix.LO_FLAGS_AUTOCLEAR | unix.LO_FLAGS_READ_ONLY
		copy(config.Info.File_name[:], backingPath)
		if err := m.ops.configure(loopFD, config); err != nil {
			_ = m.ops.close(loopFD)
			if errors.Is(err, unix.EBUSY) {
				continue
			}
			return nil, fmt.Errorf("configure loop device %s: %w", loopPath, err)
		}
		return &Device{path: loopPath, fd: loopFD, ops: m.ops}, nil
	}
	return nil, fmt.Errorf("allocate loop device: still busy after %d attempts", allocationRetries)
}
