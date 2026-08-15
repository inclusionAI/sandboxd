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

package loopdevice

import (
	"errors"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeOperations struct {
	nextDevice    int
	configureErrs []error
	configs       []*unix.LoopConfig
	setFDErrs     []error
	statuses      []*unix.LoopInfo64
	statusValue   *unix.LoopInfo64
	statValue     unix.Stat_t
	opened        []string
	closed        []int
	cleared       []int
	missingDevice bool
	created       []string
}

func (f *fakeOperations) open(path string, _ int, _ uint32) (int, error) {
	f.opened = append(f.opened, path)
	if f.missingDevice && path == "/dev/loop"+strconv.Itoa(f.nextDevice) {
		f.missingDevice = false
		return 0, unix.ENOENT
	}
	return len(f.opened) + 10, nil
}

func (f *fakeOperations) close(fd int) error {
	f.closed = append(f.closed, fd)
	return nil
}

func (f *fakeOperations) getFree(int) (int, error) { return f.nextDevice, nil }

func (f *fakeOperations) makeDevice(path string, _ int) error {
	f.created = append(f.created, path)
	return nil
}

func (f *fakeOperations) setFD(_, _ int) error {
	if len(f.setFDErrs) == 0 {
		return nil
	}
	err := f.setFDErrs[0]
	f.setFDErrs = f.setFDErrs[1:]
	if errors.Is(err, unix.EBUSY) {
		f.nextDevice++
	}
	return err
}

func (f *fakeOperations) setStatus(_ int, status *unix.LoopInfo64) error {
	f.statuses = append(f.statuses, status)
	return nil
}

func (f *fakeOperations) configure(_ int, config *unix.LoopConfig) error {
	f.configs = append(f.configs, config)
	if len(f.configureErrs) == 0 {
		return nil
	}
	err := f.configureErrs[0]
	f.configureErrs = f.configureErrs[1:]
	if errors.Is(err, unix.EBUSY) {
		f.nextDevice++
	}
	return err
}

func (f *fakeOperations) clear(fd int) error {
	f.cleared = append(f.cleared, fd)
	return nil
}

func (f *fakeOperations) status(int) (*unix.LoopInfo64, error) {
	if f.statusValue == nil {
		return nil, errors.New("status unavailable")
	}
	value := *f.statusValue
	return &value, nil
}

func (f *fakeOperations) fstat(_ int, stat *unix.Stat_t) error {
	*stat = f.statValue
	return nil
}

func TestAttachReadOnlyUsesAtomicAutoclear(t *testing.T) {
	ops := &fakeOperations{nextDevice: 5, configureErrs: []error{unix.EBUSY, nil}}
	manager := &Manager{deviceDir: "/dev", ops: ops}
	device, err := manager.AttachReadOnly("/images/runtime.erofs")
	if err != nil {
		t.Fatal(err)
	}
	if device.Path() != "/dev/loop6" {
		t.Fatalf("loop path = %q, want /dev/loop6", device.Path())
	}
	flags := ops.configs[1].Info.Flags
	wantFlags := uint32(unix.LO_FLAGS_AUTOCLEAR | unix.LO_FLAGS_READ_ONLY)
	if flags != wantFlags {
		t.Fatalf("loop flags = %#x, want %#x", flags, wantFlags)
	}
	if err := device.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestAttachReadOnlyCreatesMissingDeviceNode(t *testing.T) {
	ops := &fakeOperations{nextDevice: 8, missingDevice: true}
	manager := &Manager{deviceDir: "/dev", ops: ops}
	device, err := manager.AttachReadOnly("/images/runtime.erofs")
	if err != nil {
		t.Fatal(err)
	}
	if len(ops.created) != 1 || ops.created[0] != "/dev/loop8" {
		t.Fatalf("created device nodes = %v", ops.created)
	}
	if device.Path() != "/dev/loop8" {
		t.Fatalf("loop path = %q, want /dev/loop8", device.Path())
	}
}

func TestAttachWritableCreatesMissingDeviceAndRetriesBusy(t *testing.T) {
	ops := &fakeOperations{
		nextDevice:    8,
		missingDevice: true,
		setFDErrs:     []error{unix.EBUSY, nil},
	}
	manager := &Manager{deviceDir: "/dev", ops: ops}
	device, err := manager.AttachWritable("/var/lib/sandboxd/ext4.img")
	if err != nil {
		t.Fatal(err)
	}
	if device.Path() != "/dev/loop9" {
		t.Fatalf("loop path = %q, want /dev/loop9", device.Path())
	}
	if len(ops.created) != 1 || ops.created[0] != "/dev/loop8" {
		t.Fatalf("created device nodes = %v", ops.created)
	}
	if len(ops.statuses) != 1 || ops.statuses[0].Flags != unix.LO_FLAGS_AUTOCLEAR {
		t.Fatalf("loop statuses = %+v", ops.statuses)
	}
}

func TestDetachClearsUnMountedLoop(t *testing.T) {
	ops := &fakeOperations{nextDevice: 3}
	manager := &Manager{deviceDir: "/dev", ops: ops}
	device, err := manager.AttachReadOnly("/images/runtime.erofs")
	if err != nil {
		t.Fatal(err)
	}
	if err := device.Detach(); err != nil {
		t.Fatal(err)
	}
	if len(ops.cleared) != 1 {
		t.Fatalf("clear calls = %d, want 1", len(ops.cleared))
	}
}

func TestAdoptVerifiesBackingFileAndFlags(t *testing.T) {
	ops := &fakeOperations{
		nextDevice: 12,
		statusValue: &unix.LoopInfo64{
			Device: 44,
			Inode:  55,
			Flags:  unix.LO_FLAGS_AUTOCLEAR,
		},
		statValue: unix.Stat_t{Dev: 44, Ino: 55},
	}
	manager := &Manager{deviceDir: "/dev", ops: ops}
	device, err := manager.Adopt("/dev/loop12", "/var/lib/sandboxd/ext4.img", false)
	if err != nil {
		t.Fatal(err)
	}
	if device.Path() != "/dev/loop12" {
		t.Fatalf("adopted path = %q", device.Path())
	}
}

func TestNewRejectsUnsafeDeviceDirectory(t *testing.T) {
	for _, path := range []string{"relative", "/"} {
		if _, err := New(path); err == nil {
			t.Fatalf("New(%q) succeeded", path)
		}
	}
}
