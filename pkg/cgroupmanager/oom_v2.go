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

package cgroupmanager

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const v2OOMEventSettleTimeout = time.Second

type v2OOMEntry struct {
	name        string
	memoryPath  string
	cgroupPath  string
	memoryWD    int
	cgroupWD    int
	mu          sync.Mutex
	removed     bool
	ready       chan struct{}
	readyClosed bool
	baseline    uint64
	triggered   atomic.Bool
}

type v2OOMWatcher struct {
	mountpoint string
	inotifyFD  int
	epollFD    int
	wakeFD     int

	// eventsMu serializes reads from the shared inotify fd. OOMKilled drains
	// already-queued notifications and waits for either an OOM increment or
	// an empty cgroup, so runtime Wait cannot outrun the kernel notifications.
	eventsMu    sync.Mutex
	eventBuffer []byte

	mu     sync.RWMutex
	byName map[string]*v2OOMEntry
	byWD   map[int]*v2OOMEntry

	closed atomic.Bool
	wg     sync.WaitGroup
}

func newV2OOMWatcher(mountpoint string) (*v2OOMWatcher, error) {
	inotifyFD, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("create cgroup v2 OOM inotify: %w", err)
	}
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		_ = unix.Close(inotifyFD)
		return nil, fmt.Errorf("create cgroup v2 OOM epoll: %w", err)
	}
	wakeFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = unix.Close(epollFD)
		_ = unix.Close(inotifyFD)
		return nil, fmt.Errorf("create cgroup v2 OOM wake eventfd: %w", err)
	}
	for fd, label := range map[int]string{
		inotifyFD: "inotify",
		wakeFD:    "wake eventfd",
	} {
		if err := unix.EpollCtl(epollFD, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(fd),
		}); err != nil {
			_ = unix.Close(wakeFD)
			_ = unix.Close(epollFD)
			_ = unix.Close(inotifyFD)
			return nil, fmt.Errorf("register cgroup v2 OOM %s: %w", label, err)
		}
	}

	watcher := &v2OOMWatcher{
		mountpoint:  mountpoint,
		inotifyFD:   inotifyFD,
		epollFD:     epollFD,
		wakeFD:      wakeFD,
		eventBuffer: make([]byte, 64*1024),
		byName:      make(map[string]*v2OOMEntry),
		byWD:        make(map[int]*v2OOMEntry),
	}
	watcher.wg.Add(1)
	go watcher.run()
	return watcher, nil
}

func (w *v2OOMWatcher) Add(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return errors.New("cgroup v2 OOM watcher is closed")
	}
	if _, exists := w.byName[name]; exists {
		return nil
	}
	memoryPath := filepath.Join(w.mountpoint, name, "memory.events")
	baseline, err := readOOMKillCount(memoryPath)
	if err != nil {
		return fmt.Errorf("read OOM baseline for %s: %w", name, err)
	}
	memoryWD, err := unix.InotifyAddWatch(
		w.inotifyFD,
		memoryPath,
		unix.IN_MODIFY|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF,
	)
	if err != nil {
		return fmt.Errorf("watch memory.events for %s: %w", name, err)
	}
	cgroupPath := filepath.Join(w.mountpoint, name, "cgroup.events")
	cgroupWD, err := unix.InotifyAddWatch(
		w.inotifyFD,
		cgroupPath,
		unix.IN_MODIFY|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF,
	)
	if err != nil {
		_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(memoryWD))
		return fmt.Errorf("watch cgroup.events for %s: %w", name, err)
	}
	current, err := readOOMKillCount(memoryPath)
	if err != nil {
		_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(memoryWD))
		_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(cgroupWD))
		return fmt.Errorf("verify OOM baseline for %s: %w", name, err)
	}
	entry := &v2OOMEntry{
		name:       name,
		memoryPath: memoryPath,
		cgroupPath: cgroupPath,
		memoryWD:   memoryWD,
		cgroupWD:   cgroupWD,
		ready:      make(chan struct{}),
		baseline:   baseline,
	}
	if current > baseline {
		entry.triggered.Store(true)
		entry.signalReady()
	}
	w.byName[name] = entry
	w.byWD[memoryWD] = entry
	w.byWD[cgroupWD] = entry
	return nil
}

func (w *v2OOMWatcher) Remove(name string) {
	w.mu.Lock()
	entry, exists := w.byName[name]
	if exists {
		delete(w.byName, name)
		delete(w.byWD, entry.memoryWD)
		delete(w.byWD, entry.cgroupWD)
	}
	w.mu.Unlock()
	if !exists {
		return
	}

	entry.mu.Lock()
	entry.removed = true
	entry.signalReady()
	_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(entry.memoryWD))
	_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(entry.cgroupWD))
	entry.mu.Unlock()
}

func (w *v2OOMWatcher) Reset(name string) error {
	entry, err := w.entry(name)
	if err != nil {
		return err
	}
	if err := w.drainEvents(); err != nil {
		return fmt.Errorf("drain cgroup v2 OOM events before reset: %w", err)
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.removed {
		return fmt.Errorf("OOM watcher for cgroup %s was removed", name)
	}
	current, err := readOOMKillCount(entry.memoryPath)
	if err != nil {
		return fmt.Errorf("reset OOM baseline for %s: %w", name, err)
	}
	entry.baseline = current
	entry.triggered.Store(false)
	entry.ready = make(chan struct{})
	entry.readyClosed = false
	return nil
}

func (w *v2OOMWatcher) OOMKilled(name string) (bool, error) {
	entry, err := w.entry(name)
	if err != nil {
		return false, err
	}
	if err := w.drainEvents(); err != nil {
		return false, fmt.Errorf("drain cgroup v2 OOM events: %w", err)
	}

	entry.mu.Lock()
	if entry.removed {
		entry.mu.Unlock()
		return false, fmt.Errorf("OOM watcher for cgroup %s was removed", name)
	}
	if entry.triggered.Load() || entry.readyClosed {
		killed := entry.triggered.Load()
		entry.mu.Unlock()
		return killed, nil
	}
	ready := entry.ready
	entry.mu.Unlock()

	timer := time.NewTimer(v2OOMEventSettleTimeout)
	defer timer.Stop()
	select {
	case <-ready:
	case <-timer.C:
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.removed {
		return false, fmt.Errorf("OOM watcher for cgroup %s was removed", name)
	}
	return entry.triggered.Load(), nil
}

func (w *v2OOMWatcher) entry(name string) (*v2OOMEntry, error) {
	w.mu.RLock()
	entry, exists := w.byName[name]
	w.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("OOM watcher for cgroup %s is not registered", name)
	}
	return entry, nil
}

func (w *v2OOMWatcher) run() {
	defer w.wg.Done()
	events := make([]unix.EpollEvent, 2)
	for {
		count, err := unix.EpollWait(w.epollFD, events, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return
		}
		for _, event := range events[:count] {
			fd := int(event.Fd)
			if fd == w.wakeFD {
				return
			}
			if fd != w.inotifyFD {
				continue
			}
			if err := w.drainEvents(); err != nil {
				return
			}
		}
	}
}

func (w *v2OOMWatcher) drainEvents() error {
	w.eventsMu.Lock()
	defer w.eventsMu.Unlock()

	for {
		bytesRead, err := unix.Read(w.inotifyFD, w.eventBuffer)
		switch {
		case errors.Is(err, unix.EAGAIN):
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return err
		case bytesRead == 0:
			return nil
		default:
			w.handleEvents(w.eventBuffer[:bytesRead])
		}
	}
}

func (w *v2OOMWatcher) handleEvents(buffer []byte) {
	for offset := 0; offset+unix.SizeofInotifyEvent <= len(buffer); {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buffer[offset]))
		offset += unix.SizeofInotifyEvent + int(raw.Len)

		w.mu.RLock()
		entry := w.byWD[int(raw.Wd)]
		w.mu.RUnlock()
		if entry == nil {
			continue
		}
		entry.mu.Lock()
		if !entry.removed {
			current, oomErr := readOOMKillCount(entry.memoryPath)
			if oomErr == nil && current > entry.baseline {
				entry.triggered.Store(true)
				entry.signalReady()
			} else if populated, eventErr := readCgroupPopulated(entry.cgroupPath); eventErr == nil &&
				!populated {
				entry.signalReady()
			}
		}
		entry.mu.Unlock()
	}
}

func (e *v2OOMEntry) signalReady() {
	if e.readyClosed {
		return
	}
	close(e.ready)
	e.readyClosed = true
}

func (w *v2OOMWatcher) Close() error {
	if !w.closed.CompareAndSwap(false, true) {
		return nil
	}
	wakeEventFD(w.wakeFD)
	w.wg.Wait()

	w.mu.Lock()
	entries := make([]*v2OOMEntry, 0, len(w.byName))
	for _, entry := range w.byName {
		entries = append(entries, entry)
	}
	w.byName = make(map[string]*v2OOMEntry)
	w.byWD = make(map[int]*v2OOMEntry)
	w.mu.Unlock()
	for _, entry := range entries {
		entry.mu.Lock()
		entry.removed = true
		entry.signalReady()
		_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(entry.memoryWD))
		_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(entry.cgroupWD))
		entry.mu.Unlock()
	}
	_ = unix.Close(w.wakeFD)
	_ = unix.Close(w.inotifyFD)
	return unix.Close(w.epollFD)
}

func readOOMKillCount(path string) (uint64, error) {
	return readEventValue(path, "oom_kill")
}

func readCgroupPopulated(path string) (bool, error) {
	populated, err := readEventValue(path, "populated")
	if err != nil {
		return false, err
	}
	return populated != 0, nil
}

func readEventValue(path, key string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var fields [2]string
		count := 0
		for field := range strings.FieldsSeq(scanner.Text()) {
			if count < len(fields) {
				fields[count] = field
			}
			count++
		}
		if count == 0 || fields[0] != key {
			continue
		}
		if count != len(fields) {
			return 0, fmt.Errorf("invalid %s entry %q", key, scanner.Text())
		}
		return strconv.ParseUint(fields[1], 10, 64)
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%s does not contain %s", filepath.Base(path), key)
}
