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
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	cg "github.com/containerd/cgroups/v3/cgroup1"
	"golang.org/x/sys/unix"
)

type v1OOMEntry struct {
	name      string
	fd        int
	mu        sync.Mutex
	removed   bool
	triggered atomic.Bool
}

type v1OOMWatcher struct {
	epollFD int
	wakeFD  int

	mu     sync.RWMutex
	byName map[string]*v1OOMEntry
	byFD   map[int]*v1OOMEntry

	closed atomic.Bool
	wg     sync.WaitGroup
}

func newV1OOMWatcher() (*v1OOMWatcher, error) {
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create cgroup v1 OOM epoll: %w", err)
	}
	wakeFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = unix.Close(epollFD)
		return nil, fmt.Errorf("create cgroup v1 OOM wake eventfd: %w", err)
	}
	if err := unix.EpollCtl(epollFD, unix.EPOLL_CTL_ADD, wakeFD, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(wakeFD),
	}); err != nil {
		_ = unix.Close(wakeFD)
		_ = unix.Close(epollFD)
		return nil, fmt.Errorf("register cgroup v1 OOM wake eventfd: %w", err)
	}

	watcher := &v1OOMWatcher{
		epollFD: epollFD,
		wakeFD:  wakeFD,
		byName:  make(map[string]*v1OOMEntry),
		byFD:    make(map[int]*v1OOMEntry),
	}
	watcher.wg.Add(1)
	go watcher.run()
	return watcher, nil
}

func (w *v1OOMWatcher) Add(name string) error {
	if w.closed.Load() {
		return errors.New("cgroup v1 OOM watcher is closed")
	}

	group, err := cg.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return fmt.Errorf("load cgroup %s for OOM watch: %w", name, err)
	}
	rawFD, err := group.OOMEventFD()
	if err != nil {
		return fmt.Errorf("open OOM eventfd for %s: %w", name, err)
	}
	fd := int(rawFD)
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("set OOM eventfd non-blocking for %s: %w", name, err)
	}
	return w.addFD(name, fd)
}

func (w *v1OOMWatcher) addFD(name string, fd int) error {
	entry := &v1OOMEntry{name: name, fd: fd}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		_ = unix.Close(fd)
		return errors.New("cgroup v1 OOM watcher is closed")
	}
	if _, exists := w.byName[name]; exists {
		_ = unix.Close(fd)
		return nil
	}
	if err := unix.EpollCtl(w.epollFD, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
	}); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("register OOM eventfd for %s: %w", name, err)
	}
	w.byName[name] = entry
	w.byFD[fd] = entry
	return nil
}

func (w *v1OOMWatcher) Remove(name string) {
	w.mu.Lock()
	entry, exists := w.byName[name]
	if exists {
		delete(w.byName, name)
		delete(w.byFD, entry.fd)
		_ = unix.EpollCtl(w.epollFD, unix.EPOLL_CTL_DEL, entry.fd, nil)
	}
	w.mu.Unlock()
	if !exists {
		return
	}

	entry.mu.Lock()
	entry.removed = true
	_ = unix.Close(entry.fd)
	entry.mu.Unlock()
}

func (w *v1OOMWatcher) Reset(name string) error {
	entry, err := w.entry(name)
	if err != nil {
		return err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.removed {
		return fmt.Errorf("OOM watcher for cgroup %s was removed", name)
	}
	if _, err := drainEventFD(entry.fd); err != nil {
		return fmt.Errorf("drain OOM eventfd for %s: %w", name, err)
	}
	entry.triggered.Store(false)
	return nil
}

func (w *v1OOMWatcher) OOMKilled(name string) (bool, error) {
	entry, err := w.entry(name)
	if err != nil {
		return false, err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.removed {
		return false, fmt.Errorf("OOM watcher for cgroup %s was removed", name)
	}
	triggered, err := drainEventFD(entry.fd)
	if err != nil {
		return false, fmt.Errorf("drain OOM eventfd for %s: %w", name, err)
	}
	if triggered {
		entry.triggered.Store(true)
	}
	return entry.triggered.Load(), nil
}

func (w *v1OOMWatcher) entry(name string) (*v1OOMEntry, error) {
	w.mu.RLock()
	entry, exists := w.byName[name]
	w.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("OOM watcher for cgroup %s is not registered", name)
	}
	return entry, nil
}

func (w *v1OOMWatcher) run() {
	defer w.wg.Done()
	events := make([]unix.EpollEvent, 64)
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
			w.mu.RLock()
			entry := w.byFD[fd]
			w.mu.RUnlock()
			if entry == nil {
				continue
			}
			entry.mu.Lock()
			if !entry.removed {
				triggered, readErr := drainEventFD(entry.fd)
				if readErr == nil && triggered {
					entry.triggered.Store(true)
				}
			}
			entry.mu.Unlock()
		}
	}
}

func (w *v1OOMWatcher) Close() error {
	if !w.closed.CompareAndSwap(false, true) {
		return nil
	}
	wakeEventFD(w.wakeFD)
	w.wg.Wait()

	w.mu.Lock()
	entries := make([]*v1OOMEntry, 0, len(w.byName))
	for _, entry := range w.byName {
		entries = append(entries, entry)
	}
	w.byName = make(map[string]*v1OOMEntry)
	w.byFD = make(map[int]*v1OOMEntry)
	w.mu.Unlock()
	for _, entry := range entries {
		entry.mu.Lock()
		entry.removed = true
		_ = unix.Close(entry.fd)
		entry.mu.Unlock()
	}
	_ = unix.Close(w.wakeFD)
	return unix.Close(w.epollFD)
}

func drainEventFD(fd int) (bool, error) {
	var buffer [8]byte
	triggered := false
	for {
		_, err := unix.Read(fd, buffer[:])
		switch {
		case err == nil:
			triggered = true
		case errors.Is(err, unix.EAGAIN):
			return triggered, nil
		case errors.Is(err, unix.EINTR):
			continue
		default:
			return triggered, err
		}
	}
}

func wakeEventFD(fd int) {
	var buffer [8]byte
	binary.NativeEndian.PutUint64(buffer[:], 1)
	_, _ = unix.Write(fd, buffer[:])
}
