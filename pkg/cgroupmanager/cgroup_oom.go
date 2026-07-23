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
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	cg "github.com/containerd/cgroups/v3/cgroup1"
	"github.com/sirupsen/logrus"
)

// WatchOOM subscribes to the memory cgroup's oom_control eventfd for the
// given v1 cgroup name (e.g. "/sandbox/<id>") and invokes onOOM when the
// kernel reports an OOM event for that cgroup.
//
// onOOM is called at most once: an OOM kill is a one-shot event from
// sandboxd's perspective, since the offending process is dead by the time
// we observe it. The returned stop function tears the watcher down; it is
// safe to call multiple times and from any goroutine.
//
// The watcher goroutine reads the eventfd through Go's netpoller (via
// os.NewFile) so it does not pin an OS thread while blocked. stop closes
// the *os.File, which unblocks the read with an *PathError wrapping
// ErrClosed. Callers MUST call stop in a defer regardless of whether OOM
// fires, otherwise the goroutine leaks.
func (d *v1Driver) WatchOOM(name string, onOOM func()) (func(), error) {
	if onOOM == nil {
		return nil, errors.New("WatchOOM: onOOM callback must not be nil")
	}
	cgroup, err := d.handler.Load(cg.StaticPath(name), cg.WithHiearchy(cg.Default))
	if err != nil {
		return nil, fmt.Errorf("load cgroup %s: %w", name, err)
	}
	fdU, err := cgroup.OOMEventFD()
	if err != nil {
		return nil, fmt.Errorf("open oom eventfd for %s: %w", name, err)
	}
	// containerd opens the eventfd with flag=0 (blocking). Go's *os.File
	// only routes Read through the netpoller when the underlying fd is
	// non-blocking — otherwise (*FD).Read's first syscall.Read blocks
	// inside the kernel and pins an OS thread. Flip it to non-blocking
	// before wrapping so reads return EAGAIN and park the goroutine via
	// epoll instead.
	if err := syscall.SetNonblock(int(fdU), true); err != nil {
		_ = syscall.Close(int(fdU))
		return nil, fmt.Errorf("set non-blocking on oom eventfd for %s: %w", name, err)
	}
	// Hand the fd to os.NewFile so reads go through the runtime netpoller
	// (epoll) instead of pinning an OS thread per watcher. The *os.File now
	// owns the fd; closing it releases the underlying descriptor.
	f := os.NewFile(fdU, fmt.Sprintf("oom_eventfd:%s", name))
	if f == nil {
		_ = syscall.Close(int(fdU))
		return nil, fmt.Errorf("wrap oom eventfd for %s: invalid fd %d", name, fdU)
	}

	var (
		closeOnce sync.Once
		fired     sync.Once
	)
	done := make(chan struct{})
	stop := func() {
		closeOnce.Do(func() {
			// Reconcile a pending event synchronously. Wait may return before
			// the netpoll goroutine gets scheduled to consume the eventfd.
			buf := make([]byte, 8)
			if n, readErr := syscall.Read(int(fdU), buf); readErr == nil && n > 0 {
				fired.Do(onOOM)
			}
			if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				logrus.Warnf("close oom eventfd for %s: %v", name, err)
			}
		})
		<-done
	}

	go func() {
		defer close(done)
		buf := make([]byte, 8)
		for {
			n, err := f.Read(buf)
			if err != nil {
				// ErrClosed arrives once stop closed the file.
				return
			}
			if n == 0 {
				return
			}
			fired.Do(onOOM)
			// Stop watching after the first event; keeping the loop going
			// would only pick up duplicate notifications for the same dead
			// container.
			return
		}
	}()

	return stop, nil
}
