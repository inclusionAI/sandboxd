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

package networkacl

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const conntrackBatchLimit = 64

type conntrackRequest struct {
	ip   net.IP
	done chan error
}

// Bounded queue and batching window amortize a namespace-wide conntrack dump.
// Each caller waits for its batch, so endpoint reuse cannot outrun cleanup.
type conntrackBatcher struct {
	mu       sync.RWMutex
	closed   bool
	queue    chan conntrackRequest
	finished chan struct{}
}

func newConntrackBatcher(remove func([]net.IP) error) *conntrackBatcher {
	b := &conntrackBatcher{queue: make(chan conntrackRequest, conntrackBatchLimit), finished: make(chan struct{})}
	go func() {
		defer close(b.finished)
		for first := range b.queue {
			batch := []conntrackRequest{first}
			timer := time.NewTimer(200 * time.Microsecond)
		collect:
			for len(batch) < conntrackBatchLimit {
				select {
				case next, ok := <-b.queue:
					if !ok {
						break collect
					}
					batch = append(batch, next)
				case <-timer.C:
					break collect
				}
			}
			timer.Stop()
			ips := make([]net.IP, len(batch))
			for i, r := range batch {
				ips[i] = r.ip
			}
			err := remove(ips)
			for _, r := range batch {
				r.done <- err
			}
		}
	}()
	return b
}

func (b *conntrackBatcher) Delete(ip net.IP) error {
	if ip.To4() == nil {
		return errors.New("conntrack endpoint must be IPv4")
	}
	r := conntrackRequest{ip: append(net.IP(nil), ip.To4()...), done: make(chan error, 1)}
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return errors.New("conntrack cleaner is closed")
	}
	b.queue <- r
	b.mu.RUnlock()
	return <-r.done
}

func (b *conntrackBatcher) Close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.queue)
	}
	b.mu.Unlock()
	<-b.finished
}

type endpointSetFilter map[[4]byte]struct{}

func (f endpointSetFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if flow == nil {
		return false
	}
	for _, ip := range []net.IP{flow.Forward.SrcIP, flow.Forward.DstIP, flow.Reverse.SrcIP, flow.Reverse.DstIP} {
		if v := ip.To4(); v != nil {
			if _, ok := f[[4]byte(v)]; ok {
				return true
			}
		}
	}
	return false
}

func deleteConntrackEndpoints(ips []net.IP) error {
	filter := make(endpointSetFilter, len(ips))
	for _, ip := range ips {
		if v := ip.To4(); v != nil {
			filter[[4]byte(v)] = struct{}{}
		}
	}
	if len(filter) == 0 {
		return nil
	}
	_, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET), filter)
	return err
}
