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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestConntrackBatchBoundsCoalescesAndPropagatesFailure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	injected := errors.New("dump interrupted")
	var mu sync.Mutex
	sizes := []int{}
	b := newConntrackBatcher(func(ips []net.IP) error {
		mu.Lock()
		sizes = append(sizes, len(ips))
		first := len(sizes) == 1
		mu.Unlock()
		if first {
			close(entered)
			<-release
			return nil
		}
		return injected
	})
	first := make(chan error, 1)
	go func() { first <- b.Delete(net.ParseIP("10.0.0.1")) }()
	<-entered
	// Fill a complete pending batch deterministically while the first dump waits.
	replies := make([]chan error, conntrackBatchLimit)
	for i := range replies {
		replies[i] = make(chan error, 1)
		b.queue <- conntrackRequest{ip: net.IPv4(10, 0, 1, byte(i+1)), done: replies[i]}
	}
	closed := make(chan struct{})
	go func() { b.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("close dropped pending cleanup")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-first)
	for _, reply := range replies {
		require.ErrorIs(t, <-reply, injected)
	}
	<-closed
	require.Error(t, b.Delete(net.ParseIP("10.0.0.2")))
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []int{1, conntrackBatchLimit}, sizes)
}

func TestEndpointSetMatchesEveryNATTuplePosition(t *testing.T) {
	ip := net.IPv4(10, 88, 0, 2).To4()
	f := endpointSetFilter{[4]byte(ip): {}}
	for pos := 0; pos < 4; pos++ {
		flow := &netlink.ConntrackFlow{}
		switch pos {
		case 0:
			flow.Forward.SrcIP = ip
		case 1:
			flow.Forward.DstIP = ip
		case 2:
			flow.Reverse.SrcIP = ip
		case 3:
			flow.Reverse.DstIP = ip
		}
		require.True(t, f.MatchConntrackFlow(flow))
	}
	require.False(t, f.MatchConntrackFlow(&netlink.ConntrackFlow{}))
	require.False(t, f.MatchConntrackFlow(nil))
}

func TestEmptyPolicyFastPathRequiresDurableNeverInstalledProof(t *testing.T) {
	calls := 0
	b := &iptablesBackend{deleteConntrackForIP: func(net.IP) error { calls++; return nil }}
	entry := persistedEntry{IP: "10.88.0.2", IfIndex: 12, HostVeth: "tap", KernelPolicyAbsent: true}
	// Nil iptables clients make any unnecessary rule operation fail immediately.
	require.NoError(t, b.cleanup(entry))
	require.Equal(t, 1, calls)
	legacy := entry
	legacy.KernelPolicyAbsent = false
	client := &countingIPTables{iptablesClient: newMemoryIPTables()}
	b.client = client
	b.ipv6Client = newMemoryIPTables()
	require.NoError(t, b.cleanup(legacy))
	require.Equal(t, 2, calls)
	require.Greater(t, client.checks, 0, "legacy state must inspect kernel rules")

}

type countingIPTables struct {
	iptablesClient
	checks int
}

func (c *countingIPTables) ChainExists(table, chain string) (bool, error) {
	c.checks++
	return c.iptablesClient.ChainExists(table, chain)
}
