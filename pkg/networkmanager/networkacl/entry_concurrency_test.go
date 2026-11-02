// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

type pausedRecordStore struct {
	*store.BboltStoreImp
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *pausedRecordStore) StoreRecords(bucket string, records map[string][]byte) error {
	if _, ok := records["slow"]; ok {
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	return s.BboltStoreImp.StoreRecords(bucket, records)
}

func TestDurableEntryWaitDoesNotHoldRegistry(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	defer db.Close()
	state := &pausedRecordStore{BboltStoreImp: db, entered: make(chan struct{}), release: make(chan struct{})}
	m := &Manager{store: state, entries: map[string]persistedEntry{}, sourceIndex: map[string]string{}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { return nil }}}
	require.NoError(t, m.loadState())
	m.entries["slow"] = persistedEntry{IP: "10.88.0.2", HostVeth: "old", IfIndex: 1234, KernelPolicyAbsent: true}
	// Use the actual bbolt record layout and initialize the existing endpoint.
	raw, err := encodeEntries(m.entries)
	require.NoError(t, err)
	require.NoError(t, db.StoreRecords(entryStoreKey, raw))
	done := make(chan error, 1)
	go func() { done <- m.Remove("slow") }()
	<-state.entered
	peer := make(chan error, 1)
	go func() {
		peer <- m.Register(Binding{SandboxID: "peer", IP: net.ParseIP("10.88.0.3"), HostVeth: "lo"}, Policy{})
	}()
	select {
	case err := <-peer:
		require.NoError(t, err)
	case <-time.After(time.Second):
		close(state.release)
		<-done
		t.Fatal("independent registration waited for durable write")
	}
	// The slow endpoint stays reserved before its intent has committed.
	require.Error(t, m.Register(Binding{SandboxID: "slow", IP: net.ParseIP("10.88.0.4"), HostVeth: "lo"}, Policy{}))
	close(state.release)
	require.NoError(t, <-done)
	recovered := &Manager{store: db, entries: map[string]persistedEntry{}}
	require.NoError(t, recovered.loadState())
	require.Contains(t, recovered.entries, "peer")
	require.NotContains(t, recovered.entries, "slow")
}

func TestLegacyStateMigratesOnce(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.StoreRaw(stateStoreKey, []byte(`{"entries":{"old":{"ip":"10.88.0.2","ifindex":42,"orphaned":true}}}`)))
	m := &Manager{store: db, entries: map[string]persistedEntry{}}
	require.NoError(t, m.loadState())
	require.True(t, m.entries["old"].Orphaned)
	legacy, err := db.LoadRaw(stateStoreKey)
	require.NoError(t, err)
	require.False(t, json.Valid(legacy), "old whole-state readers must reject migrated data")
	require.NoError(t, m.persistEntry("old", nil))
	next := &Manager{store: db, entries: map[string]persistedEntry{}}
	require.NoError(t, next.loadState())
	require.Empty(t, next.entries)
}

func TestDNSResponseCannotCrossEndpointIncarnation(t *testing.T) {
	for _, replacement := range []string{"old", "replacement"} {
		t.Run(replacement, func(t *testing.T) {
			db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
			require.NoError(t, err)
			defer db.Close()
			m := &Manager{store: db, entries: map[string]persistedEntry{}, sourceIndex: map[string]string{}, iptables: &iptablesBackend{deleteConntrackForIP: func(net.IP) error { return nil }}}
			require.NoError(t, m.loadState())
			ip := net.ParseIP("10.88.0.2")
			require.NoError(t, m.Register(Binding{SandboxID: "old", IP: ip, HostVeth: "lo"}, Policy{}))
			old := m.entries["old"]
			upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			require.NoError(t, err)
			defer upstream.Close()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			upstreamDone := make(chan error, 1)
			go func() {
				buffer := make([]byte, 4096)
				n, peer, err := upstream.ReadFromUDP(buffer)
				if err != nil {
					upstreamDone <- err
					return
				}
				var reply dnsmessage.Message
				if err = reply.Unpack(buffer[:n]); err != nil {
					upstreamDone <- err
					return
				}
				reply.Header.Response = true
				response, err := reply.Pack()
				if err != nil {
					upstreamDone <- err
					return
				}
				close(entered)
				<-release
				_, err = upstream.WriteToUDP(response, peer)
				upstreamDone <- err
			}()
			request, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 17}, Questions: []dnsmessage.Question{{Name: testDNSName(t, "service.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
			require.NoError(t, err)
			proxy := &dnsProxy{upstreams: []string{upstream.LocalAddr().String()}, authorize: m.authorizeDNS, observe: m.observeDNS}
			response := make(chan []byte, 1)
			failure := make(chan error, 1)
			go func() { data, err := proxy.handle(ip, request, "udp"); response <- data; failure <- err }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("DNS request did not reach upstream")
			}
			require.NoError(t, m.Remove("old"))
			require.NoError(t, m.Register(Binding{SandboxID: replacement, IP: ip, HostVeth: "lo"}, Policy{}))
			next := m.entries[replacement]
			require.Equal(t, old.Generation, next.Generation, "empty-policy generations are both zero")
			require.NotEqual(t, old.Incarnation, next.Incarnation)
			unblock()
			require.NoError(t, <-upstreamDone)
			var reply dnsmessage.Message
			require.NoError(t, reply.Unpack(<-response))
			require.NoError(t, <-failure)
			require.Equal(t, dnsmessage.RCodeServerFailure, reply.Header.RCode)
			require.Empty(t, m.entries[replacement].DomainGrants)
			require.NoError(t, m.Remove(replacement))
		})
	}
}
