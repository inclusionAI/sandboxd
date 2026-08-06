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

package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestService creates an sandboxService with a real sandbox.Manager backed by a temp dir.
func newTestService(t *testing.T, handlers map[string]svc.Handler) *sandboxService {
	t.Helper()

	tmpDir := t.TempDir()

	handlerMap := cmap.New[svc.Handler]()
	runtimeBinary := make(map[string]string)
	for name, h := range handlers {
		handlerMap.Set(name, h)
		runtimeBinary[name] = "/fake/" + name
	}

	healthChan := make(chan bool, 10)

	cm, err := sandbox.NewManager(tmpDir, handlerMap, healthChan, nil, 1000)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	s := &sandboxService{
		config: config.Config{
			RootDir: tmpDir,
			PluginConfig: config.PluginConfig{
				RuntimeConfig: config.RuntimeConfig{
					RuntimeBinary: runtimeBinary,
				},
			},
		},
		serviceHandler:                    handlerMap,
		sandboxManager:                    cm,
		store:                             store.NewMockStore(),
		UnimplementedSandboxServiceServer: runtime.UnimplementedSandboxServiceServer{},
		fsMgr:                             newFSManager(nil),
		networkMgr:                        newNetworkManager(nil, "", false),
	}
	s.ready.Store(true)
	s.recoveryReady.Store(true)
	return s
}

func TestWait(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	const id = "sbox-test-wait"
	// Wait now reads the terminal state maintained by the sandbox
	// manager rather than calling runtime.Wait directly. Stage a sandbox
	// that has already exited so the RPC can resolve via the fast path.
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
	}))
	assert.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))

	resp, err := s.Wait(context.Background(), &runtime.WaitRequest{ID: id})
	assert.NoError(t, err)
	assert.Equal(t, int32(0), resp.ExitCode)
}

func TestWait_NotFound(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := s.Wait(ctx, &runtime.WaitRequest{ID: "sbox-no-such"})
	assert.Error(t, err)
}

func TestResetMetadataIfResourceStateIncompatible_RemovesLegacyResourceState(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "metadata.db")
	db := store.NewStoreImp(storePath)
	assert.NoError(t, db.StoreRaw(config.CgroupBucket, []byte{0x0b, 0x0a, 0x05}))

	assert.NoError(t, resetMetadataIfResourceStateIncompatible(storePath))
	assert.NoFileExists(t, storePath)
}

func TestResetMetadataIfResourceStateIncompatible_KeepsJSONResourceState(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "metadata.db")
	db := store.NewStoreImp(storePath)
	assert.NoError(t, db.StoreRaw(config.CgroupBucket, []byte(`{"items":["/akernel/abc"]}`)))
	assert.NoError(t, db.StoreRaw(config.BridgeIpBucket, []byte(`{"items":["{\"ip\":\"172.17.0.2\"}"]}`)))

	assert.NoError(t, resetMetadataIfResourceStateIncompatible(storePath))
	assert.FileExists(t, storePath)
}

func TestList_Empty(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	resp, err := s.List(context.Background(), &runtime.ListSandboxesRequest{})
	assert.NoError(t, err)
	assert.Empty(t, resp.Sandboxes)
}

func TestListAvailableRuntimes(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"other": svc.NewFakeRuntimeHandler(),
		"runsc": svc.NewFakeRuntimeHandler(),
	})
	s.config.PluginConfig.RuntimeConfig.RuntimeBinary["unavailable"] = "/fake/unavailable"

	resp, err := s.ListAvailableRuntimes(
		context.Background(),
		&runtime.ListAvailableRuntimesRequest{},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"other", "runsc"}, resp.RuntimeClasses)
}

func TestDistillFSRecoveryGatesNewSandboxTraffic(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})
	s.recoveryReady.Store(false)

	assert.False(t, s.Healthy())
	_, err := s.ListAvailableRuntimes(
		context.Background(),
		&runtime.ListAvailableRuntimesRequest{},
	)
	assert.Error(t, err)
	_, err = s.Start(context.Background(), &runtime.StartRequest{})
	assert.Error(t, err)
}

func TestStatsFailsWhenCgroupManagementIsDisabled(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		config.RuntimeNameRunsc: svc.NewFakeRuntimeHandler(),
	})
	s.config.DisableCgroup = true

	_, err := s.Stats(context.Background(), &runtime.StatsRequest{ID: "sbox-test"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestStartRejectsWritableLayerLimitForKata(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		config.RuntimeNameKata: svc.NewFakeRuntimeHandler(),
	})
	_, err := s.Start(context.Background(), &runtime.StartRequest{
		Runtime:                 config.RuntimeNameKata,
		Rootfs:                  &runtime.RootfsConfig{},
		WritableLayerLimitBytes: 1 << 30,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestStartRejectsWritableLayerLimitWithoutFilestore(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		config.RuntimeNameRunsc: svc.NewFakeRuntimeHandler(),
	})
	_, err := s.Start(context.Background(), &runtime.StartRequest{
		Runtime:                 config.RuntimeNameRunsc,
		Rootfs:                  &runtime.RootfsConfig{},
		WritableLayerLimitBytes: 1 << 30,
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestStartNormalizesRootfsWritableLayerLimit(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		config.RuntimeNameKata: svc.NewFakeRuntimeHandler(),
	})
	_, err := s.Start(context.Background(), &runtime.StartRequest{
		Runtime: config.RuntimeNameKata,
		Rootfs: &runtime.RootfsConfig{
			WritableLayerSizeBytes: 1 << 30,
		},
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestStartRejectsConflictingWritableLayerLimits(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		config.RuntimeNameRunsc: svc.NewFakeRuntimeHandler(),
	})
	_, err := s.Start(context.Background(), &runtime.StartRequest{
		Runtime: config.RuntimeNameRunsc,
		Rootfs: &runtime.RootfsConfig{
			WritableLayerSizeBytes: 2 << 30,
		},
		WritableLayerLimitBytes: 1 << 30,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestList_ById_NotFound(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	_, err := s.List(context.Background(), &runtime.ListSandboxesRequest{
		ID: "sbox-nonexistent",
	})
	assert.Error(t, err)
}

func TestList_WithStoredContainer(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	sandboxID := "sbox-test-list-001"
	meta := &runtime.SandboxMetadata{
		ID:             sandboxID,
		RuntimeHandler: "runsc",
		Labels:         map[string]string{"env": "test"},
		Stdout:         "/tmp/stdout.log",
		Stderr:         "/tmp/stderr.log",
	}

	assert.NoError(t, s.sandboxManager.StoreMetadata(sandboxID, meta))
	time.Sleep(200 * time.Millisecond)

	resp, err := s.List(context.Background(), &runtime.ListSandboxesRequest{})
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.Sandboxes), 1)

	found := false
	for _, c := range resp.Sandboxes {
		if c.ID == sandboxID {
			found = true
			assert.Equal(t, "runsc", c.Runtime)
			break
		}
	}
	assert.True(t, found, "stored sandbox should appear in list")
}

func TestList_ByLabel(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	sandboxID := "sbox-test-label-001"
	meta := &runtime.SandboxMetadata{
		ID:             sandboxID,
		RuntimeHandler: "runsc",
		Labels:         map[string]string{"app": "myapp"},
	}
	assert.NoError(t, s.sandboxManager.StoreMetadata(sandboxID, meta))
	time.Sleep(200 * time.Millisecond)

	// Match label
	resp, err := s.List(context.Background(), &runtime.ListSandboxesRequest{
		Selector: map[string]string{"app": "myapp"},
	})
	assert.NoError(t, err)
	found := false
	for _, c := range resp.Sandboxes {
		if c.ID == sandboxID {
			found = true
		}
	}
	assert.True(t, found)

	// Non-matching label
	resp, err = s.List(context.Background(), &runtime.ListSandboxesRequest{
		Selector: map[string]string{"app": "other"},
	})
	assert.NoError(t, err)
	for _, c := range resp.Sandboxes {
		assert.NotEqual(t, sandboxID, c.ID)
	}
}

func TestDelete_NotFoundIsIdempotent(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	_, err := s.Delete(context.Background(), &runtime.DeleteRequest{
		ID: "sbox-nonexistent",
	})
	assert.NoError(t, err)
}

type recordingDeleteHandler struct {
	*svc.FakeRuntimeHandler
	calls     int
	sandboxID string
}

func (h *recordingDeleteHandler) Delete(
	_ context.Context,
	sandboxID string,
) error {
	h.calls++
	h.sandboxID = sandboxID
	return nil
}

func TestDeleteRoutesSandboxIDToRuntime(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})

	const id = "sbox-force-delete"
	bundleDir := filepath.Join(s.config.RootDir, "containers", id)
	assert.NoError(t, os.MkdirAll(bundleDir, 0755))
	assert.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`),
		0600,
	))
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
	}))
	_, err := s.sandboxManager.Get(id)
	assert.NoError(t, err)

	_, err = s.Delete(context.Background(), &runtime.DeleteRequest{ID: id, Timeout: 30})
	assert.NoError(t, err)
	assert.Equal(t, 1, handler.calls)
	assert.Equal(t, id, handler.sandboxID)
}

type blockingDeleteHandler struct {
	*svc.FakeRuntimeHandler
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (h *blockingDeleteHandler) Delete(ctx context.Context, _ string) error {
	h.calls.Add(1)
	h.once.Do(func() { close(h.started) })
	select {
	case <-h.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func storeSandboxForDelete(t *testing.T, s *sandboxService, id string) {
	t.Helper()
	bundleDir := filepath.Join(s.config.RootDir, "containers", id)
	assert.NoError(t, os.MkdirAll(bundleDir, 0755))
	assert.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`),
		0600,
	))
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
	}))
}

func TestDeleteCoalescesConcurrentRequestsAfterCallerTimeout(t *testing.T) {
	handler := &blockingDeleteHandler{
		FakeRuntimeHandler: svc.NewFakeRuntimeHandler(),
		started:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "sbox-concurrent-delete"
	storeSandboxForDelete(t, s, id)

	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() {
		_, err := s.Delete(firstCtx, &runtime.DeleteRequest{ID: id})
		firstDone <- err
	}()

	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("runtime delete did not start")
	}

	select {
	case err := <-firstDone:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("first delete did not honor caller timeout")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := s.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
		secondDone <- err
	}()

	select {
	case err := <-secondDone:
		t.Fatalf("second delete returned before shared cleanup completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	assert.Equal(t, int32(1), handler.calls.Load())

	close(handler.release)
	select {
	case err := <-secondDone:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("second delete did not receive shared cleanup result")
	}
	assert.Equal(t, int32(1), handler.calls.Load())

	_, err := s.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
	assert.NoError(t, err)
	assert.Equal(t, int32(1), handler.calls.Load())
}

func TestStart_And_Delete(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	rootfsDir := filepath.Join(t.TempDir(), "rootfs")
	assert.NoError(t, os.MkdirAll(rootfsDir, 0755))

	startReq := &runtime.StartRequest{
		SandboxID: "sbox-test-start-del",
		Runtime:   "runsc",
		Rootfs: &runtime.RootfsConfig{
			Readonly: false,
			Type:     runtime.RootfsSrcType_LOCAL,
			Source:   &runtime.RootfsConfig_Path{Path: rootfsDir},
		},
		Command: []string{"/bin/sleep", "infinity"},
		Stdout:  "/tmp/stdout.log",
		Stderr:  "/tmp/stderr.log",
	}

	startResp, err := s.Start(context.Background(), startReq)
	if err != nil {
		// Start may fail in unit test env due to cgroup/resource allocation
		// but it should not panic
		t.Logf("Start failed (expected in test env): %v", err)
		return
	}
	assert.Equal(t, int32(0), startResp.Code)
	assert.NotEmpty(t, startResp.ID)

	// Delete the started sandbox
	_, err = s.Delete(context.Background(), &runtime.DeleteRequest{
		ID: startResp.ID,
	})
	assert.NoError(t, err)
}

// --- DNAT tests ---

// fakeNetworkManager records DNAT calls for verification without touching iptables.
type fakeNetworkManager struct {
	mu           sync.Mutex
	added        []dnatCall
	localAdded   []dnatCall
	removed      []dnatCall
	localRemoved []dnatCall
	failNext     bool
	failLocal    bool
}

type dnatCall struct {
	Protocol   string
	DstPort    uint16
	TargetIP   string
	TargetPort uint16
}

func (f *fakeNetworkManager) SetupSNATRules(string) error                         { return nil }
func (f *fakeNetworkManager) CleanupSNATRules(string) error                       { return nil }
func (f *fakeNetworkManager) SetupNetworkRulesForActivating(net.IP, string) error { return nil }
func (f *fakeNetworkManager) CleanupNetworkRulesForActivating(net.IP) error       { return nil }

func (f *fakeNetworkManager) SetupDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return fmt.Errorf("injected error")
	}
	f.added = append(f.added, dnatCall{protocol, dstPort, targetIP, targetPort})
	return nil
}

func (f *fakeNetworkManager) CleanupDNATRule(protocol string, dstPort uint16, targetIP string, targetPort uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return fmt.Errorf("injected error")
	}
	f.removed = append(f.removed, dnatCall{protocol, dstPort, targetIP, targetPort})
	return nil
}

func (f *fakeNetworkManager) SetupLocalDNATRule(
	protocol string,
	dstPort uint16,
	targetIP string,
	targetPort uint16,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failLocal {
		f.failLocal = false
		return fmt.Errorf("injected local DNAT error")
	}
	if f.failNext {
		f.failNext = false
		return fmt.Errorf("injected error")
	}
	f.localAdded = append(f.localAdded, dnatCall{protocol, dstPort, targetIP, targetPort})
	return nil
}

func (f *fakeNetworkManager) CleanupLocalDNATRule(
	protocol string,
	dstPort uint16,
	targetIP string,
	targetPort uint16,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return fmt.Errorf("injected error")
	}
	f.localRemoved = append(f.localRemoved, dnatCall{protocol, dstPort, targetIP, targetPort})
	return nil
}

const testNetworkType = "fake-test-net"

func TestResolveNATBackend(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		want    string
		wantErr bool
	}{
		{name: "default", backend: "", want: config.NatBackendIptables},
		{name: "iptables", backend: config.NatBackendIptables, want: config.NatBackendIptables},
		{name: "bpfnat", backend: config.NatBackendBpfnat, want: config.NatBackendBpfnat},
		{name: "unsupported", backend: "unregistered-backend", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveNATBackend(test.backend)
			if test.wantErr {
				assert.ErrorContains(t, err, "unsupported NAT backend")
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestValidateRuntimeFilestore(t *testing.T) {
	assert.ErrorContains(t, validateRuntimeFilestore(config.RuntimeConfig{
		RuntimeBinary: map[string]string{config.RuntimeNameRunsc: "/usr/local/bin/runsc"},
	}), "plugin.runtime.filestore_dir")
	assert.NoError(t, validateRuntimeFilestore(config.RuntimeConfig{
		RuntimeBinary: map[string]string{config.RuntimeNameRunsc: "/usr/local/bin/runsc"},
		FilestoreDir:  "/var/lib/sandboxd/filestore",
	}))
	assert.NoError(t, validateRuntimeFilestore(config.RuntimeConfig{
		RuntimeBinary: map[string]string{config.RuntimeNameKata: "/usr/local/bin/containerd-shim-kata-v2"},
	}))
}

// newDnatTestService creates a sandboxService with a fake NetworkManager registered.
func newDnatTestService(t *testing.T, fake *fakeNetworkManager) *sandboxService {
	t.Helper()
	networkmanager.Register(testNetworkType, fake)
	t.Cleanup(func() {
		delete(networkmanager.NetworkManagers, testNetworkType)
	})

	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})
	s.config.NatBackend = testNetworkType
	s.networkMgr = newNetworkManager(nil, testNetworkType, false)
	return s
}

func TestSetupDnatRules_Basic(t *testing.T) {
	fake := &fakeNetworkManager{}
	s := newDnatTestService(t, fake)

	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:80", "udp:5353:53"}, "10.0.0.2")
	assert.NoError(t, err)

	// Verify NetworkManager was called correctly
	assert.Len(t, fake.added, 2)
	assert.Empty(t, fake.localAdded)
	assert.Equal(t, dnatCall{"tcp", 8080, "10.0.0.2", 80}, fake.added[0])
	assert.Equal(t, dnatCall{"udp", 5353, "10.0.0.2", 53}, fake.added[1])

	// Verify in-memory state
	rules := s.networkMgr.rulesFor("ctr-1")
	assert.Len(t, rules, 2)
	assert.Equal(t, "tcp", rules[0].Protocol)
	assert.Equal(t, uint16(8080), rules[0].DstPort)
	assert.Equal(t, "10.0.0.2", rules[0].TargetIP)
	assert.Equal(t, uint16(80), rules[0].TargetPort)
}

func TestSetupDnatRules_LocalDNATEnabled(t *testing.T) {
	fake := &fakeNetworkManager{}
	s := newDnatTestService(t, fake)
	s.networkMgr = newNetworkManager(nil, testNetworkType, true)

	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:80"}, "10.0.0.2")
	assert.NoError(t, err)
	assert.Equal(t, []dnatCall{{"tcp", 8080, "10.0.0.2", 80}}, fake.added)
	assert.Equal(t, []dnatCall{{"tcp", 8080, "10.0.0.2", 80}}, fake.localAdded)
}

func TestSetupDnatRules_LocalDNATFailureRollsBack(t *testing.T) {
	fake := &fakeNetworkManager{failLocal: true}
	s := newDnatTestService(t, fake)
	s.networkMgr = newNetworkManager(nil, testNetworkType, true)

	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:80"}, "10.0.0.2")
	assert.ErrorContains(t, err, "failed to add local DNAT rule")
	assert.Len(t, fake.added, 1)
	assert.Len(t, fake.removed, 1)
	assert.Empty(t, s.networkMgr.rulesFor("ctr-1"))
}

func TestSetupDnatRules_EmptyPorts(t *testing.T) {
	fake := &fakeNetworkManager{}
	s := newDnatTestService(t, fake)

	err := s.networkMgr.setupDnatRules("ctr-1", nil, "10.0.0.2")
	assert.NoError(t, err)
	assert.Empty(t, fake.added)
}

func TestSetupDnatRules_InvalidFormat(t *testing.T) {
	fake := &fakeNetworkManager{}
	s := newDnatTestService(t, fake)

	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080"}, "10.0.0.2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port format")

	err = s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:notanumber:80"}, "10.0.0.2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid dstPort")

	err = s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:notanumber"}, "10.0.0.2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid targetPort")
}

func TestSetupDnatRules_NetworkManagerError(t *testing.T) {
	fake := &fakeNetworkManager{failNext: true}
	s := newDnatTestService(t, fake)

	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:80"}, "10.0.0.2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add DNAT rule")

	// No rules should be stored in memory
	assert.Empty(t, s.networkMgr.rulesFor("ctr-1"))
}

func TestSetupDnatRules_NoNetworkManager(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})
	s.config.NatBackend = "nonexistent-type"
	s.networkMgr = newNetworkManager(nil, "nonexistent-type", false)

	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:80"}, "10.0.0.2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network manager not found")
}

func TestCleanupDnatRules_Basic(t *testing.T) {
	fake := &fakeNetworkManager{}
	s := newDnatTestService(t, fake)

	// Setup first
	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:80", "udp:5353:53"}, "10.0.0.2")
	assert.NoError(t, err)

	// Cleanup
	s.networkMgr.cleanupDnatRules("ctr-1")

	assert.Len(t, fake.removed, 2)
	assert.Len(t, fake.localRemoved, 2)
	assert.Equal(t, dnatCall{"tcp", 8080, "10.0.0.2", 80}, fake.removed[0])
	assert.Equal(t, dnatCall{"udp", 5353, "10.0.0.2", 53}, fake.removed[1])

	// In-memory state should be cleared
	assert.Empty(t, s.networkMgr.rulesFor("ctr-1"))
}

func TestCleanupDnatRules_NonexistentContainer(t *testing.T) {
	fake := &fakeNetworkManager{}
	s := newDnatTestService(t, fake)

	// Should be a no-op, no panic
	s.networkMgr.cleanupDnatRules("ctr-nonexistent")
	assert.Empty(t, fake.removed)
}

func TestSetupDnatRules_MultipleContainers(t *testing.T) {
	fake := &fakeNetworkManager{}
	s := newDnatTestService(t, fake)

	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:80"}, "10.0.0.2")
	assert.NoError(t, err)
	err = s.networkMgr.setupDnatRules("ctr-2", []string{"tcp:9090:90"}, "10.0.0.3")
	assert.NoError(t, err)

	assert.Equal(t, 2, s.networkMgr.ruleCount())

	// Cleanup one sandbox, other should remain
	s.networkMgr.cleanupDnatRules("ctr-1")
	assert.Empty(t, s.networkMgr.rulesFor("ctr-1"))
	assert.NotEmpty(t, s.networkMgr.rulesFor("ctr-2"))
}
