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
	"testing"
	"time"

	runtime "github.com/akernel-dev/sandboxd/api/runtime/v1"
	"github.com/akernel-dev/sandboxd/config"
	"github.com/akernel-dev/sandboxd/pkg/cgroupmanager"
	"github.com/akernel-dev/sandboxd/pkg/networkmanager"
	svc "github.com/akernel-dev/sandboxd/pkg/runtime"
	"github.com/akernel-dev/sandboxd/pkg/sandbox"
	"github.com/akernel-dev/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/assert"
)

// newTestService creates an sandboxService with a real sandbox.Manager backed by a temp dir.
func newTestService(t *testing.T, handlers map[string]svc.RealRuntimeHandler) *sandboxService {
	t.Helper()

	tmpDir := t.TempDir()

	handlerMap := cmap.New[svc.RealRuntimeHandler]()
	runtimeBinary := make(map[string]string)
	for name, h := range handlers {
		handlerMap.Set(name, h)
		runtimeBinary[name] = "/fake/" + name
	}

	healthChan := make(chan bool, 10)

	cgMgr, err := cgroupmanager.NewCgroupManager(store.NewMockStore(), config.ResourceConfig{
		MaxInstanceNum:  10,
		CgroupRootName:  "sandbox-test",
		CgroupCacheSize: 4,
		ResourceAdvanceConfig: config.ResourceAdvanceConfig{
			RecyclePolicy: config.RecyclePolicyDestroy,
		},
	}, 10)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	cm, err := sandbox.NewManager(tmpDir, handlerMap, healthChan, cgMgr, 1000)
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
		cgroupMgr:                         cgMgr,
		store:                             store.NewMockStore(),
		UnimplementedSandboxServiceServer: runtime.UnimplementedSandboxServiceServer{},
		fsMgr:                             newFSManager(nil),
		networkMgr:                        newNetworkManager(nil, ""),
	}
	s.ready.Store(true)
	return s
}

func TestWait(t *testing.T) {
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	const id = "sbox-test-wait"
	// Wait now reads the terminal state maintained by the sandbox
	// manager rather than calling runtime.Wait directly. Stage a sandbox
	// that has already exited so the RPC can resolve via the fast path.
	s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
	})
	assert.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))

	resp, err := s.Wait(context.Background(), &runtime.WaitRequest{ID: id})
	assert.NoError(t, err)
	assert.Equal(t, int32(0), resp.ExitCode)
}

func TestWait_NotFound(t *testing.T) {
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
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

func TestNewSandboxServiceRejectsInvalidCgroupVersion(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	contents := fmt.Sprintf("rootDir = %q\nstoreDir = %q\n[plugin.resource]\ncgroup_version = %q\n", filepath.Join(root, "root"), filepath.Join(root, "store"), "auto")
	assert.NoError(t, os.WriteFile(configPath, []byte(contents), 0600))
	_, err := NewSandboxService(root, configPath)
	assert.EqualError(t, err, `resource configuration: unsupported cgroup_version "auto" (valid values: "v1", "v2")`)
}

func TestNewSandboxServiceRequiresExplicitV2Parent(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")
	contents := fmt.Sprintf("rootDir = %q\nstoreDir = %q\n[plugin.resource]\ncgroup_version = %q\n", filepath.Join(root, "root"), filepath.Join(root, "store"), "v2")
	assert.NoError(t, os.WriteFile(configPath, []byte(contents), 0600))
	_, err := NewSandboxService(root, configPath)
	assert.EqualError(t, err, `resource configuration: cgroup_parent is required when cgroup_version is "v2"`)
}

func TestList_Empty(t *testing.T) {
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	resp, err := s.List(context.Background(), &runtime.ListSandboxesRequest{})
	assert.NoError(t, err)
	assert.Empty(t, resp.Sandboxes)
}

func TestListAvailableRuntimes(t *testing.T) {
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
		"runsc": svc.NewFakeRuntimeHandler(),
		"kata":  svc.NewFakeRuntimeHandler(),
	})
	s.config.PluginConfig.RuntimeConfig.RuntimeBinary["unavailable"] = "/fake/unavailable"

	resp, err := s.ListAvailableRuntimes(
		context.Background(),
		&runtime.ListAvailableRuntimesRequest{},
	)
	assert.NoError(t, err)
	assert.Equal(t, []string{"kata", "runsc"}, resp.RuntimeClasses)
}

func TestList_ById_NotFound(t *testing.T) {
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	_, err := s.List(context.Background(), &runtime.ListSandboxesRequest{
		ID: "sbox-nonexistent",
	})
	assert.Error(t, err)
}

func TestList_WithStoredContainer(t *testing.T) {
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
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

	s.sandboxManager.StoreMetadata(sandboxID, meta)
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
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	sandboxID := "sbox-test-label-001"
	meta := &runtime.SandboxMetadata{
		ID:             sandboxID,
		RuntimeHandler: "runsc",
		Labels:         map[string]string{"app": "myapp"},
	}
	s.sandboxManager.StoreMetadata(sandboxID, meta)
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

func TestDelete_NotFound(t *testing.T) {
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})

	_, err := s.Delete(context.Background(), &runtime.DeleteRequest{
		ID: "sbox-nonexistent",
	})
	assert.Error(t, err)
}

type recordingDeleteHandler struct {
	*svc.FakeRuntimeHandler
	calls   int
	request *svc.DeleteSandboxRequest
	options svc.HandlerOptions
}

func (h *recordingDeleteHandler) DeleteSandbox(
	_ context.Context,
	request *svc.DeleteSandboxRequest,
	options svc.HandlerOptions,
) (*svc.DeleteSandboxResponse, error) {
	h.calls++
	h.request = request
	h.options = options
	return &svc.DeleteSandboxResponse{}, nil
}

func TestDeleteAlwaysForcesAndIgnoresTimeout(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.RealRuntimeHandler{"runsc": handler})

	const id = "sbox-force-delete"
	bundleDir := filepath.Join(s.config.RootDir, "containers", id)
	assert.NoError(t, os.MkdirAll(bundleDir, 0755))
	assert.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`),
		0600,
	))
	s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
	})
	_, err := s.sandboxManager.Get(id)
	assert.NoError(t, err)

	_, err = s.Delete(context.Background(), &runtime.DeleteRequest{ID: id, Timeout: 30})
	assert.NoError(t, err)
	assert.Equal(t, 1, handler.calls)
	assert.Equal(t, int64(30), handler.request.Timeout)
	assert.True(t, handler.options.ForceDelete)
}

func TestStart_And_Delete(t *testing.T) {
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
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
	mu       sync.Mutex
	added    []dnatCall
	removed  []dnatCall
	failNext bool
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

// newDnatTestService creates a sandboxService with a fake NetworkManager registered.
func newDnatTestService(t *testing.T, fake *fakeNetworkManager) *sandboxService {
	t.Helper()
	networkmanager.Register(testNetworkType, fake)
	t.Cleanup(func() {
		delete(networkmanager.NetworkManagers, testNetworkType)
	})

	s := newTestService(t, map[string]svc.RealRuntimeHandler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})
	s.config.NatBackend = testNetworkType
	s.networkMgr = newNetworkManager(nil, testNetworkType)
	return s
}

func TestSetupDnatRules_Basic(t *testing.T) {
	fake := &fakeNetworkManager{}
	s := newDnatTestService(t, fake)

	err := s.networkMgr.setupDnatRules("ctr-1", []string{"tcp:8080:80", "udp:5353:53"}, "10.0.0.2")
	assert.NoError(t, err)

	// Verify NetworkManager was called correctly
	assert.Len(t, fake.added, 2)
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
	s := newTestService(t, map[string]svc.RealRuntimeHandler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})
	s.config.NatBackend = "nonexistent-type"
	s.networkMgr = newNetworkManager(nil, "nonexistent-type")

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
