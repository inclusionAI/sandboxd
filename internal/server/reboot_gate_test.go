package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRebootFencePersistsAndRejectsOldCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fence")
	g, err := loadRebootGate(path)
	require.NoError(t, err)
	const first = "00000000000000000001-00000000000000000000000000000001"
	const next = "00000000000000000002-00000000000000000000000000000002"
	var inventoryError error
	call := func(method, path string, want int) {
		t.Helper()
		out := httptest.NewRecorder()
		g.handler(func() error { return nil }, func(context.Context) error { return inventoryError }).ServeHTTP(out, httptest.NewRequest(method, path, nil))
		require.Equal(t, want, out.Code, out.Body.String())
	}
	call("GET", "/available", http.StatusNoContent)
	require.True(t, g.enter())
	call("PUT", "/close/"+first, http.StatusNoContent)
	call("GET", "/drained/"+first, http.StatusConflict)
	h := &sandboxService{rebootGate: g}
	for _, req := range []*runtime.StartRequest{{}, {CheckpointInfo: &runtime.CheckpointInfo{CheckpointDir: "/unused"}}} {
		_, err := h.Start(context.Background(), req)
		require.Equal(t, codes.Unavailable, status.Code(err))
	}
	_, err = h.Checkpoint(context.Background(), &runtime.CheckpointRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))
	g.leave()
	inventoryError = errors.New("unknown runtime inventory")
	call("GET", "/drained/"+first, http.StatusServiceUnavailable)
	inventoryError = nil
	call("GET", "/drained/"+first, http.StatusNoContent)

	g, err = loadRebootGate(path)
	require.NoError(t, err)
	require.False(t, g.enter())
	call("PUT", "/open/"+next, http.StatusConflict)
	call("PUT", "/open/"+first, http.StatusNoContent)
	call("PUT", "/open/"+first, http.StatusNoContent)
	call("PUT", "/close/"+first, http.StatusConflict)
	call("PUT", "/close/"+next, http.StatusNoContent)
	call("PUT", "/open/"+next, http.StatusNoContent)
	call("PUT", "/close/"+first, http.StatusConflict)
	g, err = loadRebootGate(path)
	require.NoError(t, err)
	call("PUT", "/close/"+next, http.StatusConflict)
	require.True(t, g.enter())
	g.leave()
	require.NoError(t, os.WriteFile(path, []byte(`{"attempt":"`+first+`"}`), 0600))
	_, err = loadRebootGate(path)
	require.Error(t, err)
}

func TestRebootFenceRejectsPodResetDirectoryBeforeDeletingState(t *testing.T) {
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	require.NoError(t, os.Mkdir(storeDir, 0700))
	fence := filepath.Join(storeDir, "fence")
	g, err := loadRebootGate(fence)
	require.NoError(t, err)
	const attempt = "00000000000000000001-00000000000000000000000000000001"
	require.Equal(t, http.StatusNoContent, g.change(attempt, true))
	alias := filepath.Join(dir, "alias")
	require.NoError(t, os.Symlink(storeDir, alias))
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf("storeDir = %q\nrootDir = %q\n", storeDir, dir)), 0600))
	for _, path := range []string{fence, filepath.Join(alias, "fence")} {
		t.Setenv("AKERNEL_REBOOT_FENCE_PATH", path)
		_, err := NewSandboxService(dir, cfgPath)
		require.ErrorContains(t, err, "would be cleared")
		reloaded, err := loadRebootGate(fence)
		require.NoError(t, err)
		require.True(t, reloaded.closedAndIdle(attempt))
	}
}

func TestRebootDrainRejectsConcurrentRelease(t *testing.T) {
	g, err := loadRebootGate(filepath.Join(t.TempDir(), "fence"))
	require.NoError(t, err)
	const attempt = "00000000000000000001-00000000000000000000000000000001"
	require.Equal(t, http.StatusNoContent, g.change(attempt, true))
	out := httptest.NewRecorder()
	g.handler(func() error { return nil }, func(context.Context) error {
		require.Equal(t, http.StatusNoContent, g.change(attempt, false))
		return nil
	}).ServeHTTP(out, httptest.NewRequest("GET", "/drained/"+attempt, nil))
	require.Equal(t, http.StatusConflict, out.Code)
}

func TestRebootInventoryRejectsUnloadedOptionalRuntime(t *testing.T) {
	gate, err := loadRebootGate(filepath.Join(t.TempDir(), "fence"))
	require.NoError(t, err)
	h := &sandboxService{
		rebootGate:     gate,
		cgroupMgr:      &cgroupmanager.CgroupManager{},
		sandboxManager: &sandbox.Manager{},
		serviceHandler: cmap.New[svc.Handler](),
	}
	h.ready.Store(true)
	h.recoveryReady.Store(true)
	h.config.RuntimeConfig.RuntimeBinary = map[string]string{config.RuntimeNameFirecracker: "/missing"}
	out := httptest.NewRecorder()
	h.RebootHandler().ServeHTTP(out, httptest.NewRequest("GET", "/available", nil))
	require.Equal(t, http.StatusServiceUnavailable, out.Code)
	require.Contains(t, out.Body.String(), "runtime firecracker inventory unavailable")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.ErrorContains(t, h.rebootInventoryEmpty(ctx), "runtime firecracker inventory unavailable")
	h.serviceHandler.Set(config.RuntimeNameFirecracker, svc.NewFakeRuntimeHandler())
	out = httptest.NewRecorder()
	h.RebootHandler().ServeHTTP(out, httptest.NewRequest("GET", "/available", nil))
	require.Equal(t, http.StatusNoContent, out.Code)
}
