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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/metrics"
	"github.com/inclusionAI/sandboxd/internal/trace"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	// The side-effect import registers the public NAT backend before
	// InterfaceManager initialization while avoiding an import cycle.
	_ "github.com/inclusionAI/sandboxd/pkg/networkmanager/bridge"
	"github.com/inclusionAI/sandboxd/pkg/resourcemanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/inclusionAI/sandboxd/pkg/volumemanager"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pelletier/go-toml"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type SandboxService interface {
	runtime.SandboxServiceServer
	Run() error
	Shutdown()
	Ready() bool
	RegisterServer(*grpc.Server)
}

var _ SandboxService = &sandboxService{}

// sandboxService implements SandboxService.
type sandboxService struct {
	// config is the sandbox service config
	config         config.Config
	serviceHandler cmap.ConcurrentMap[string, svc.Handler]

	sandboxManager *sandbox.Manager

	// Resource and infrastructure managers owned by the server. SandboxManager
	// receives only the cgroup manager reference it needs for OOM monitoring;
	// allocation, release, and shutdown stay in server-owned managers.
	cgroupMgr    *cgroupmanager.CgroupManager
	interfaceMgr *networkmanager.InterfaceManager
	networkMgr   *networkManager
	resourceMod  *resourcemanager.Module
	imageMod     *imagemanager.Module
	volumeMgr    *volumemanager.Module

	store store.DbStore

	runtime.UnimplementedSandboxServiceServer

	fsMgr *fsManager

	ready         atomic.Bool
	recoveryReady atomic.Bool

	runscHostCgroupMemoryOverhead int64
}

// loadRuntimeHandlers loads runtime handlers with exponential backoff.
// It blocks until all configured runtimes are loaded or timeout is reached.
func (h *sandboxService) loadRuntimeHandlers() {
	logrus.Debugf("loading runtime handlers: %v", h.config.PluginConfig.RuntimeConfig.RuntimeBinary)

	// Disk path "containers" is retained for state-recovery compatibility.
	sandboxesRoot := filepath.Join(h.config.RootDir, "containers")
	if err := os.MkdirAll(sandboxesRoot, 0755); err != nil {
		logrus.Errorf("create sandboxes dir failed: %v", err)
	}

	const maxWait = 30 * time.Second
	backoff := 100 * time.Millisecond
	deadline := time.Now().Add(maxWait)

	for {
		allLoaded := true
		for runtimeName, runtimeBin := range h.config.PluginConfig.RuntimeConfig.RuntimeBinary {
			if h.config.DisableCgroup && runtimeName != config.RuntimeNameRunsc {
				logrus.Warnf(
					"runtime %v is not registered: experimental cgroup-disabled "+
						"mode currently supports only runsc",
					runtimeName,
				)
				continue
			}
			if h.serviceHandler.Has(runtimeName) {
				continue
			}
			handler, err := svc.NewHandler(h.config, runtimeBin, runtimeName)
			if err != nil {
				if runtimeName == config.RuntimeNameRunsc {
					logrus.Warnf("load required runtime %v handler failed: %v", runtimeName, err)
					allLoaded = false
				} else {
					// Optional runtimes are node capabilities. A node that does
					// not meet their host requirements remains ready and omits
					// them from ListAvailableRuntimes.
					logrus.Warnf("optional runtime %v is unavailable: %v", runtimeName, err)
				}
				continue
			}
			logrus.Infof("loaded runtime handler for %v", runtimeName)
			h.serviceHandler.Set(runtimeName, handler)
		}

		if allLoaded || time.Now().After(deadline) {
			if !allLoaded {
				logrus.Errorf("timeout waiting for runtime handlers after %v", maxWait)
			}
			return
		}

		time.Sleep(backoff)
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

func (h *sandboxService) Ready() bool {
	return h.Healthy()
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (h *sandboxService) startSandboxRuntime(
	ctx context.Context,
	runtimeName string,
	startConfig svc.StartConfig,
) (err error) {
	traceID, spanID := trace.GetContextID(ctx)
	start := time.Now()
	defer func() {
		if err != nil {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("StartSandbox failed, traceID: %v, spanId: %v, err: %v", traceID, spanID, err)
		}
	}()

	if err = h.checkRuntime(runtimeName); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("check runtime failed: %v", err)
		return fmt.Errorf("runtime %q is not available: %w", runtimeName, err)
	}

	handler, ok := h.serviceHandler.Get(runtimeName)
	if !ok {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}

	if startConfig.CgroupPath != "" {
		if h.cgroupMgr == nil {
			return errors.New("cgroup manager is not configured")
		}
		hostResources, resourceErr := svc.HostCgroupResources(
			runtimeName,
			startConfig.Resources,
			h.runscHostCgroupMemoryOverhead,
		)
		if resourceErr != nil {
			return fmt.Errorf("prepare host cgroup resources: %w", resourceErr)
		}
		if err = h.cgroupMgr.Prepare(startConfig.CgroupPath, hostResources); err != nil {
			return fmt.Errorf("prepare cgroup %s: %w", startConfig.CgroupPath, err)
		}
	}

	if err = handler.Start(ctx, startConfig); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler create sandbox failed: %v", err)
		h.sandboxManager.CleanSandboxRoot(startConfig.ID)
		return errord.ToGRPC(err)
	}

	logrus.WithField(trace.ContextKeyTraceId, traceID).Infof("StartSandbox %s success, traceID: %v, spanId: %v, cost: %v", startConfig.ID, traceID, spanID, time.Since(start).String())
	return nil
}

func (h *sandboxService) deleteSandboxRuntime(ctx context.Context, sandboxID string) (err error) {
	traceID, spanID := trace.GetContextID(ctx)
	start := time.Now()
	defer func() {
		if err != nil {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("DeleteSandbox %s failed, traceID: %v, spanId: %v, err: %v", sandboxID, traceID, spanID, err)
		} else {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Infof("DeleteSandbox %s success, traceID: %v, spanId: %v, cost: %v", sandboxID, traceID, spanID, time.Since(start).String())
		}
	}()

	c, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		return errord.ToGRPC(err)
	}

	if h.checkRuntime(c.Metadata.RuntimeHandler) != nil {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}

	handler, ok := h.serviceHandler.Get(c.Metadata.RuntimeHandler)
	if !ok {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}

	resource, err := h.sandboxManager.CollectResourceByID(sandboxID)
	if err != nil {
		return err
	}

	err = handler.Delete(ctx, sandboxID)
	if err != nil && !errors.Is(err, errord.ErrNotFound) {
		metrics.RecordRuntimeCallResult("delete", "failed", c.Metadata.RuntimeHandler)
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler force delete sandbox failed: %v", err)
		return errord.ToGRPC(err)
	}
	metrics.RecordRuntimeCallResult("delete", "success", c.Metadata.RuntimeHandler)

	if err := h.fsMgr.Release(sandboxID); err != nil {
		return err
	}
	if err := h.releaseStartResources(resource); err != nil {
		return err
	}

	h.sandboxManager.Delete(sandboxID)
	return nil
}

func (h *sandboxService) List(ctx context.Context, request *runtime.ListSandboxesRequest) (*runtime.ListSandboxesResponse, error) {
	var sandboxes []*sandbox.Sandbox
	response := new(runtime.ListSandboxesResponse)
	if request.ID != "" {
		sandboxes = h.sandboxManager.List(sandbox.ListFilterById(request.ID))
		if len(sandboxes) == 0 {
			return response, errord.ToGRPC(errord.ErrNotFound)
		}
	} else {
		sandboxes = h.sandboxManager.List(sandbox.ListFilterByLabels(request.Selector))
	}

	for idx := range sandboxes {
		c := sandboxes[idx]
		if c == nil || c.Status == nil || c.Metadata == nil {
			continue
		}
		response.Sandboxes = append(response.Sandboxes, &runtime.SandboxStatus{
			ID:           c.Metadata.ID,
			Runtime:      c.Metadata.RuntimeHandler,
			State:        c.Status.Get().State(),
			StartedAt:    util.MustInt64(c.Status.Get().StartedAt),
			FinishedAt:   util.MustInt64(c.Status.Get().FinishedAt),
			ExitCode:     c.Status.Get().ExitCode,
			Labels:       copyStringMap(c.Metadata.Labels),
			MetricLabels: copyStringMap(c.Metadata.MetricLabels),
			Stdout:       c.Metadata.Stdout,
			Stderr:       c.Metadata.Stderr,
		})
	}
	return response, nil
}

func (h *sandboxService) Stats(ctx context.Context, request *runtime.StatsRequest) (*runtime.StatsResponse, error) {
	if request.ID == "" {
		return nil, errord.ToGRPC(errord.ErrInvalidArgument)
	}
	if h.config.DisableCgroup {
		return nil, errord.ToGRPC(fmt.Errorf(
			"sandbox stats require per-sandbox cgroups: %w",
			errord.ErrFailedPrecondition,
		))
	}

	// Look up the sandbox to verify it exists.
	_, err := h.sandboxManager.Get(request.ID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}

	// Get the cgroup path from the sandbox's OCI spec.
	resource, err := h.sandboxManager.CollectResourceByID(request.ID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	cgroupPath, ok := resource.Resources[config.ResourceNameCgroup]
	if !ok || cgroupPath == "" {
		return nil, errord.ToGRPC(fmt.Errorf("cgroup path not found for sandbox %s", request.ID))
	}

	if h.cgroupMgr == nil {
		return nil, errord.ToGRPC(errors.New("cgroup manager is not configured"))
	}
	cgroupStats, err := h.cgroupMgr.Stats(cgroupPath)
	if err != nil {
		return nil, errord.ToGRPC(fmt.Errorf("stat cgroup %s failed: %v", cgroupPath, err))
	}

	return &runtime.StatsResponse{
		CpuUsageNs:          cgroupStats.CPUUsageNanos,
		CpuKernelNs:         cgroupStats.CPUKernelNanos,
		CpuUserNs:           cgroupStats.CPUUserNanos,
		MemoryUsageBytes:    cgroupStats.MemoryUsageBytes,
		MemoryLimitBytes:    cgroupStats.MemoryLimitBytes,
		MemoryMaxUsageBytes: cgroupStats.MemoryMaxUsageBytes,
	}, nil
}

// ListAvailableRuntimes returns a stable snapshot of runtime classes whose
// handlers initialized successfully. Configured classes that failed to load
// are absent from serviceHandler and therefore from this list.
func (h *sandboxService) ListAvailableRuntimes(
	_ context.Context,
	_ *runtime.ListAvailableRuntimesRequest,
) (*runtime.ListAvailableRuntimesResponse, error) {
	if !h.Healthy() {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "sandbox service is not ready")
	}
	runtimeClasses := h.serviceHandler.Keys()
	sort.Strings(runtimeClasses)

	return &runtime.ListAvailableRuntimesResponse{
		RuntimeClasses: runtimeClasses,
	}, nil
}

func (h *sandboxService) Run() error {
	logrus.Infof("sandbox service run at %s", h.config.RootDir)
	for {
		if err := h.imageMod.ReconcileRecoveredDaemons(); err != nil {
			logrus.WithError(err).Warn("distillfs recovery is incomplete; retrying")
			time.Sleep(time.Second)
			continue
		}
		break
	}
	h.recoveryReady.Store(true)
	h.sandboxManager.Start()
	return nil
}

func (h *sandboxService) Shutdown() {
	logrus.Info("sandbox service shutting down: cleaning up sandboxes")

	// 1. Force-delete all running sandboxes with per-sandbox timeout.
	sandboxes := h.sandboxManager.List()
	for _, c := range sandboxes {
		if c == nil || c.Metadata == nil {
			continue
		}
		id := c.Metadata.ID
		if h.networkMgr != nil {
			h.networkMgr.cleanupDnatRules(id)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := h.deleteSandboxRuntime(ctx, id); err != nil {
			logrus.Warnf("shutdown: failed to delete sandbox %s: %v", id, err)
		}
		cancel()

	}

	h.fsMgr.Shutdown()

	// 2. Stop sandbox manager (stops event loop + monitors).
	h.sandboxManager.Stop()

	// 3. Stop resource managers owned by the server.
	if h.cgroupMgr != nil {
		if err := h.cgroupMgr.ShutDown(); err != nil {
			logrus.Warnf("shutdown: failed to stop cgroup manager: %v", err)
		}
	}
	if h.interfaceMgr != nil {
		if err := h.interfaceMgr.ShutDown(); err != nil {
			logrus.Warnf("shutdown: failed to stop interface manager: %v", err)
		}
	}

	// Tear infrastructure modules down in reverse dependency order.
	// SandboxManager / runsc handlers are already torn down above;
	// here we drop the underlying infrastructure modules:
	//   ImageManager  -> drains distillfs + persists mount_records.db
	//   ResourceMod   -> closes /var/run/resource.sock + stops the K8s
	//                    watcher; safe to call even when Start was a no-op
	//   VolumeMgr     -> unmounts the XFS filestore
	if h.imageMod != nil {
		h.imageMod.Stop()
	}
	if h.resourceMod != nil {
		h.resourceMod.Stop()
	}
	if h.volumeMgr != nil {
		if err := h.volumeMgr.Stop(); err != nil {
			logrus.Warnf("shutdown: failed to unmount XFS filestore: %v", err)
		}
	}
	logrus.Info("sandbox service shutdown complete")
}

// Healthy aggregates each module's Healthy() signal into a single boolean
// for the process-level health endpoint. A module that has not
// been constructed (e.g. legacy code path) is treated as not unhealthy:
// only an explicit false from a live module flips the result.
func (h *sandboxService) Healthy() bool {
	if !h.recoveryReady.Load() || !h.ready.Load() {
		return false
	}
	if h.resourceMod != nil && !h.resourceMod.Healthy() {
		return false
	}
	if h.imageMod != nil && !h.imageMod.Healthy() {
		return false
	}
	if h.volumeMgr != nil && !h.volumeMgr.Healthy() {
		return false
	}
	return true
}

func (h *sandboxService) RegisterServer(server *grpc.Server) {
	runtime.RegisterSandboxServiceServer(server, h)
}

// NewSandboxService creates a new sandbox service.
// root is the working root directory; configPath is the path to config.toml.
// resetStateIfPodChanged wipes persisted state when sandboxd starts in a
// different pod than the one that wrote it. The hostname is used as the pod
// identity (k8s sets it to the pod name; same pod across in-sandbox service
// restarts, different pod across pod recreation). The stamp lives next to the
// bbolt store so it shares the state's lifetime.
//
// Without this, a recreated pod that reuses a hostPath volume would inherit
// the previous pod's registrations, sandbox OCI bundles, and bbolt
// buckets, causing register-with-same-name to silently no-op.
func resetStateIfPodChanged(storeDir, rootDir, imageManagerRoot string) error {
	current, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}
	stampPath := filepath.Join(storeDir, ".pod_host")
	if stored, err := os.ReadFile(stampPath); err == nil && string(stored) == current {
		return nil
	}

	logrus.Infof("pod identity changed (hostname=%q): wiping persisted state in %s, %s, %s", current, storeDir, rootDir, imageManagerRoot)
	if err := os.RemoveAll(storeDir); err != nil {
		return fmt.Errorf("remove storeDir %s: %w", storeDir, err)
	}
	// "containers" is the established on-disk directory name used by the
	// sandbox manager and runsc handler for state recovery.
	for _, sub := range []string{"containers"} {
		p := filepath.Join(rootDir, sub)
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	// Tie image-manager cleanup to the same pod-identity stamp as the rest of
	// sandboxd state so process restarts preserve mount recovery data.
	if imageManagerRoot != "" {
		if err := os.RemoveAll(imageManagerRoot); err != nil {
			return fmt.Errorf("remove imageManagerRoot %s: %w", imageManagerRoot, err)
		}
	}
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		return fmt.Errorf("recreate storeDir %s: %w", storeDir, err)
	}
	return os.WriteFile(stampPath, []byte(current), 0644)
}

func resetMetadataIfResourceStateIncompatible(storePath string) error {
	if _, err := os.Stat(storePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat metadata db %s: %w", storePath, err)
	}

	db := store.NewStoreImp(storePath)
	for _, key := range []string{config.CgroupBucket, config.BridgeIpBucket} {
		data, err := db.LoadRaw(key)
		if err != nil {
			if errord.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("load raw metadata bucket %s: %w", key, err)
		}

		var state struct {
			Items []string `json:"items"`
		}
		if err := json.Unmarshal(data, &state); err != nil {
			logrus.Warnf("metadata db %s has incompatible %s bucket (%v); removing stale db", storePath, key, err)
			if err := os.Remove(storePath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove incompatible metadata db %s: %w", storePath, err)
			}
			return nil
		}
	}
	return nil
}

func NewSandboxService(root, configPath string) (result SandboxService, retErr error) {
	// if root dir is not exist, create it
	if _, err := os.Stat(root); os.IsNotExist(err) {
		if err := os.MkdirAll(root, 0755); err != nil {
			return nil, err
		}
	}

	// read and unmarshal config.toml
	var cfg config.Config
	if configBytes, err := os.ReadFile(configPath); err != nil {
		return nil, err
	} else if err := toml.NewDecoder(bytes.NewReader(configBytes)).Decode(&cfg); err != nil {
		return nil, err
	}
	runscHostCgroupMemoryOverhead, err := config.ParseMemorySize(
		cfg.RuntimeConfig.RunscHostCgroupMemoryOverhead,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"runtime configuration: parse runsc_host_cgroup_memory_overhead %q: %w",
			cfg.RuntimeConfig.RunscHostCgroupMemoryOverhead,
			err,
		)
	}
	if runscHostCgroupMemoryOverhead < 0 {
		return nil, fmt.Errorf("runtime configuration: runsc_host_cgroup_memory_overhead must not be negative")
	}

	natBackend, err := resolveNATBackend(cfg.NatBackend)
	if err != nil {
		return nil, fmt.Errorf("network configuration: %w", err)
	}
	cfg.NatBackend = natBackend

	if err := resetStateIfPodChanged(cfg.StoreDir, cfg.RootDir, cfg.ImageManagerRoot); err != nil {
		return nil, fmt.Errorf("reset state on pod change: %w", err)
	}
	storePath := filepath.Join(cfg.StoreDir, "metadata.db")
	if err := resetMetadataIfResourceStateIncompatible(storePath); err != nil {
		return nil, fmt.Errorf("reset incompatible metadata: %w", err)
	}

	// The optional node-resource module comes up first so its external resource
	// socket is visible before image, volume, and sandbox initialization. Gated on
	// [plugin.node_resource]: deployments that don't report node resources
	// (e.g. standalone) omit the section and the module is skipped; when it is
	// configured, init/bind failure is fatal and lets systemd restart sandboxd.
	// Held in a local because s.resourceMod is back-filled once s exists below.
	var nodeResMod *resourcemanager.Module
	if cfg.SockPath != "" {
		sockPath := cfg.SockPath
		mod, merr := resourcemanager.NewModule(sockPath)
		if merr != nil {
			return nil, fmt.Errorf("node-resource module init: %w", merr)
		}
		if serr := mod.Start(); serr != nil {
			// NewModule already started the OTel collector's periodic-reader
			// goroutine; if Start then fails to bind /var/run/resource.sock we
			// must drain that collector so it doesn't outlive sandboxd's init.
			mod.Stop()
			return nil, fmt.Errorf("node-resource module start: %w", serr)
		}
		nodeResMod = mod
		logrus.Infof("node-resource module ready, sock=%s", sockPath)
		defer func() {
			if retErr != nil {
				mod.Stop()
			}
		}()
	} else {
		logrus.Infof("node-resource module disabled (no [plugin.node_resource] config)")
	}

	// Construct the in-process image manager before sandboxService so mount and
	// rootfs consumers share one Service. Initialization is fatal because
	// sandboxd cannot manage rootfs or S3/OCI mounts without it.
	imgMod, err := imagemanager.NewModule(imagemanager.Config{
		Root:              cfg.ImageManagerRoot,
		DistillFsBin:      cfg.DistillFsBin,
		OSSTemplate:       cfg.OSSTemplate,
		NydusTemplate:     cfg.NydusTemplate,
		NydusSuffix:       cfg.NydusSuffix,
		OSSAuthsPath:      cfg.OSSAuthsPath,
		RegistryAuthsPath: cfg.RegistryAuthsPath,
		CgroupMemoryLimit: cfg.CgroupMemoryLimit,
		DisableCgroup:     cfg.DisableCgroup,
	})
	if err != nil {
		return nil, fmt.Errorf("imagemanager: %w", err)
	}
	// On any subsequent init failure, roll infrastructure modules back in
	// reverse construction order. defer-LIFO gives the reverse-order
	// Clean up initialized modules if construction fails.
	// Without these, Restart=always would loop with leaked distillfs
	// goroutines / bbolt handles, an XFS mount still attached, and
	// resource-manager's OTel collector still pushing metrics.
	defer func() {
		if retErr != nil {
			imgMod.Stop()
		}
	}()
	imgSvc := imgMod.Service()

	stateStore := store.NewStoreImp(storePath)
	s := &sandboxService{
		config:                            cfg,
		store:                             stateStore,
		UnimplementedSandboxServiceServer: runtime.UnimplementedSandboxServiceServer{},
		serviceHandler:                    cmap.New[svc.Handler](),
		fsMgr:                             newFSManager(imgSvc, stateStore),
		imageMod:                          imgMod,
		resourceMod:                       nodeResMod,
		runscHostCgroupMemoryOverhead:     runscHostCgroupMemoryOverhead,
	}

	// VolumeManager comes up before runtime handlers. Failure to mount XFS is
	// not fatal because VolumeManager.Start can use the plain directory.
	s.volumeMgr = volumemanager.NewModule(cfg.RuntimeConfig.FilestoreDir, cfg.RuntimeConfig.FilestoreDirSize)
	if vErr := s.volumeMgr.Start(); vErr != nil {
		return nil, fmt.Errorf("volumemanager: %w", vErr)
	}
	defer func() {
		if retErr != nil {
			if vErr := s.volumeMgr.Stop(); vErr != nil {
				logrus.Warnf("init rollback: volumemanager Stop failed: %v", vErr)
			}
		}
	}()

	s.loadRuntimeHandlers()

	// Prepare resource modules directly. Each
	// pool runs its own single maintenance goroutine (demand-driven create +
	// periodic shrink), started inside its constructor. The pool ceiling is the
	// converged MaxSandboxLimit shared across cgroup and interface (1 sandbox =
	// 1 cgroup + 1 interface).
	maxSandboxLimit := networkmanager.MaxSandboxLimit(cfg.MaxInstanceNum)
	var cgroupMgr *cgroupmanager.CgroupManager
	if !cfg.DisableCgroup && cfg.CgroupCacheSize > 0 {
		cgroupMgr, err = cgroupmanager.NewCgroupManager(s.store, cfg.ResourceConfig, maxSandboxLimit)
		if err != nil {
			return nil, err
		}
		s.cgroupMgr = cgroupMgr
		metrics.RecordResourceGauge("cgroup", float64(cgroupMgr.CacheSizeLimit()))
		if nodeResMod != nil {
			nodeResMod.SetCgroupStatsReader(cgroupMgr.Stats)
		}
		defer func() {
			if retErr != nil {
				_ = cgroupMgr.ShutDown()
			}
		}()
	} else if cfg.DisableCgroup {
		logrus.Warn(
			"EXPERIMENTAL: cgroup management is disabled; only runsc is " +
				"available, and per-sandbox CPU, memory, and pids limits " +
				"are not enforced",
		)
	}

	var interfaceMgr *networkmanager.InterfaceManager
	if cfg.InterfaceCacheSize > 0 {
		interfaceMgr, err = networkmanager.NewInterfaceManager(
			s.store, cfg.IPRange, maxSandboxLimit, cfg.InterfaceCacheSize, cfg.NatBackend,
		)
		if err != nil {
			return nil, err
		}
		s.interfaceMgr = interfaceMgr
		metrics.RecordResourceGauge("interface", float64(interfaceMgr.CacheSizeLimit()))
		defer func() {
			if retErr != nil {
				_ = interfaceMgr.ShutDown()
			}
		}()
	}
	s.networkMgr = newNetworkManager(interfaceMgr, cfg.NatBackend)
	logrus.Debugf("resource modules init success with config: %v", cfg.PluginConfig.ResourceConfig)

	// create root dir if not exist
	if err = os.MkdirAll(cfg.RootDir, 0755); err != nil {
		return nil, err
	}

	healthChan := make(chan bool)

	if s.sandboxManager, err = sandbox.NewManager(
		cfg.RootDir,
		s.serviceHandler,
		healthChan,
		cgroupMgr,
		maxSandboxLimit,
	); err != nil {
		return nil, err
	}
	if nodeResMod != nil {
		nodeResMod.SetSandboxMetricsSource(s.sandboxManager)
		s.sandboxManager.OnSandboxStopped = nodeResMod.MarkSandboxStopped
	}
	if err := s.fsMgr.Restore(func(sandboxID string) bool {
		_, getErr := s.sandboxManager.Get(sandboxID)
		return getErr == nil
	}); err != nil {
		return nil, fmt.Errorf("restore sandbox filesystem state: %w", err)
	}

	// health check from sandbox manager housekeeping.
	go func() {
		for ready := range healthChan {
			s.ready.Store(ready)
		}
	}()

	return s, nil
}

func (h *sandboxService) Delete(ctx context.Context, request *runtime.DeleteRequest) (response *runtime.DeleteResponse, err error) {
	// Clean up DNAT rules before deleting sandbox
	h.networkMgr.cleanupDnatRules(request.ID)

	err = h.deleteSandboxRuntime(ctx, request.ID)
	return response, err
}

// resourcesToLinux converts a StartRequest.Resources map (CPU millicore, Memory MB)
// to LinuxSandboxResources. Returns defaults if the map is nil or empty.
func resourcesToLinux(resources map[string]float64) *runtime.LinuxSandboxResources {
	const (
		defaultCpuShares        = uint64(512)
		defaultMemoryLimitBytes = int64(4 * 1024 * 1024 * 1024) // 4GB
	)

	res := &runtime.LinuxSandboxResources{
		CpuShares:          defaultCpuShares,
		MemoryLimitInBytes: defaultMemoryLimitBytes,
	}

	if len(resources) == 0 {
		return res
	}

	if cpu, ok := resources["CPU"]; ok && cpu > 0 {
		// CPU is in millicore (1000 = 1 core). Convert to cpu.shares (1024 = 1 core).
		res.CpuShares = uint64(cpu * 1024 / 1000)
		if res.CpuShares < 2 {
			res.CpuShares = 2 // minimum cpu.shares
		}
	}

	if mem, ok := resources["Memory"]; ok && mem > 0 {
		// Memory is in MB.
		res.MemoryLimitInBytes = int64(mem * 1024 * 1024)
	}

	return res
}

type ExtraConfig struct {
	// NetworkStack selects the in-sandbox network stack. The open-source runsc
	// adapter supports gVisor netstack only; empty is treated as netstack.
	NetworkStack string `json:"networkStack,omitempty"`
}

type fsPrepareResult struct {
	fs  *preparedFS
	err error
}

type resourcePrepareResult struct {
	resources *preparedStartResources
	err       error
}

func (h *sandboxService) Start(ctx context.Context, request *runtime.StartRequest) (*runtime.StartResponse, error) {
	if request == nil {
		err := fmt.Errorf("start request is nil")
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
	}
	if !h.recoveryReady.Load() {
		err := errord.ToGRPCf(errord.ErrUnavailable, "distillfs recovery is incomplete")
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
	}
	startReq := proto.Clone(request).(*runtime.StartRequest)
	if startReq.Rootfs == nil {
		err := fmt.Errorf("rootfs is required")
		return &runtime.StartResponse{Code: -1, Message: err.Error()}, err
	}
	if startReq.Runtime == "" {
		startReq.Runtime = config.RuntimeNameRunsc
	}
	if startReq.Cwd == "" {
		startReq.Cwd = "/"
	}
	if startReq.Stdout == "" {
		logrus.Warnf("stdout path is empty for sandbox %q; discarding stdout to %s", startReq.SandboxID, os.DevNull)
		startReq.Stdout = os.DevNull
	}
	if startReq.Stderr == "" {
		logrus.Warnf("stderr path is empty for sandbox %q; discarding stderr to %s", startReq.SandboxID, os.DevNull)
		startReq.Stderr = os.DevNull
	}
	if startReq.Network == "" {
		startReq.Network = "sandbox"
	}
	if startReq.ExtraConfig != "" {
		var extraConfig ExtraConfig
		if err := json.Unmarshal([]byte(startReq.ExtraConfig), &extraConfig); err != nil {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("invalid extra config: %v", err),
			}, errord.ToGRPC(errord.ErrInvalidArgument)
		}
		if extraConfig.NetworkStack != "" && extraConfig.NetworkStack != "netstack" {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("unsupported network stack %q", extraConfig.NetworkStack),
			}, errord.ToGRPC(errord.ErrInvalidArgument)
		}
	}

	if err := h.checkRuntime(startReq.Runtime); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("runtime %q is not available: %v", startReq.Runtime, err),
		}, err
	}

	sandboxID, err := h.sandboxManager.ReserveID(startReq.SandboxID)
	if err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("failed to reserve sandbox id: %v", err),
		}, errord.ToGRPC(err)
	}
	startReq.SandboxID = sandboxID
	startSucceeded := false
	var preparedFilesystem *preparedFS
	var preparedResources *preparedStartResources
	var filesystemCommitted bool
	var runtimeStarted bool
	var dnatConfigured bool
	defer func() {
		if startSucceeded {
			return
		}
		if runtimeStarted {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			if handler, ok := h.serviceHandler.Get(startReq.Runtime); ok {
				if err := handler.Delete(cleanupCtx, sandboxID); err != nil {
					logrus.Warnf("rollback runtime for sandbox %s: %v", sandboxID, err)
				} else {
					h.sandboxManager.CleanSandboxRoot(sandboxID)
				}
			}
			cancel()
		}
		if dnatConfigured {
			h.networkMgr.cleanupDnatRules(sandboxID)
		}
		if filesystemCommitted {
			if err := h.fsMgr.Release(sandboxID); err != nil {
				logrus.Warnf("rollback filesystem state for sandbox %s: %v", sandboxID, err)
			}
		} else if preparedFilesystem != nil {
			preparedFilesystem.Rollback()
		}
		if preparedResources != nil {
			if err := h.releaseStartResources(preparedResources.OccupiedResource); err != nil {
				logrus.Warnf("rollback resources for sandbox %s: %v", sandboxID, err)
			}
		}
		h.sandboxManager.ReleaseID(sandboxID)
	}()

	fsCh := make(chan fsPrepareResult, 1)
	resourceCh := make(chan resourcePrepareResult, 1)
	go func() {
		preparedFS, err := h.fsMgr.Prepare(startReq)
		fsCh <- fsPrepareResult{fs: preparedFS, err: err}
	}()
	go func() {
		resources, err := h.prepareStartResources(startReq.Runtime, sandboxID)
		resourceCh <- resourcePrepareResult{resources: resources, err: err}
	}()

	fsResult := <-fsCh
	resourceResult := <-resourceCh
	preparedFilesystem = fsResult.fs
	preparedResources = resourceResult.resources
	if fsResult.err != nil || resourceResult.err != nil {
		err := errors.Join(fsResult.err, resourceResult.err)
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("failed to prepare sandbox: %v", err),
			ID:      "",
		}, err
	}

	// Rootfs env (from image mount) goes first with lowest priority; request
	// envs follow and override on key conflict because combineEnvs uses a map
	// where later entries win.
	rootfsEnvs := preparedFilesystem.rootfs.RootFS.Env()
	env := make([]*runtime.KeyValue, 0, len(rootfsEnvs)+len(startReq.Envs))
	for _, e := range rootfsEnvs {
		if parts := strings.SplitN(e, "=", 2); len(parts) == 2 {
			env = append(env, &runtime.KeyValue{
				Key:   parts[0],
				Value: parts[1],
			})
		}
	}
	for k, v := range startReq.Envs {
		env = append(env, &runtime.KeyValue{
			Key:   k,
			Value: v,
		})
	}

	annotations := copyStringMap(startReq.Labels)
	if annotations == nil {
		annotations = make(map[string]string)
	}
	for key, value := range preparedResources.ToLabels() {
		annotations[key] = value
	}

	sandboxResources := resourcesToLinux(startReq.Resources)
	if h.config.DisableCgroup {
		sandboxResources = nil
	}
	runtimeConfig := svc.StartConfig{
		ID:            sandboxID,
		Command:       startReq.Command,
		Rootfs:        preparedFilesystem.RootfsPath(),
		Resources:     sandboxResources,
		Mounts:        preparedFilesystem.Mounts(),
		Envs:          env,
		Stdout:        startReq.Stdout,
		Stderr:        startReq.Stderr,
		Cwd:           startReq.Cwd,
		CgroupPath:    preparedResources.Resources[config.ResourceNameCgroup],
		Annotations:   annotations,
		Network:       preparedResources.network,
		DisableCgroup: h.config.DisableCgroup,
	}
	if err := h.startSandboxRuntime(ctx, startReq.Runtime, runtimeConfig); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to start: %v", err),
			ID:      "",
		}, err
	}
	runtimeStarted = true

	// If Ports are specified, set up DNAT rules using sandbox IP from startSandboxRuntime.
	if len(startReq.Ports) > 0 {
		if preparedResources.sandboxIP == "" {
			return &runtime.StartResponse{
				Code:    -1,
				Message: "Failed to get sandbox IP for DNAT",
			}, errors.New("sandbox IP not available")
		}
		if err := h.networkMgr.setupDnatRules(sandboxID, startReq.Ports, preparedResources.sandboxIP); err != nil {
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("Failed to setup DNAT rules: %v", err),
			}, err
		}
		dnatConfigured = true
	}

	if err := h.fsMgr.Commit(sandboxID, preparedFilesystem); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to commit filesystem state: %v", err),
		}, err
	}
	filesystemCommitted = true
	metadata := &runtime.SandboxMetadata{
		ID:             sandboxID,
		RuntimeHandler: startReq.Runtime,
		Labels:         copyStringMap(startReq.Labels),
		MetricLabels:   copyStringMap(startReq.MetricLabels),
		Stdout:         startReq.Stdout,
		Stderr:         startReq.Stderr,
	}
	if err := h.sandboxManager.StoreMetadata(sandboxID, metadata); err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to persist sandbox metadata: %v", err),
		}, err
	}
	h.sandboxManager.ReceiveEvent(sandbox.Event{
		Type:      sandbox.EventTypeCreate,
		MetaData:  metadata,
		SandboxID: sandboxID,
	})
	startSucceeded = true
	return &runtime.StartResponse{
		Code:    0,
		Message: "Succeed",
		ID:      sandboxID,
	}, nil
}

func (h *sandboxService) Wait(ctx context.Context, request *runtime.WaitRequest) (*runtime.WaitResponse, error) {
	// Route Wait through the sandbox manager so the response observes the
	// terminal status that sandboxd has already persisted (set by the per-
	// sandbox monitor goroutine in sandbox.Manager.__startMonitor).
	// This avoids a second runc/runsc Wait and gives a consistent
	// happens-before edge for any state derived from the exit, e.g. the
	// OOM-kill reason embedded in WaitResponse.Message below.
	s, err := h.sandboxManager.WaitForExit(ctx, request.ID)
	if err != nil {
		return new(runtime.WaitResponse), errord.ToGRPC(err)
	}
	resp := &runtime.WaitResponse{ExitCode: s.ExitCode}
	if s.OOMKilled {
		resp.Message = "sandbox was oom-killed by the kernel (memory cgroup limit exceeded)"
	}
	return resp, nil
}
