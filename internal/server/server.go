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
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/cgroupops"
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
	cg "github.com/containerd/cgroups/v3/cgroup1"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pelletier/go-toml"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type SandboxService interface {
	runtime.SandboxServiceServer
	// Closer is used by containerd to gracefully stop sandbox service.
	io.Closer

	Run() error

	ShutDown()

	Ready() bool
	RegisterServer(*grpc.Server)
}

var _ SandboxService = &sandboxService{}

// sandboxService implements SandboxService.
type sandboxService struct {
	// config is the sandbox service config
	config         config.Config
	serviceHandler cmap.ConcurrentMap[string, svc.RealRuntimeHandler]

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

	ready atomic.Bool
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
			if h.serviceHandler.Has(runtimeName) {
				continue
			}
			handler, err := svc.GetRuntimeHandler(h.config, runtimeBin, runtimeName, h.volumeMgr)
			if err != nil {
				logrus.Warnf("load runtime %v handler failed: %v", runtimeName, err)
				allLoaded = false
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

func (h *sandboxService) startSandboxRuntime(ctx context.Context, request *svc.StartSandboxRequest, networkStack string, resources *preparedStartResources) (*svc.StartSandboxResponse, error) {
	traceID, spanID := trace.GetContextID(ctx)
	response := new(svc.StartSandboxResponse)
	start := time.Now()
	var err error
	defer func() {
		if err != nil {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("StartSandbox failed, traceID: %v, spanId: %v, err: %v", traceID, spanID, err)
		}
	}()

	if err = h.checkRuntime(request.Runtime); err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("check runtime failed: %v", err)
		return response, fmt.Errorf("runtime %q is not available: %w", request.Runtime, err)
	}

	handler, ok := h.serviceHandler.Get(request.Runtime)
	if !ok {
		return response, errord.ToGRPC(errord.ErrNotImplemented)
	}

	metaData, err := handler.StartSandbox(ctx, request, svc.HandlerOptions{
		TraceID:   traceID.String(),
		SpanID:    spanID.String(),
		SandboxID: resources.ID,

		CgroupPath:            resources.Resources[config.ResourceNameCgroup],
		AdditionalAnnotations: resources.ToLabels(),
		NetworkStack:          networkStack,
	})
	if err != nil {
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler create sandbox failed: %v", err)
		h.sandboxManager.CleanSandboxRoot(resources.ID)
		// clean std file
		if metaData != nil {
			if err := os.RemoveAll(metaData.Stderr); err != nil {
				logrus.WithField(trace.ContextKeyTraceId, traceID).Warnf("clean std file failed: %v", err)
			}
			if err := os.RemoveAll(metaData.Stdout); err != nil {
				logrus.WithField(trace.ContextKeyTraceId, traceID).Warnf("clean std file failed: %v", err)
			}
		}
		return response, errord.ToGRPC(err)
	}

	response.ID = resources.ID

	h.sandboxManager.StoreMetadata(resources.ID, metaData)
	logrus.WithField(trace.ContextKeyTraceId, traceID).Infof("StartSandbox %s success, traceID: %v, spanId: %v, cost: %v", resources.ID, traceID, spanID, time.Since(start).String())

	go h.sandboxManager.ReceiveEvent(sandbox.Event{
		Type:      sandbox.EventTypeCreate,
		MetaData:  metaData,
		SandboxID: resources.ID,
	})

	return response, nil
}

func (h *sandboxService) deleteSandboxRuntime(ctx context.Context, request *svc.DeleteSandboxRequest) (response *svc.DeleteSandboxResponse, err error) {
	traceID, spanID := trace.GetContextID(ctx)
	start := time.Now()
	defer func() {
		if err != nil {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("DeleteSandbox %s failed, traceID: %v, spanId: %v, err: %v", request.ID, traceID, spanID, err)
		} else {
			logrus.WithField(trace.ContextKeyTraceId, traceID).Infof("DeleteSandbox %s success, traceID: %v, spanId: %v, cost: %v", request.ID, traceID, spanID, time.Since(start).String())
		}
	}()

	c, err := h.sandboxManager.Get(request.ID)
	if err != nil {
		return response, errord.ToGRPC(err)
	}

	if h.checkRuntime(c.Metadata.RuntimeHandler) != nil {
		return response, errord.ToGRPC(errord.ErrNotImplemented)
	}

	handler, ok := h.serviceHandler.Get(c.Metadata.RuntimeHandler)
	if !ok {
		return response, errord.ToGRPC(errord.ErrNotImplemented)
	}

	resource, err := h.sandboxManager.CollectResourceByID(request.ID)
	if err != nil {
		return response, err
	}

	// TODO: implement graceful deletion using request.Timeout. The v0.1.0
	// contract is force-only, so timeout is intentionally ignored.
	response, err = handler.DeleteSandbox(ctx, request, svc.HandlerOptions{
		TraceID:               traceID.String(),
		SpanID:                spanID.String(),
		SandboxID:             request.ID,
		ForceDelete:           true,
		AdditionalAnnotations: c.Spec.Annotations,
	})
	if err != nil && !errors.Is(err, errord.ErrNotFound) {
		metrics.RecordRuntimeCallResult("delete", "failed", c.Metadata.RuntimeHandler)
		logrus.WithField(trace.ContextKeyTraceId, traceID).Errorf("runtime handler force delete sandbox failed: %v", err)
		return response, errord.ToGRPC(err)
	}
	metrics.RecordRuntimeCallResult("delete", "success", c.Metadata.RuntimeHandler)

	if err := h.releaseStartResources(resource); err != nil {
		return response, err
	}

	h.sandboxManager.Delete(request.ID)
	// clean c in goroutine.
	go h.sandboxManager.ReceiveEvent(sandbox.Event{
		Type:      sandbox.EventTypeDelete,
		SandboxID: request.ID,
	})

	return response, nil
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

	cgroupHandler := &cgroupops.CgroupHandlerImpl{}
	cgroup, err := cgroupHandler.Load(cg.StaticPath(cgroupPath), cg.WithHiearchy(cg.Default))
	if err != nil {
		return nil, errord.ToGRPC(fmt.Errorf("load cgroup %s failed: %v", cgroupPath, err))
	}

	metrics, err := cgroup.Stat()
	if err != nil {
		return nil, errord.ToGRPC(fmt.Errorf("stat cgroup %s failed: %v", cgroupPath, err))
	}

	resp := &runtime.StatsResponse{}
	if metrics.CPU != nil && metrics.CPU.Usage != nil {
		resp.CpuUsageNs = metrics.CPU.Usage.Total
		resp.CpuKernelNs = metrics.CPU.Usage.Kernel
		resp.CpuUserNs = metrics.CPU.Usage.User
	}
	if metrics.Memory != nil && metrics.Memory.Usage != nil {
		resp.MemoryUsageBytes = metrics.Memory.Usage.Usage
		resp.MemoryLimitBytes = metrics.Memory.Usage.Limit
		resp.MemoryMaxUsageBytes = metrics.Memory.Usage.Max
	}
	return resp, nil
}

// ListAvailableRuntimes returns a stable snapshot of runtime classes whose
// handlers initialized successfully. Configured classes that failed to load
// are absent from serviceHandler and therefore from this list.
func (h *sandboxService) ListAvailableRuntimes(
	_ context.Context,
	_ *runtime.ListAvailableRuntimesRequest,
) (*runtime.ListAvailableRuntimesResponse, error) {
	runtimeClasses := h.serviceHandler.Keys()
	sort.Strings(runtimeClasses)

	return &runtime.ListAvailableRuntimesResponse{
		RuntimeClasses: runtimeClasses,
	}, nil
}

func (h *sandboxService) Close() (err error) {
	defer func() {
		if err != nil {
			logrus.Errorf("close sandbox service failed: %v", err)
		} else {
			logrus.Info("close sandbox service success")
		}
	}()
	h.sandboxManager.Stop()
	return nil
}

func (h *sandboxService) Run() error {
	logrus.Infof("sandbox service run at %s", h.config.RootDir)
	h.sandboxManager.Start()
	return nil
}

func (h *sandboxService) ShutDown() {
	logrus.Info("sandbox service shutting down: cleaning up sandboxes")

	// 1. Force-delete all running sandboxes with per-sandbox timeout.
	sandboxes := h.sandboxManager.List()
	for _, c := range sandboxes {
		if c == nil || c.Metadata == nil {
			continue
		}
		id := c.Metadata.ID
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if _, err := h.deleteSandboxRuntime(ctx, &svc.DeleteSandboxRequest{ID: id}); err != nil {
			logrus.Warnf("shutdown: failed to delete sandbox %s: %v", id, err)
		}
		cancel()

		h.fsMgr.Release(id)
	}

	h.fsMgr.Shutdown()

	// 2. Shut down all runtime handlers. Must happen after sandboxes are
	// gone but before resource managers and XFS are torn down.
	for _, handler := range h.sandboxManager.Handlers() {
		handler.ShutDown()
	}

	// 3. Stop sandbox manager (stops event loop + monitors).
	h.sandboxManager.Stop()

	// 4. Stop resource managers owned by the server.
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
	if !h.ready.Load() {
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
	})
	if err != nil {
		return nil, fmt.Errorf("imagemanager: %w", err)
	}
	// On any subsequent init failure, roll infrastructure modules back in
	// reverse construction order. defer-LIFO gives the reverse-order
	// shutdown that mirrors ShutDown() without duplicating its body.
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
		serviceHandler:                    cmap.New[svc.RealRuntimeHandler](),
		fsMgr:                             newFSManager(imgSvc, stateStore),
		imageMod:                          imgMod,
		resourceMod:                       nodeResMod,
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
	if cfg.CgroupCacheSize > 0 {
		cgroupMgr, err = cgroupmanager.NewCgroupManager(s.store, cfg.ResourceConfig, maxSandboxLimit)
		if err != nil {
			return nil, err
		}
		s.cgroupMgr = cgroupMgr
		metrics.RecordResourceGauge("cgroup", float64(cgroupMgr.CacheSizeLimit()))
		defer func() {
			if retErr != nil {
				_ = cgroupMgr.ShutDown()
			}
		}()
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

	deleteSandboxRequest := &svc.DeleteSandboxRequest{
		ID:      request.ID,
		Timeout: request.Timeout,
	}

	_, err = h.deleteSandboxRuntime(ctx, deleteSandboxRequest)

	if err == nil {
		h.fsMgr.Release(request.ID)
	}

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
	idCommitted := false
	defer func() {
		if !idCommitted {
			h.sandboxManager.ReleaseID(sandboxID)
		}
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
	preparedFS := fsResult.fs
	preparedResources := resourceResult.resources

	fsCommitted := false
	defer func() {
		if !fsCommitted && preparedFS != nil {
			preparedFS.Rollback()
		}
	}()
	resourcesCommitted := false
	defer func() {
		if !resourcesCommitted && preparedResources != nil {
			if err := h.releaseStartResources(preparedResources.OccupiedResource); err != nil {
				logrus.Warnf("rollback resources for sandbox %s failed: %v", sandboxID, err)
			}
		}
	}()
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
	rootfsEnvs := preparedFS.rootfs.RootFS.Env()
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

	var networkStack string
	if startReq.ExtraConfig != "" {
		var extraConfig ExtraConfig
		err := json.Unmarshal([]byte(startReq.ExtraConfig), &extraConfig)
		if err != nil {
			logrus.Errorf("unmarshal extra config failed: %v, extra_config: %v", err, startReq.ExtraConfig)
		} else {
			logrus.Infof("unmarshal extra config success: %v, original extra_config: %v", extraConfig, startReq.ExtraConfig)
			networkStack = extraConfig.NetworkStack
		}
	}

	startSandboxRequest := &svc.StartSandboxRequest{
		Runtime: startReq.Runtime,
		Command: startReq.Command,
		Rootfs: &svc.Rootfs{
			Type:     "none",
			LowerDir: "",
			RootDir:  preparedFS.RootfsPath(),
		},
		Resource:     resourcesToLinux(startReq.Resources),
		Mounts:       preparedFS.Mounts(),
		Envs:         env,
		Network:      startReq.Network,
		Labels:       copyStringMap(startReq.Labels),
		MetricLabels: copyStringMap(startReq.MetricLabels),
		Stdout:       startReq.Stdout,
		Stderr:       startReq.Stderr,
		Cwd:          startReq.Cwd,
	}
	startSandboxResponse, err := h.startSandboxRuntime(ctx, startSandboxRequest, networkStack, preparedResources)
	if err != nil {
		return &runtime.StartResponse{
			Code:    -1,
			Message: fmt.Sprintf("Failed to start: %v", err),
			ID:      "",
		}, err
	}
	resourcesCommitted = true
	idCommitted = true

	// If Ports are specified, set up DNAT rules using sandbox IP from startSandboxRuntime.
	if len(startReq.Ports) > 0 {
		if preparedResources.sandboxIP == "" {
			h.deleteSandboxRuntime(ctx, &svc.DeleteSandboxRequest{
				ID:      startSandboxResponse.ID,
				Timeout: 0,
			})
			return &runtime.StartResponse{
				Code:    -1,
				Message: "Failed to get sandbox IP for DNAT",
			}, errors.New("sandbox IP not available")
		}
		if err := h.networkMgr.setupDnatRules(startSandboxResponse.ID, startReq.Ports, preparedResources.sandboxIP); err != nil {
			h.networkMgr.cleanupDnatRules(startSandboxResponse.ID)
			h.deleteSandboxRuntime(ctx, &svc.DeleteSandboxRequest{
				ID:      startSandboxResponse.ID,
				Timeout: 0,
			})
			return &runtime.StartResponse{
				Code:    -1,
				Message: fmt.Sprintf("Failed to setup DNAT rules: %v", err),
			}, err
		}
	}

	h.fsMgr.Commit(startSandboxResponse.ID, preparedFS)
	fsCommitted = true
	return &runtime.StartResponse{
		Code:    0,
		Message: "Succeed",
		ID:      startSandboxResponse.ID,
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
