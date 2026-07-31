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

// Package imagemanager owns image and mount lifecycle state in-process.
package imagemanager

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/nydus"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
)

// Config corresponds to the [plugin.image] sandboxd configuration section.
type Config struct {
	Root              string
	DistillFsBin      string
	OSSTemplate       string
	NydusTemplate     string
	NydusSuffix       string
	OSSAuthsPath      string
	RegistryAuthsPath string
	CgroupMemoryLimit string // human-readable: "512MiB" / "2GiB" / raw bytes; "0" / "" = no limit
	DisableCgroup     bool
}

// Module owns the in-process distillfs Manager, OCI manager and HttpWorker.
// Lifecycle:
//
//	cfg := imagemanager.Config{...}
//	mod, err := imagemanager.NewModule(cfg)
//	mod.Start()              // currently a no-op
//	svc := mod.Service()     // hand to sandboxd consumers (langrtmanager, imagemount)
//	... use svc ...
//	mod.Stop()
type Module struct {
	cfg        Config
	mgr        distillfs.Manager
	ociMgr     *oci.Manager
	worker     *api.HttpWorker
	closedOnce sync.Once
	healthy    atomic.Bool
}

// NewModule mirrors the standalone main.go setup: registry/nydus client
// init, distillfs manager init, OCI manager init, then HttpWorker over the
// shared mount_records.db. Failure of any stage is fatal — sandboxd cannot
// run sandboxes without image-mount plumbing.
func NewModule(cfg Config) (*Module, error) {
	if cfg.Root == "" {
		return nil, fmt.Errorf("imagemanager: Root is required")
	}
	if cfg.DistillFsBin == "" {
		cfg.DistillFsBin = "/usr/local/bin/distill_fs"
	}

	cgroupMemoryLimit, err := config.ParseMemorySize(cfg.CgroupMemoryLimit)
	if err != nil {
		return nil, fmt.Errorf("imagemanager: parse cgroup_memory_limit %q: %w", cfg.CgroupMemoryLimit, err)
	}

	var sharedRegistryClient *imageregistry.Client
	var nydusClient *nydus.RegistryClient
	if cfg.RegistryAuthsPath != "" {
		var rerr error
		sharedRegistryClient, rerr = imageregistry.NewClient(cfg.RegistryAuthsPath)
		if rerr != nil {
			logrus.Warnf("imagemanager: registry client init failed (%v); proceeding without registry auth", rerr)
		} else {
			nydusClient = nydus.NewRegistryClientFromShared(sharedRegistryClient)
		}
	}

	mgr, err := distillfs.NewManager(&distillfs.ManagerConfig{
		Context:           context.Background(),
		Root:              cfg.Root,
		OSSCfgPath:        cfg.OSSTemplate,
		NydusCfgPath:      cfg.NydusTemplate,
		BinPath:           cfg.DistillFsBin,
		NydusClient:       nydusClient,
		OSSAuthsPath:      cfg.OSSAuthsPath,
		RegistryAuthsPath: cfg.RegistryAuthsPath,
		CgroupMemoryLimit: cgroupMemoryLimit,
		DisableCgroup:     cfg.DisableCgroup,
	})
	if err != nil {
		return nil, fmt.Errorf("imagemanager: distillfs manager: %w", err)
	}

	ociMgr, err := oci.NewManager(cfg.Root, cfg.NydusTemplate, sharedRegistryClient)
	if err != nil {
		return nil, fmt.Errorf("imagemanager: oci manager: %w", err)
	}

	// Mount records stay in the image-manager root, separate from sandbox
	// lifecycle metadata.
	dbPath := filepath.Join(cfg.Root, "mount_records.db")
	worker, err := api.NewHttpWorker(&api.HttpWorkerConfig{
		Manager:     mgr,
		OCIManager:  ociMgr,
		NydusClient: nydusClient,
		NydusSuffix: cfg.NydusSuffix,
		DBPath:      dbPath,
	})
	if err != nil {
		ociMgr.Close()
		return nil, fmt.Errorf("imagemanager: http worker: %w", err)
	}

	m := &Module{cfg: cfg, mgr: mgr, ociMgr: ociMgr, worker: worker}
	m.healthy.Store(true)
	return m, nil
}

// Service returns the in-process Service implementation, satisfying the
// 4-call-site sandboxd contract previously fronted by api.NewHttpClient().
func (m *Module) Service() api.Service { return m.worker }

// Start currently has nothing to drive because the manager and worker start
// their background goroutines during NewModule.
func (m *Module) Start() error { return nil }

// ReconcileRecoveredDaemons removes distillfs daemons that were not claimed
// while sandbox filesystem state was restored.
func (m *Module) ReconcileRecoveredDaemons() error {
	return m.mgr.ReconcileRecoveredDaemons()
}

// Stop closes the worker (drains in-flight requests, persists mount state
// to mount_records.db) and the OCI manager (releases overlay mounts). It
// is safe to call multiple times; only the first call performs work.
func (m *Module) Stop() {
	m.closedOnce.Do(func() {
		m.healthy.Store(false)
		if m.worker != nil {
			m.worker.Close()
		}
		if m.ociMgr != nil {
			m.ociMgr.Close()
		}
	})
}

// Healthy returns true while the module is constructed and not yet
// Stop()ped. A richer signal (e.g. distillfs daemon liveness aggregation)
// is left to a later iteration since Stop is the only well-defined unhealthy
// transition right now.
func (m *Module) Healthy() bool { return m.healthy.Load() }
