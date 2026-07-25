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
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/langrtmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type fsManager struct {
	rootfs *langrtmanager.LangRTManager
	s3     *s3MountManager
	oci    *ociMountManager

	mu              sync.Mutex
	sandboxRootfs   map[string]*langrtmanager.LanguageRuntime
	sandboxS3Mount  map[string][]*runtime.S3Config
	sandboxOCIMount map[string][]string
	sandboxState    map[string]sandboxFSState
	store           store.DbStore
	persistMu       sync.Mutex
}

type preparedFS struct {
	manager *fsManager
	rootfs  *langrtmanager.LanguageRuntime
	source  *runtime.RootfsConfig
	mounts  []*runtime.Mount
	s3      []*runtime.S3Config
	oci     []string
}

type sandboxFSState struct {
	Rootfs []byte              `json:"rootfs,omitempty"`
	S3     []*runtime.S3Config `json:"s3,omitempty"`
	OCI    []string            `json:"oci,omitempty"`
}

type storedSandboxFSStates struct {
	Items map[string]sandboxFSState `json:"items"`
}

func newFSManager(imgSvc imageapi.Service, stores ...store.DbStore) *fsManager {
	s3Mgr := newS3MountManagerForFS(imgSvc)
	ociMgr := newOciMountManagerForFS(imgSvc)
	var stateStore store.DbStore
	if len(stores) > 0 {
		stateStore = stores[0]
	}
	return &fsManager{
		rootfs:          langrtmanager.NewLanguageRuntimeManager(langrtmanager.NewDefaultMounter(imgSvc)),
		s3:              s3Mgr,
		oci:             ociMgr,
		sandboxRootfs:   make(map[string]*langrtmanager.LanguageRuntime),
		sandboxS3Mount:  make(map[string][]*runtime.S3Config),
		sandboxOCIMount: make(map[string][]string),
		sandboxState:    make(map[string]sandboxFSState),
		store:           stateStore,
	}
}

func newS3MountManagerForFS(imgSvc imageapi.Service) *s3MountManager {
	if imgSvc != nil {
		return newS3MountManager(imgSvc)
	}
	return &s3MountManager{
		entries:  make(map[string]*imageMountEntry),
		unmountF: func(_, _, _ string) error { return nil },
	}
}

func newOciMountManagerForFS(imgSvc imageapi.Service) *ociMountManager {
	if imgSvc != nil {
		return newOciMountManager(imgSvc)
	}
	return &ociMountManager{
		entries:  make(map[string]*imageMountEntry),
		unmountF: func(string) error { return nil },
	}
}

func (m *fsManager) Prepare(request *runtime.StartRequest) (_ *preparedFS, retErr error) {
	rootfs, err := m.rootfs.AddLangRuntime(request, true)
	if err != nil {
		return nil, err
	}
	rootfs.IncRef()

	prepared := &preparedFS{
		manager: m,
		rootfs:  rootfs,
		source:  proto.Clone(request.Rootfs).(*runtime.RootfsConfig),
	}
	defer func() {
		if retErr != nil {
			prepared.Rollback()
		}
	}()

	prepared.mounts = cloneMounts(request.Mounts)
	for _, mount := range prepared.mounts {
		if mount == nil {
			continue
		}
		switch src := mount.GetSource().(type) {
		case *runtime.Mount_HostPath:
		case *runtime.Mount_S3Config:
			if err := requireReadOnlyMount(mount); err != nil {
				return nil, fmt.Errorf("invalid S3 mount: %w", err)
			}
			path, err := m.s3.mountS3(src.S3Config)
			if err != nil {
				return nil, fmt.Errorf("failed to mount S3: %w", err)
			}
			mount.Source = &runtime.Mount_HostPath{HostPath: path}
			prepared.s3 = append(prepared.s3, src.S3Config)
		case *runtime.Mount_ImageUrl:
			if err := requireReadOnlyMount(mount); err != nil {
				return nil, fmt.Errorf("invalid image mount: %w", err)
			}
			path, err := m.oci.mountOCI(src.ImageUrl)
			if err != nil {
				return nil, fmt.Errorf("failed to mount OCI image: %w", err)
			}
			mount.Source = &runtime.Mount_HostPath{HostPath: path}
			prepared.oci = append(prepared.oci, src.ImageUrl)
		default:
			if mount.GetHostPath() == "" {
				logrus.Warnf("mount %s has no source, skipping", mount.GetTarget())
			}
		}
	}
	return prepared, nil
}

func (m *fsManager) Commit(sandboxID string, prepared *preparedFS) {
	if sandboxID == "" || prepared == nil {
		return
	}
	state, err := stateFromPrepared(prepared)
	if err != nil {
		logrus.Errorf("failed to encode filesystem state for sandbox %s: %v", sandboxID, err)
		return
	}
	m.mu.Lock()
	m.sandboxRootfs[sandboxID] = prepared.rootfs
	if len(prepared.s3) > 0 {
		m.sandboxS3Mount[sandboxID] = append([]*runtime.S3Config(nil), prepared.s3...)
	}
	if len(prepared.oci) > 0 {
		m.sandboxOCIMount[sandboxID] = append([]string(nil), prepared.oci...)
	}
	m.sandboxState[sandboxID] = state
	m.mu.Unlock()
	m.persistState()
}

func (m *fsManager) Release(sandboxID string) {
	m.release(sandboxID, true)
}

func (m *fsManager) Shutdown() {
	m.mu.Lock()
	rootfsRefs := make([]*langrtmanager.LanguageRuntime, 0, len(m.sandboxRootfs))
	for _, rootfs := range m.sandboxRootfs {
		rootfsRefs = append(rootfsRefs, rootfs)
	}
	m.sandboxRootfs = make(map[string]*langrtmanager.LanguageRuntime)
	m.sandboxS3Mount = make(map[string][]*runtime.S3Config)
	m.sandboxOCIMount = make(map[string][]string)
	m.sandboxState = make(map[string]sandboxFSState)
	m.mu.Unlock()

	for _, rootfs := range rootfsRefs {
		if rootfs != nil {
			rootfs.DecRef()
		}
	}
	m.s3.cleanupAllS3Unmounts()
	m.oci.cleanupAllOciUnmounts()
	m.persistState()
}

func stateFromPrepared(prepared *preparedFS) (sandboxFSState, error) {
	if prepared == nil || prepared.source == nil {
		return sandboxFSState{}, fmt.Errorf("rootfs source is missing")
	}
	rootfs, err := proto.Marshal(prepared.source)
	if err != nil {
		return sandboxFSState{}, fmt.Errorf("marshal rootfs source: %w", err)
	}
	return sandboxFSState{
		Rootfs: rootfs,
		S3:     cloneS3Configs(prepared.s3),
		OCI:    append([]string(nil), prepared.oci...),
	}, nil
}

func cloneS3Configs(configs []*runtime.S3Config) []*runtime.S3Config {
	cloned := make([]*runtime.S3Config, 0, len(configs))
	for _, cfg := range configs {
		if cfg == nil {
			cloned = append(cloned, nil)
			continue
		}
		cloned = append(cloned, proto.Clone(cfg).(*runtime.S3Config))
	}
	return cloned
}

func cloneFSState(state sandboxFSState) sandboxFSState {
	return sandboxFSState{
		Rootfs: append([]byte(nil), state.Rootfs...),
		S3:     cloneS3Configs(state.S3),
		OCI:    append([]string(nil), state.OCI...),
	}
}

func (m *fsManager) persistState() {
	if m.store == nil {
		return
	}
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	m.mu.Lock()
	items := make(map[string]sandboxFSState, len(m.sandboxState))
	for sandboxID, state := range m.sandboxState {
		items[sandboxID] = cloneFSState(state)
	}
	m.mu.Unlock()

	data, err := json.Marshal(storedSandboxFSStates{Items: items})
	if err != nil {
		logrus.Warnf("failed to encode sandbox filesystem state: %v", err)
		return
	}
	if err := m.store.StoreRaw(config.SandboxFSStateBucket, data); err != nil {
		logrus.Warnf("failed to persist sandbox filesystem state: %v", err)
	}
}

// Restore rebuilds rootfs and additional-mount references after sandboxd
// restarts in the same pod. State belonging to sandboxes that no longer exist
// is re-acquired and immediately released so the underlying mount is cleaned.
func (m *fsManager) Restore(sandboxExists func(string) bool) error {
	if m.store == nil {
		return nil
	}
	data, err := m.store.LoadRaw(config.SandboxFSStateBucket)
	if err != nil {
		if errord.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("load sandbox filesystem state: %w", err)
	}

	var stored storedSandboxFSStates
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("decode sandbox filesystem state: %w", err)
	}
	ids := make([]string, 0, len(stored.Items))
	for sandboxID := range stored.Items {
		ids = append(ids, sandboxID)
	}
	sort.Strings(ids)

	var restoreErrors []error
	for _, sandboxID := range ids {
		state := cloneFSState(stored.Items[sandboxID])
		if err := m.restoreSandbox(sandboxID, state); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("sandbox %s: %w", sandboxID, err))
			continue
		}
		if sandboxExists != nil && !sandboxExists(sandboxID) {
			m.release(sandboxID, false)
		}
	}
	if len(restoreErrors) > 0 {
		return errors.Join(restoreErrors...)
	}
	m.persistState()
	return nil
}

func (m *fsManager) restoreSandbox(sandboxID string, state sandboxFSState) (retErr error) {
	rootfs := &runtime.RootfsConfig{}
	if len(state.Rootfs) == 0 {
		return fmt.Errorf("rootfs source is missing")
	}
	if err := proto.Unmarshal(state.Rootfs, rootfs); err != nil {
		return fmt.Errorf("unmarshal rootfs source: %w", err)
	}
	lrt, err := m.rootfs.AddLangRuntime(&runtime.StartRequest{
		SandboxID: sandboxID,
		Rootfs:    rootfs,
	}, true)
	if err != nil {
		return fmt.Errorf("restore rootfs: %w", err)
	}
	lrt.IncRef()
	prepared := &preparedFS{manager: m, rootfs: lrt, source: rootfs}
	defer func() {
		if retErr != nil {
			prepared.Rollback()
		}
	}()

	for _, cfg := range state.S3 {
		if _, err := m.s3.mountS3(cfg); err != nil {
			return fmt.Errorf("restore S3 mount: %w", err)
		}
		prepared.s3 = append(prepared.s3, cfg)
	}
	for _, imageURL := range state.OCI {
		if _, err := m.oci.mountOCI(imageURL); err != nil {
			return fmt.Errorf("restore OCI mount: %w", err)
		}
		prepared.oci = append(prepared.oci, imageURL)
	}

	m.mu.Lock()
	m.sandboxRootfs[sandboxID] = prepared.rootfs
	m.sandboxS3Mount[sandboxID] = cloneS3Configs(prepared.s3)
	m.sandboxOCIMount[sandboxID] = append([]string(nil), prepared.oci...)
	m.sandboxState[sandboxID] = cloneFSState(state)
	m.mu.Unlock()
	return nil
}

func (m *fsManager) release(sandboxID string, persist bool) {
	if sandboxID == "" {
		return
	}
	m.mu.Lock()
	rootfs := m.sandboxRootfs[sandboxID]
	s3Configs := append([]*runtime.S3Config(nil), m.sandboxS3Mount[sandboxID]...)
	ociURLs := append([]string(nil), m.sandboxOCIMount[sandboxID]...)
	delete(m.sandboxRootfs, sandboxID)
	delete(m.sandboxS3Mount, sandboxID)
	delete(m.sandboxOCIMount, sandboxID)
	delete(m.sandboxState, sandboxID)
	m.mu.Unlock()

	if rootfs != nil {
		rootfs.DecRef()
	}
	for _, cfg := range s3Configs {
		if err := m.s3.unmountS3(cfg); err != nil {
			logrus.Warnf("failed to unmount S3 for sandbox %s: %v", sandboxID, err)
		}
	}
	for _, imageURL := range ociURLs {
		if err := m.oci.unmountOCI(imageURL); err != nil {
			logrus.Warnf("failed to unmount OCI image for sandbox %s: %v", sandboxID, err)
		}
	}
	if persist {
		m.persistState()
	}
}

func (p *preparedFS) RootfsPath() string {
	if p == nil || p.rootfs == nil || p.rootfs.RootFS == nil {
		return ""
	}
	return p.rootfs.RootFS.Path()
}

func (p *preparedFS) Mounts() []*runtime.Mount {
	if p == nil {
		return nil
	}
	return p.mounts
}

func (p *preparedFS) Rollback() {
	if p == nil {
		return
	}
	if p.rootfs != nil {
		p.rootfs.DecRef()
		p.rootfs = nil
	}
	for _, cfg := range p.s3 {
		_ = p.manager.s3.unmountS3(cfg)
	}
	for _, url := range p.oci {
		_ = p.manager.oci.unmountOCI(url)
	}
	p.s3 = nil
	p.oci = nil
}

func cloneMounts(mounts []*runtime.Mount) []*runtime.Mount {
	cloned := make([]*runtime.Mount, 0, len(mounts))
	for _, mount := range mounts {
		if mount == nil {
			cloned = append(cloned, nil)
			continue
		}
		cloned = append(cloned, proto.Clone(mount).(*runtime.Mount))
	}
	return cloned
}
