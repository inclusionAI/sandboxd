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

package langrtmanager

import (
	"fmt"
	"sync"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/sirupsen/logrus"
)

type SeedInfo struct {
	Cid  string
	Cmd  []string
	Envs map[string]string
}

type rootfsEntry struct {
	rootfs *RootFS
	err    error
	ready  chan struct{} // closed when rootfs creation is done
}

type LangRTManager struct {
	mounter ImageMounter

	lrMu   sync.RWMutex
	lrtMap map[string]*LanguageRuntime

	rfMu      sync.Mutex
	rootfsMap map[RootfsConfig]*rootfsEntry
}

func (lm *LangRTManager) GetRootfs(cfg RootfsConfig) (*RootFS, error) {
	lm.rfMu.Lock()
	if entry, ok := lm.rootfsMap[cfg]; ok {
		lm.rfMu.Unlock()
		<-entry.ready
		return entry.rootfs, entry.err
	}

	// First caller for this config: create a placeholder entry and release lock
	// before the slow NewRootFS operation.
	entry := &rootfsEntry{
		ready: make(chan struct{}),
	}
	lm.rootfsMap[cfg] = entry
	lm.rfMu.Unlock()

	logrus.Infof("rootfs %v not exists, try to create it", cfg)
	rootfs, err := NewRootFS(cfg, lm.mounter, func() {
		lm.rfMu.Lock()
		// Only delete if it's still our entry (not replaced by a new one).
		if lm.rootfsMap[cfg] == entry {
			delete(lm.rootfsMap, cfg)
		}
		lm.rfMu.Unlock()
	})

	entry.rootfs = rootfs
	entry.err = err
	close(entry.ready)

	if err != nil {
		// Remove failed entry so future callers can retry.
		lm.rfMu.Lock()
		if lm.rootfsMap[cfg] == entry {
			delete(lm.rootfsMap, cfg)
		}
		lm.rfMu.Unlock()
		return nil, fmt.Errorf("failed to create rootfs with config %v: %v", cfg, err)
	}

	return rootfs, nil
}

func (lm *LangRTManager) GetLangRuntime(id string) *LanguageRuntime {
	lm.lrMu.RLock()
	defer lm.lrMu.RUnlock()

	if lr, ok := lm.lrtMap[id]; ok {
		return lr
	} else {
		return nil
	}
}

// NewLanguageRuntimeManager creates a new LangRTManager.
// If mounter is nil, the default production ImageMounter is used.
func NewLanguageRuntimeManager(mounter ...ImageMounter) *LangRTManager {
	var m ImageMounter
	if len(mounter) > 0 && mounter[0] != nil {
		m = mounter[0]
	} else {
		m = &defaultMounter{}
	}
	return &LangRTManager{
		mounter:   m,
		lrtMap:    make(map[string]*LanguageRuntime),
		rootfsMap: make(map[RootfsConfig]*rootfsEntry),
	}
}

func (lm *LangRTManager) AddLangRuntime(request *api.StartRequest, temporary bool) (*LanguageRuntime, error) {
	if request == nil {
		return nil, fmt.Errorf("start request is nil")
	}
	if request.Rootfs == nil {
		return nil, fmt.Errorf("rootfs is nil")
	}

	// Fast path: check if already exists with read lock only.
	id := request.SandboxID
	lm.lrMu.RLock()
	if lr, ok := lm.lrtMap[id]; ok {
		lm.lrMu.RUnlock()
		logrus.Debugf("Language runtime %v already exists!", id)
		lr.SetTemporary(temporary)
		return lr, nil
	}
	lm.lrMu.RUnlock()

	// Build rootfs config without holding any lock.
	var cfg RootfsConfig

	switch request.Rootfs.Type {
	case api.RootfsSrcType_S3:
		s3Config := request.Rootfs.GetS3Config()
		if s3Config == nil {
			return nil, fmt.Errorf("S3Config is nil while rootfs type is S3.")
		}
		cfg = RootfsConfig{
			SrcType:         request.Rootfs.Type,
			Endpoint:        s3Config.Endpoint,
			Bucket:          s3Config.Bucket,
			Object:          s3Config.Object,
			AccessKeyID:     s3Config.AccessKeyID,
			AccessKeySecret: s3Config.AccessKeySecret,
		}
	case api.RootfsSrcType_IMAGE:
		imageUrl := request.Rootfs.GetImageUrl()
		if imageUrl == "" {
			return nil, fmt.Errorf("Image URL is empty while rootfs type is IMAGE.")
		}
		cfg = RootfsConfig{
			SrcType:  request.Rootfs.Type,
			ImageUrl: imageUrl,
		}
	case api.RootfsSrcType_LOCAL:
		path := request.Rootfs.GetPath()
		if path == "" {
			return nil, fmt.Errorf("Path empty while rootfs type is LOCAL.")
		}
		cfg = RootfsConfig{
			SrcType: request.Rootfs.Type,
			Path:    path,
		}
	default:
		return nil, fmt.Errorf("Rootfs Type not supported: %v", request.Rootfs.Type.String())
	}
	if id == "" {
		id = cfg.key()
	}

	// Slow path: create rootfs without holding lrMu.
	var (
		rootfs *RootFS
		err    error
	)
	for {
		rootfs, err = lm.GetRootfs(cfg)
		if err != nil {
			return nil, err
		}

		err = rootfs.IncRef()
		if err != nil {
			logrus.Warningf("Get reference of rootfs %v failed: %v, retry", rootfs.cfg, err)
			continue
		} else {
			break // get rootfs succeed.
		}
	}

	// Take write lock to insert. Double-check in case another goroutine
	// added the same runtime while we were creating rootfs.
	lm.lrMu.Lock()
	defer lm.lrMu.Unlock()

	if lr, ok := lm.lrtMap[id]; ok {
		logrus.Debugf("Language runtime %v already exists (added concurrently)!", id)
		lr.SetTemporary(temporary)
		rootfs.DecRef()
		return lr, nil
	}

	lr := &LanguageRuntime{
		ID:       id,
		Sandbox:  request.Runtime,
		Readonly: request.Rootfs.Readonly,
		SeedInfo: &SeedInfo{
			Cid:  id,
			Cmd:  request.Command,
			Envs: request.Envs,
		},
		RootFS:    rootfs,
		temporary: temporary,
		cleanupFunc: func() {
			lm.lrMu.Lock()
			delete(lm.lrtMap, id)
			lm.lrMu.Unlock()
		},
	}
	lm.lrtMap[lr.ID] = lr
	logrus.Debugf("Add language runtime: %v", lr)

	return lr, nil
}

func (lm *LangRTManager) List() []*LanguageRuntime {
	lm.lrMu.RLock()
	defer lm.lrMu.RUnlock()

	var lrtList []*LanguageRuntime
	for _, lrt := range lm.lrtMap {
		lrtList = append(lrtList, lrt)
	}

	return lrtList
}
