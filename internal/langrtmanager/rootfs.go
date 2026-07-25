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
	"os"
	"sync"

	runtime_api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/sirupsen/logrus"
)

// ImageMounter abstracts rootfs mount/umount operations for testability.
type ImageMounter interface {
	Mount(cfg RootfsConfig) (path string, env []string, err error)
	Umount(cfg RootfsConfig) error
}

type RootFS struct {
	cfg         RootfsConfig
	path        string
	env         []string
	mounter     ImageMounter
	cleanupFunc func()
	mu          sync.Mutex // mu protects fields below
	refcnt      int64
	deleted     bool
}

type RootfsConfig struct {
	SrcType runtime_api.RootfsSrcType

	// OSS
	Endpoint        string
	Bucket          string
	Object          string
	AccessKeyID     string
	AccessKeySecret string

	// docker image
	ImageUrl string

	// local
	Path string
}

func (cfg RootfsConfig) key() string {
	return fmt.Sprintf("%d:%s:%s:%s:%s:%s:%s:%s",
		cfg.SrcType,
		cfg.Endpoint,
		cfg.Bucket,
		cfg.Object,
		cfg.AccessKeyID,
		cfg.AccessKeySecret,
		cfg.ImageUrl,
		cfg.Path,
	)
}

func (rf *RootFS) Path() string {
	return rf.path
}

func (rf *RootFS) Env() []string {
	return rf.env
}

func (rf *RootFS) Config() RootfsConfig {
	return rf.cfg
}

func (rf *RootFS) MountImage() error {
	if rf.path != "" {
		return fmt.Errorf("already mounted")
	}
	path, env, err := rf.mounter.Mount(rf.cfg)
	if err != nil {
		return err
	}
	rf.path = path
	rf.env = env
	return nil
}

func (rf *RootFS) UmountImage() error {
	return rf.mounter.Umount(rf.cfg)
}

// defaultMounter is the production ImageMounter backed by the in-process
// image-manager Service. Production code constructs one via NewDefaultMounter.
type defaultMounter struct {
	svc api.Service
}

// NewDefaultMounter returns the production mounter, bound to the in-process
// image-manager Service that sandboxd hands down.
func NewDefaultMounter(svc api.Service) ImageMounter {
	return &defaultMounter{svc: svc}
}

func (d *defaultMounter) client() api.Service {
	if d.svc == nil {
		// Every production path must provide the in-process Service. A nil
		// service indicates a programming error rather than a recoverable mount
		// failure.
		panic("langrtmanager: defaultMounter used without an image-manager Service")
	}
	return d.svc
}

func (d *defaultMounter) Mount(cfg RootfsConfig) (string, []string, error) {
	switch cfg.SrcType {
	case runtime_api.RootfsSrcType_S3:
		mi, err := d.client().MountOSS(&api.OSSMountRequest{
			Endpoint:        cfg.Endpoint,
			Bucket:          cfg.Bucket,
			Object:          cfg.Object,
			AccessKeyID:     cfg.AccessKeyID,
			AccessKeySecret: cfg.AccessKeySecret,
		})
		if err != nil {
			return "", nil, err
		}
		return mi.FilePath, mi.Env, nil

	case runtime_api.RootfsSrcType_IMAGE:
		resp, err := d.client().MountOCI(&api.OCIMountRequest{
			ImageURL: cfg.ImageUrl,
		})
		if err != nil {
			return "", nil, err
		}
		return resp.MountPath, resp.Env, nil

	case runtime_api.RootfsSrcType_LOCAL:
		// LOCAL rootfs is a pre-existing host path; no image-manager Service
		// call is involved, so leaving d.svc nil (typical in tests) is fine.
		if _, err := os.Stat(cfg.Path); err != nil {
			return "", nil, fmt.Errorf("failed to stat local rootfs path %s: %w", cfg.Path, err)
		}
		return cfg.Path, nil, nil

	default:
		return "", nil, fmt.Errorf("Unsupported image type: %v", cfg.SrcType.String())
	}
}

func (d *defaultMounter) Umount(cfg RootfsConfig) error {
	switch cfg.SrcType {
	case runtime_api.RootfsSrcType_S3:
		return d.client().UmountOSS(&api.OSSUmountRequest{
			Endpoint: cfg.Endpoint,
			Bucket:   cfg.Bucket,
			Object:   cfg.Object,
		})
	case runtime_api.RootfsSrcType_IMAGE:
		return d.client().UmountOCI(&api.OCIUmountRequest{
			ImageURL: cfg.ImageUrl,
		})
	case runtime_api.RootfsSrcType_LOCAL:
		return nil
	default:
		return fmt.Errorf("Unsupported image type: %v", cfg.SrcType.String())
	}
}

func (rf *RootFS) IncRef() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.deleted {
		return fmt.Errorf("this rootfs has already been deleted")
	}
	rf.refcnt += 1
	return nil
}

func (rf *RootFS) DecRef() {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.refcnt -= 1
	if rf.refcnt == 0 {
		logrus.Infof("No one refers rootfs %v, try to release it", rf.cfg)
		rf.deleted = true
		if err := rf.UmountImage(); err != nil {
			logrus.Warningf("Failed to umount image %v: %v, just ignore", rf.path, err)
		}
		rf.cleanupFunc()
	} else if rf.refcnt < 0 {
		logrus.Warningf("Refcount %v < 0, leak happens.", rf.refcnt)
	}
}

func NewRootFS(cfg RootfsConfig, mounter ImageMounter, cleanup func()) (*RootFS, error) {
	rootFS := &RootFS{
		cfg:         cfg,
		mounter:     mounter,
		cleanupFunc: cleanup,
	}

	if err := rootFS.MountImage(); err != nil {
		return nil, err
	}

	return rootFS, nil
}
