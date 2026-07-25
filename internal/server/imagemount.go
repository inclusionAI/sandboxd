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
	"fmt"
	"strings"
	"sync"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	imgApi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/sirupsen/logrus"
)

// imageMountEntry tracks a shared image mount with reference counting.
// Multiple sandboxes using the same image share one mount point.
type imageMountEntry struct {
	refcount int
	path     string // local mount path
}

// requireReadOnlyMount enforces that S3/OCI-image mounts carry the "ro" option.
// The underlying FUSE source is read-only, so without an explicit "ro" the OCI
// spec would describe the mount as writable while writes silently fail at the
// FUSE layer.
func requireReadOnlyMount(m *runtime.Mount) error {
	if !hasReadOnlyOption(m.GetOptions()) {
		return fmt.Errorf("mount target %q must include the \"ro\" option: S3/image mounts are read-only", m.GetTarget())
	}
	return nil
}

// hasReadOnlyOption reports whether opts contains the "ro" mount option.
func hasReadOnlyOption(opts []string) bool {
	for _, opt := range opts {
		if opt == "ro" {
			return true
		}
	}
	return false
}

// s3UnmountFunc is the function type for unmounting S3 mounts.
type s3UnmountFunc func(endpoint, bucket, object string) error

// ociUnmountFunc is the function type for unmounting OCI image mounts.
type ociUnmountFunc func(imageURL string) error

// s3MountManager manages shared S3 FUSE mounts with reference counting.
// image-manager's FUSE daemon deduplicates by endpoint+bucket+object, but
// its UnmountOSS kills the daemon directly without ref counting. This manager
// ensures the daemon is only unmounted when no sandbox references it.
type s3MountManager struct {
	mu       sync.Mutex
	entries  map[string]*imageMountEntry // key: endpoint+bucket+object
	svc      imgApi.Service              // in-process image manager
	unmountF s3UnmountFunc               // test seam
}

func newS3MountManager(svc imgApi.Service) *s3MountManager {
	if svc == nil {
		// Production callers and tests must provide a Service explicitly.
		panic("server: newS3MountManager called without an image-manager Service")
	}
	return &s3MountManager{
		entries: make(map[string]*imageMountEntry),
		svc:     svc,
		unmountF: func(endpoint, bucket, object string) error {
			return svc.UmountOSS(&imgApi.OSSUmountRequest{
				Endpoint: endpoint,
				Bucket:   bucket,
				Object:   object,
			})
		},
	}
}

func s3MountKey(cfg *runtime.S3Config) string {
	return strings.Join([]string{cfg.Endpoint, cfg.Bucket, cfg.Object}, "\x00")
}

// mountS3 acquires a shared S3 mount. If the same S3 object is already mounted
// by another sandbox, the existing path is returned without calling image-manager.
func (m *s3MountManager) mountS3(cfg *runtime.S3Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("s3_config is nil")
	}
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.Object == "" {
		return "", fmt.Errorf("s3_config missing required fields: endpoint=%q, bucket=%q, object=%q", cfg.Endpoint, cfg.Bucket, cfg.Object)
	}

	key := s3MountKey(cfg)

	m.mu.Lock()
	if entry, ok := m.entries[key]; ok {
		entry.refcount++
		m.mu.Unlock()
		logrus.Debugf("s3mount: reuse existing mount for %s/%s, refcount=%d", cfg.Bucket, cfg.Object, entry.refcount)
		return entry.path, nil
	}
	m.mu.Unlock()

	// First caller: mount via in-process image-manager.
	mi, err := m.svc.MountOSS(&imgApi.OSSMountRequest{
		Endpoint:        cfg.Endpoint,
		Bucket:          cfg.Bucket,
		Object:          cfg.Object,
		AccessKeyID:     cfg.AccessKeyID,
		AccessKeySecret: cfg.AccessKeySecret,
	})
	if err != nil {
		return "", fmt.Errorf("failed to mount S3 %s/%s: %w", cfg.Bucket, cfg.Object, err)
	}

	m.mu.Lock()
	// Double-check: another goroutine might have mounted while we were unlocked.
	if existing, ok := m.entries[key]; ok {
		existing.refcount++
		m.mu.Unlock()
		logrus.Debugf("s3mount: race detected for %s/%s, reusing existing", cfg.Bucket, cfg.Object)
		return existing.path, nil
	}
	m.entries[key] = &imageMountEntry{
		refcount: 1,
		path:     mi.FilePath,
	}
	m.mu.Unlock()

	logrus.Infof("s3mount: mounted %s/%s at %s", cfg.Bucket, cfg.Object, mi.FilePath)
	return mi.FilePath, nil
}

// unmountS3 releases a reference to a shared S3 mount.
// The FUSE daemon is only unmounted when refcount reaches zero.
func (m *s3MountManager) unmountS3(cfg *runtime.S3Config) error {
	if cfg == nil {
		return fmt.Errorf("s3_config is nil")
	}

	key := s3MountKey(cfg)

	m.mu.Lock()
	entry, ok := m.entries[key]
	if !ok {
		m.mu.Unlock()
		logrus.Warnf("s3mount: unmount called for unknown key %s/%s", cfg.Bucket, cfg.Object)
		return nil
	}

	entry.refcount--
	if entry.refcount > 0 {
		m.mu.Unlock()
		logrus.Debugf("s3mount: released one ref for %s/%s, refcount=%d", cfg.Bucket, cfg.Object, entry.refcount)
		return nil
	}

	delete(m.entries, key)
	m.mu.Unlock()

	logrus.Infof("s3mount: last ref released for %s/%s, unmounting", cfg.Bucket, cfg.Object)
	if err := m.unmountF(cfg.Endpoint, cfg.Bucket, cfg.Object); err != nil {
		logrus.Warnf("s3mount: failed to unmount S3 %s/%s: %v", cfg.Bucket, cfg.Object, err)
		return err
	}
	return nil
}

// cleanupAllS3Unmounts unmounts all remaining S3 mounts.
// Called during shutdown.
func (m *s3MountManager) cleanupAllS3Unmounts() {
	m.mu.Lock()
	entries := make(map[string]*imageMountEntry, len(m.entries))
	for k, v := range m.entries {
		entries[k] = v
	}
	m.entries = make(map[string]*imageMountEntry)
	m.mu.Unlock()

	for key, entry := range entries {
		parts := strings.Split(key, "\x00")
		if len(parts) != 3 {
			logrus.Warnf("s3mount: invalid key format, skipping: %q", key)
			continue
		}
		logrus.Infof("s3mount: cleanup remaining mount refcount=%d at %s", entry.refcount, entry.path)
		if err := m.unmountF(parts[0], parts[1], parts[2]); err != nil {
			logrus.Warnf("s3mount: cleanup failed for %s: %v", key, err)
		}
	}
}

// ociMountManager manages shared OCI image mounts with reference counting.
// Similar to s3MountManager, it ensures OCI images are only unmounted when
// no sandbox references them.
type ociMountManager struct {
	mu       sync.Mutex
	entries  map[string]*imageMountEntry // key: image URL
	svc      imgApi.Service              // in-process image-manager (nil falls back to HttpClient)
	unmountF ociUnmountFunc              // for testing injection
}

func newOciMountManager(svc imgApi.Service) *ociMountManager {
	if svc == nil {
		panic("server: newOciMountManager called without an image-manager Service")
	}
	return &ociMountManager{
		entries: make(map[string]*imageMountEntry),
		svc:     svc,
		unmountF: func(imageURL string) error {
			return svc.UmountOCI(&imgApi.OCIUmountRequest{
				ImageURL: imageURL,
			})
		},
	}
}

// mountOCI acquires a shared OCI image mount. If the same image is already mounted
// by another sandbox, the existing path is returned without calling image-manager.
func (m *ociMountManager) mountOCI(imageURL string) (string, error) {
	if imageURL == "" {
		return "", fmt.Errorf("image_url is empty")
	}

	key := imageURL

	m.mu.Lock()
	if entry, ok := m.entries[key]; ok {
		entry.refcount++
		m.mu.Unlock()
		logrus.Debugf("ocimount: reuse existing mount for %s, refcount=%d", imageURL, entry.refcount)
		return entry.path, nil
	}
	m.mu.Unlock()

	// First caller: mount via in-process image-manager.
	resp, err := m.svc.MountOCI(&imgApi.OCIMountRequest{
		ImageURL: imageURL,
	})
	if err != nil {
		return "", fmt.Errorf("failed to mount OCI image %s: %w", imageURL, err)
	}

	m.mu.Lock()
	// Double-check: another goroutine might have mounted while we were unlocked.
	if existing, ok := m.entries[key]; ok {
		existing.refcount++
		m.mu.Unlock()
		logrus.Debugf("ocimount: race detected for %s, reusing existing", imageURL)
		return existing.path, nil
	}
	m.entries[key] = &imageMountEntry{
		refcount: 1,
		path:     resp.MountPath,
	}
	m.mu.Unlock()

	logrus.Infof("ocimount: mounted %s at %s", imageURL, resp.MountPath)
	return resp.MountPath, nil
}

// unmountOCI releases a reference to a shared OCI image mount.
// The image is only unmounted when refcount reaches zero.
func (m *ociMountManager) unmountOCI(imageURL string) error {
	if imageURL == "" {
		return fmt.Errorf("image_url is empty")
	}

	key := imageURL

	m.mu.Lock()
	entry, ok := m.entries[key]
	if !ok {
		m.mu.Unlock()
		logrus.Warnf("ocimount: unmount called for unknown image %s", imageURL)
		return nil
	}

	entry.refcount--
	if entry.refcount > 0 {
		m.mu.Unlock()
		logrus.Debugf("ocimount: released one ref for %s, refcount=%d", imageURL, entry.refcount)
		return nil
	}

	delete(m.entries, key)
	m.mu.Unlock()

	logrus.Infof("ocimount: last ref released for %s, unmounting", imageURL)
	if err := m.unmountF(imageURL); err != nil {
		logrus.Warnf("ocimount: failed to unmount OCI image %s: %v", imageURL, err)
		return err
	}
	return nil
}

// cleanupAllOciUnmounts unmounts all remaining OCI image mounts.
// Called during shutdown.
func (m *ociMountManager) cleanupAllOciUnmounts() {
	m.mu.Lock()
	entries := make(map[string]*imageMountEntry, len(m.entries))
	for k, v := range m.entries {
		entries[k] = v
	}
	m.entries = make(map[string]*imageMountEntry)
	m.mu.Unlock()

	for key, entry := range entries {
		logrus.Infof("ocimount: cleanup remaining mount refcount=%d at %s", entry.refcount, entry.path)
		if err := m.unmountF(key); err != nil {
			logrus.Warnf("ocimount: cleanup failed for %s: %v", key, err)
		}
	}
}
