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

package distillfs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sirupsen/logrus"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/diskusage"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imgcgroup"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/registryauth"
)

type DaemonCreateOpt struct {
	ID         string
	Name       string
	MountPoint string
	// OSS Object = ObjectPrefix + Name
	ObjectPrefix    string
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	AccessKeySecret string
	// Source type: "oss" or "nydus"
	SourceType   string
	RegistryAuth string // For Nydus: Docker config path or credentials
	ImageURL     string // For Nydus: image URL to fetch bootstrap from registry
}

func (opts *DaemonCreateOpt) overwriteOSSConfig() bool {
	return opts.Endpoint != "" && opts.Bucket != "" && opts.ObjectPrefix != ""
}

type Manager interface {
	CreateDaemon(opts *DaemonCreateOpt) error
	GetDaemon(id string) *Daemon
	CleanupDaemon(daemonID string) error
	ListDaemons() []DaemonInfo
}

type manager struct {
	mu  sync.RWMutex
	ctx context.Context

	binPath          string
	root             string
	ossCfgTemplate   BackendConfig // OSS backend config template
	nydusCfgTemplate BackendConfig // Nydus backend config template
	daemons          map[string]*Daemon
	nydusClient      NydusClient           // Client for fetching Nydus images
	ossAuths         OSSAuthsConfig        // OSS authentication credentials
	registryAuths    RegistryAuthsConfig   // Registry authentication credentials
	cgroupCtrl       *imgcgroup.Controller // Memory cgroup for daemon processes (nil = disabled)
}

// NydusClient interface for fetching Nydus images and extracting bootstrap.
// FetchAndExtractBootstrap returns the bootstrap path and environment variables
// parsed from the image config.
type NydusClient interface {
	FetchAndExtractBootstrap(ctx context.Context, imageURL string, outputDir string, proxyURL string) (string, []string, error)
}

// ChunkDBStats represents the output of 'distill_fs stats-chunk' command
type ChunkDBStats struct {
	AccessTime struct {
		NewestEpochSecs int64 `json:"newest_epoch_secs"`
		OldestEpochSecs int64 `json:"oldest_epoch_secs"`
	} `json:"access_time"`
	Chunks struct {
		TotalCount int64 `json:"total_count"`
	} `json:"chunks"`
	Readers struct {
		Current      int64 `json:"current"`
		Max          int64 `json:"max"`
		StaleCleared int64 `json:"stale_cleared"`
	} `json:"readers"`
	Storage struct {
		FreeSizeBytes  int64  `json:"free_size_bytes"`
		TotalSizeBytes int64  `json:"total_size_bytes"`
		UsagePercent   string `json:"usage_percent"`
		UsedSizeBytes  int64  `json:"used_size_bytes"`
	} `json:"storage"`
}

// ManagerConfig holds configuration for creating a new Manager
type ManagerConfig struct {
	Context           context.Context // Context for tracing and cancellation (optional, defaults to Background)
	Root              string          // Root working directory
	OSSCfgPath        string          // Path to OSS config template file
	NydusCfgPath      string          // Path to Nydus config template file
	BinPath           string          // Path to distill_fs binary
	NydusClient       NydusClient     // Client for fetching Nydus images
	OSSAuthsPath      string          // Path to OSS auths file (oss_auths.json)
	RegistryAuthsPath string          // Path to registry auths file (registry_auths.json)
	CgroupMemoryLimit int64           // Memory limit in bytes for distill_fs cgroup (0 = no limit)
}

func NewManager(config *ManagerConfig) (Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Default to background context if not provided
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}

	mgr := &manager{
		ctx:              ctx,
		binPath:          config.BinPath,
		root:             config.Root,
		ossCfgTemplate:   BackendConfig{},
		nydusCfgTemplate: BackendConfig{},
		daemons:          map[string]*Daemon{},
		nydusClient:      config.NydusClient,
		cgroupCtrl:       imgcgroup.NewController(config.CgroupMemoryLimit),
	}
	if err := mgr.prepare(config.OSSCfgPath, config.NydusCfgPath, config.OSSAuthsPath, config.RegistryAuthsPath); err != nil {
		return nil, fmt.Errorf("failed to prepare distillfs manager: %w", err)
	}
	if err := mgr.loadExistedDaemons(); err != nil {
		return nil, fmt.Errorf("failed to load existed daemons: %w", err)
	}
	mgr.addExistingDaemonsToCgroup()
	go mgr.gcWorker()
	go mgr.chunkDBCleanupWorker()
	return mgr, nil
}

func (mgr *manager) daemonList() []*Daemon {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	var daemons []*Daemon
	for _, d := range mgr.daemons {
		daemons = append(daemons, d)
	}

	return daemons
}

func (mgr *manager) checkDaemons() {
	daemons := mgr.daemonList()

	for _, daemon := range daemons {
		if daemon.IsAlive() {
			continue
		}
		logrus.WithFields(daemon.daemonLogFields()).Warn("daemon dead, do remount")
		err := daemon.Mount()
		if err != nil {
			logrus.WithFields(daemon.daemonLogFields()).WithError(err).Error("failed to remount daemon")
		}
	}
}

func (mgr *manager) loadExistedDaemons() error {
	daemonConfigDir := filepath.Join(mgr.root, "daemon_configs")
	entries, err := os.ReadDir(daemonConfigDir)
	if err != nil {
		return fmt.Errorf("failed to read daemon configs: %w", err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		d := &Daemon{ctx: mgr.ctx, binPath: mgr.binPath, cgroupCtrl: mgr.cgroupCtrl}
		metaFilePath := filepath.Join(daemonConfigDir, entry.Name())
		if err = d.LoadExisted(metaFilePath); err != nil {
			logrus.Errorf("failed to load daemon from meta file %s: %v", metaFilePath, err)
			continue
		}
		d.savedPath = filepath.Join(daemonConfigDir, d.meta.ID+".json")
		mgr.daemons[d.meta.ID] = d
	}
	return nil
}

// addExistingDaemonsToCgroup adds alive daemon PIDs to the cgroup on restart.
func (mgr *manager) addExistingDaemonsToCgroup() {
	if !mgr.cgroupCtrl.Enabled() {
		return
	}
	for _, d := range mgr.daemons {
		if !d.IsAlive() {
			continue
		}
		pid := d.getPid()
		if pid <= 0 {
			continue
		}
		if err := mgr.cgroupCtrl.AddPID(pid); err != nil {
			logrus.Warnf("cgroup: failed to add existing daemon %s (pid %d): %v", d.meta.ID, pid, err)
		} else {
			logrus.Infof("cgroup: added existing daemon %s (pid %d) to cgroup", d.meta.ID, pid)
		}
	}
}

func (mgr *manager) prepare(ossCfgPath string, nydusCfgPath string, ossAuthsPath string, registryAuthsPath string) error {
	// chunk db
	err := os.MkdirAll(filepath.Join(mgr.root, "chunk_db"), 0755)
	if err != nil {
		return fmt.Errorf("failed to create chunk_db dir: %w", err)
	}
	// meta db root dir
	err = os.MkdirAll(filepath.Join(mgr.root, "image_metas"), 0755)
	if err != nil {
		return fmt.Errorf("failed to create image_meta dir: %w", err)
	}
	// daemons root dir
	err = os.MkdirAll(filepath.Join(mgr.root, "daemons"), 0755)
	if err != nil {
		return fmt.Errorf("failed to create daemons dir: %w", err)
	}
	// daemon config root dir
	err = os.MkdirAll(filepath.Join(mgr.root, "daemon_configs"), 0755)
	if err != nil {
		return fmt.Errorf("failed to create daemon configs dir: %w", err)
	}
	// daemon log staging dir (for extracting WARN/ERROR before cleanup)
	err = os.MkdirAll(filepath.Join(mgr.root, daemonLogStagingDir), 0755)
	if err != nil {
		return fmt.Errorf("failed to create daemon_log_staging dir: %w", err)
	}
	// Clean up any stale staged daemon logs from previous runs
	if entries, readErr := os.ReadDir(filepath.Join(mgr.root, daemonLogStagingDir)); readErr == nil {
		for _, e := range entries {
			if e.Type().IsRegular() {
				os.Remove(filepath.Join(mgr.root, daemonLogStagingDir, e.Name()))
			}
		}
	}

	// Load OSS config template if provided
	if ossCfgPath != "" {
		file, err := os.Open(ossCfgPath)
		if err != nil {
			return fmt.Errorf("failed to open oss config template file: %w", err)
		}
		defer file.Close()
		if err = json.NewDecoder(file).Decode(&mgr.ossCfgTemplate); err != nil {
			return fmt.Errorf("failed to load oss config template file: %w", err)
		}
	} else {
		return fmt.Errorf("oss config template path is required")
	}

	// Load Nydus config template if provided
	if nydusCfgPath != "" {
		file, err := os.Open(nydusCfgPath)
		if err != nil {
			return fmt.Errorf("failed to open nydus config template file: %w", err)
		}
		defer file.Close()
		if err = json.NewDecoder(file).Decode(&mgr.nydusCfgTemplate); err != nil {
			return fmt.Errorf("failed to load nydus config template file: %w", err)
		}
	} else {
		return fmt.Errorf("nydus config template path is required")
	}

	// Load OSS auths
	if ossAuthsPath != "" {
		file, err := os.Open(ossAuthsPath)
		if err != nil {
			return fmt.Errorf("failed to open OSS auths file: %w", err)
		}
		defer file.Close()
		mgr.ossAuths = make(OSSAuthsConfig)
		if err = json.NewDecoder(file).Decode(&mgr.ossAuths); err != nil {
			return fmt.Errorf("failed to load OSS auths file: %w", err)
		}
		logrus.Infof("loaded OSS auths for %d endpoint/bucket pairs", len(mgr.ossAuths))
	} else {
		return fmt.Errorf("oss auths path is required")
	}

	// Load registry auths
	if registryAuthsPath != "" {
		auths, err := registryauth.Load(registryAuthsPath)
		if err != nil {
			return fmt.Errorf("failed to load registry auths file: %w", err)
		}
		mgr.registryAuths = auths
		logrus.Infof("loaded registry auths for %d hosts/repos", len(mgr.registryAuths))
	} else {
		return fmt.Errorf("registry auths path is required")
	}

	return nil
}

func (mgr *manager) newDaemon(opts *DaemonCreateOpt) (*Daemon, error) {
	// Default to OSS if source type not specified
	sourceType := opts.SourceType
	if sourceType == "" {
		sourceType = "oss"
	}

	switch sourceType {
	case "nydus":
		return mgr.setupNydusDaemon(opts)
	case "oss":
		fallthrough
	default:
		return mgr.setupOSSDaemon(opts)
	}
}

// setupOSSDaemon creates a daemon for OSS source type
func (mgr *manager) setupOSSDaemon(opts *DaemonCreateOpt) (*Daemon, error) {
	d := &Daemon{
		ctx:        mgr.ctx,
		config:     &BackendConfig{},
		cgroupCtrl: mgr.cgroupCtrl,
	}
	d.meta.Name = opts.Name
	d.meta.ID = opts.ID
	d.meta.SourceType = "oss"

	if opts.MountPoint == "" {
		opts.MountPoint = filepath.Join(mgr.root, "mnt", d.meta.ID)
	}
	if err := os.MkdirAll(opts.MountPoint, 0755); err != nil {
		return nil, fmt.Errorf("failed to create mountpoint dir: %w", err)
	}
	d.meta.MountPoint = opts.MountPoint
	*d.config = mgr.ossCfgTemplate.DeepCopy()

	// Override OSS config if provided
	if opts.overwriteOSSConfig() {
		if d.config.Oss == nil {
			d.config.Oss = &OssConfig{}
		}
		d.config.Oss.Endpoint = opts.Endpoint
		d.config.Oss.BucketName = opts.Bucket
		d.config.Oss.ObjectPrefix = opts.ObjectPrefix
		logrus.Infof("overwriting OSS config (%s, %s, %s)",
			d.config.Oss.Endpoint, d.config.Oss.BucketName, d.config.Oss.ObjectPrefix)
	}
	if opts.AccessKeyID != "" && d.config.Oss != nil {
		d.config.Oss.AccessKeyId = opts.AccessKeyID
	}
	if opts.AccessKeySecret != "" && d.config.Oss != nil {
		d.config.Oss.AccessKeySecret = opts.AccessKeySecret
	}

	// If auth not provided, try to look up from ossAuths by endpoint/bucket
	if d.config.Oss != nil && d.config.Oss.AccessKeyId == "" && mgr.ossAuths != nil {
		endpoint := d.config.Oss.Endpoint
		bucket := d.config.Oss.BucketName
		lookupKey := endpoint + "/" + bucket
		if authEntry, ok := mgr.ossAuths[lookupKey]; ok {
			d.config.Oss.AccessKeyId = authEntry.AccessKeyID
			d.config.Oss.AccessKeySecret = authEntry.AccessKeySecret
			logrus.Infof("populated OSS auth for %s from auth file", lookupKey)
		} else {
			logrus.Debugf("no OSS auth found for %s in auth file", lookupKey)
		}
	}

	d.binPath = mgr.binPath
	err := os.MkdirAll(filepath.Join(mgr.root, "image_metas", d.meta.ID), 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create image meta dir: %w", err)
	}
	daemonDir := filepath.Join(mgr.root, "daemons", d.meta.ID)
	if err = os.MkdirAll(daemonDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create daemon dir: %w", err)
	}
	d.meta.DaemonDir = daemonDir
	d.meta.ImageMetaDir = filepath.Join(mgr.root, "image_metas", d.meta.ID)
	d.meta.DaemonLogPath = filepath.Join(daemonDir, "daemon.log")
	d.meta.PidFilePath = filepath.Join(daemonDir, "pid")
	d.meta.ChunkDBDir = filepath.Join(mgr.root, "chunk_db")
	d.meta.CachePath = filepath.Join(daemonDir, "cache")
	d.meta.CfgPath = filepath.Join(daemonDir, "backend.cfg")
	d.savedPath = filepath.Join(mgr.root, "daemon_configs", d.meta.ID+".json")
	d.updateExpired()

	return d, nil
}

// setupNydusDaemon creates a daemon for Nydus source type
func (mgr *manager) setupNydusDaemon(opts *DaemonCreateOpt) (*Daemon, error) {
	d := &Daemon{
		ctx:         mgr.ctx,
		config:      &BackendConfig{},
		nydusClient: mgr.nydusClient,
		cgroupCtrl:  mgr.cgroupCtrl,
	}
	d.meta.Name = opts.Name
	d.meta.ID = opts.ID
	d.meta.SourceType = "nydus"
	d.meta.ImageURL = opts.ImageURL

	if opts.MountPoint == "" {
		opts.MountPoint = filepath.Join(mgr.root, "mnt", d.meta.ID)
	}
	if err := os.MkdirAll(opts.MountPoint, 0755); err != nil {
		return nil, fmt.Errorf("failed to create mountpoint dir: %w", err)
	}
	d.meta.MountPoint = opts.MountPoint

	// Use Nydus config template (which should be a Nydus backend config with backend_type set)
	*d.config = mgr.nydusCfgTemplate.DeepCopy()
	d.binPath = mgr.binPath

	// Extract proxy URL from nydus config template
	if d.config.Registry != nil && d.config.Registry.Proxy != nil && d.config.Registry.Proxy.Url != "" {
		d.proxyURL = d.config.Registry.Proxy.Url
		logrus.Infof("using proxy %s for bootstrap download", d.proxyURL)
	}

	// Populate registry host/repo from image URL and fill auth if needed.
	if opts.ImageURL != "" && d.config.Registry != nil {
		ref, err := name.ParseReference(opts.ImageURL)
		if err != nil {
			logrus.Warnf("failed to parse image URL %s for registry config: %v", opts.ImageURL, err)
		} else {
			host := ref.Context().RegistryStr()
			repo := ref.Context().RepositoryStr()
			d.config.Registry.Host = host
			d.config.Registry.Repo = repo
			logrus.Infof("populated registry host/repo from image URL: %s/%s", host, repo)

			// Try to populate registry auth from registry auths file if not already set.
			if mgr.registryAuths != nil && d.config.Registry.Auth == "" {
				// Try host/repo first, then fallback to host only.
				hostRepo := host + "/" + repo
				if authEntry, ok := mgr.registryAuths[hostRepo]; ok {
					d.config.Registry.Auth = authEntry.Auth
					logrus.Infof("populated registry auth for %s from auth file", hostRepo)
				} else if authEntry, ok := mgr.registryAuths[host]; ok {
					d.config.Registry.Auth = authEntry.Auth
					logrus.Infof("populated registry auth for host %s from auth file", host)
				} else {
					logrus.Debugf("no registry auth found for %s or %s in auth file", hostRepo, host)
				}
			}
		}
	}

	// Create necessary directories
	err := os.MkdirAll(filepath.Join(mgr.root, "image_metas", d.meta.ID), 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create image meta dir: %w", err)
	}

	daemonDir := filepath.Join(mgr.root, "daemons", d.meta.ID)
	if err = os.MkdirAll(daemonDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create daemon dir: %w", err)
	}

	// Setup cache directory for Nydus
	cacheDir := filepath.Join(daemonDir, "cache_dir")
	if err = os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache dir: %w", err)
	}

	d.meta.DaemonDir = daemonDir
	d.meta.ImageMetaDir = filepath.Join(mgr.root, "image_metas", d.meta.ID)
	d.meta.DaemonLogPath = filepath.Join(daemonDir, "daemon.log")
	d.meta.PidFilePath = filepath.Join(daemonDir, "pid")
	d.meta.ChunkDBDir = filepath.Join(mgr.root, "chunk_db")
	d.meta.CacheDir = cacheDir
	d.meta.CfgPath = filepath.Join(daemonDir, "backend.cfg")
	// BootstrapPath will be set during Mount() when bootstrap is downloaded
	d.savedPath = filepath.Join(mgr.root, "daemon_configs", d.meta.ID+".json")
	d.updateExpired()

	return d, nil
}

func (mgr *manager) CreateDaemon(opts *DaemonCreateOpt) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if d, ok := mgr.daemons[opts.ID]; ok {
		d.updateExpired()
		// Clear mountFailed: a new CreateDaemon call means the caller intends
		// to use this daemon, so GC should not clean it up.
		d.mountFailed.Store(false)
		return nil
	}
	d, err := mgr.newDaemon(opts)
	if err != nil {
		return err
	}
	mgr.daemons[d.meta.ID] = d
	return nil
}

func (mgr *manager) GetDaemon(id string) *Daemon {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	d, ok := mgr.daemons[id]
	if ok {
		d.updateExpired()
		// Clear mountFailed: the caller retrieved this daemon to use it
		// (typically followed by d.Mount()). This prevents GC from cleaning
		// up the daemon in the window between GetDaemon and Mount.
		d.mountFailed.Store(false)
		return d
	}
	return nil
}

// cleanupDaemonResources removes all daemon resources from disk
// Caller must hold mgr.mu lock
func (mgr *manager) cleanupDaemonResources(d *Daemon) {
	logrus.WithFields(d.daemonLogFields()).Info("cleaning daemon resources")

	// Clean mount point to ensure FUSE filesystem is unmounted
	if err := d.cleanMountPoint(); err != nil {
		logrus.WithFields(d.daemonLogFields()).WithError(err).Warn("failed to clean mount point")
	}

	// Remove mount point directory if it's using the default path
	if d.meta.MountPoint != "" {
		defaultMountPath := filepath.Join(mgr.root, "mnt", d.meta.ID)
		if d.meta.MountPoint == defaultMountPath {
			if err := os.Remove(d.meta.MountPoint); err != nil && !os.IsNotExist(err) {
				logrus.Warnf("failed to remove mount point directory %s: %v", d.meta.MountPoint, err)
			}
		}
	}

	// Rescue daemon log for WARN/ERROR extraction before removing daemon dir
	rescueDaemonLog(mgr.root, d)

	// Clean daemon working directory
	if d.meta.DaemonDir != "" {
		if err := os.RemoveAll(d.meta.DaemonDir); err != nil {
			logrus.WithFields(d.daemonLogFields()).WithError(err).Warn("failed to remove daemon dir")
		}
	}

	// Clean image metadata directory
	if d.meta.ImageMetaDir != "" {
		if err := os.RemoveAll(d.meta.ImageMetaDir); err != nil {
			logrus.WithFields(d.daemonLogFields()).WithError(err).Warn("failed to remove image meta dir")
		}
	}

	// Clean daemon config file
	if d.savedPath != "" {
		if err := os.Remove(d.savedPath); err != nil && !os.IsNotExist(err) {
			logrus.WithFields(d.daemonLogFields()).WithError(err).Warn("failed to remove daemon config")
		}
	}
}

// getDiskUsage returns the disk usage percentage for the given path
func (mgr *manager) getDiskUsage(path string) (float64, error) {
	return diskusage.UsedPercentByFree(path)
}

func (mgr *manager) gcDaemons() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// First pass: collect daemons stuck after mount timeout.
	var failedDaemons []*Daemon
	for _, d := range mgr.daemons {
		if d.mountFailed.Load() {
			failedDaemons = append(failedDaemons, d)
		}
	}

	// Unmount alive failed daemons outside mgr.mu to avoid contention.
	// unmountForGC checks mountFailed under d.mu — if a new mount() cleared
	// the flag since we released mgr.mu, the unmount is safely aborted.
	if len(failedDaemons) > 0 {
		mgr.mu.Unlock()
		for _, d := range failedDaemons {
			if d.IsAlive() {
				logrus.WithFields(d.daemonLogFields()).Warn("gc: unmounting daemon with failed mount but running process")
				d.unmountForGC()
			}
		}
		mgr.mu.Lock()

		// Re-check and clean up: only delete daemons still marked as failed.
		for _, d := range failedDaemons {
			if !d.mountFailed.Load() {
				continue
			}
			logrus.WithFields(d.daemonLogFields()).Info("gc: cleaning daemon with failed mount")
			mgr.cleanupDaemonResources(d)
			delete(mgr.daemons, d.meta.ID)
		}
	}

	// Second pass: normal expiry-based GC.
	nrToDelete := 4
	for _, d := range mgr.daemons {
		if d.IsAlive() || time.Now().UnixNano() < d.expiredAt {
			continue
		}
		logrus.WithFields(d.daemonLogFields()).Info("delete daemon")

		mgr.cleanupDaemonResources(d)
		delete(mgr.daemons, d.meta.ID)

		nrToDelete--
		if nrToDelete <= 0 {
			break
		}
	}
}

// gcDaemonsByDiskPressure cleans up inactive daemons when disk usage exceeds threshold
func (mgr *manager) gcDaemonsByDiskPressure() {
	// Check disk usage
	usagePercent, err := mgr.getDiskUsage(mgr.root)
	if err != nil {
		logrus.Errorf("failed to get disk usage: %v", err)
		return
	}

	logrus.Debugf("disk usage: %.2f%%", usagePercent)

	// Only trigger GC when disk usage > 90%
	if usagePercent <= 90.0 {
		return
	}

	logrus.Warnf("disk usage %.2f%% exceeds threshold, triggering daemon GC", usagePercent)

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// Collect inactive daemons (not alive and expired)
	type daemonWithExpiry struct {
		daemon    *Daemon
		expiredAt int64
	}
	var inactiveDaemons []daemonWithExpiry

	for _, d := range mgr.daemons {
		// Only collect inactive daemons (not alive)
		if !d.IsAlive() {
			inactiveDaemons = append(inactiveDaemons, daemonWithExpiry{
				daemon:    d,
				expiredAt: d.expiredAt,
			})
		}
	}

	if len(inactiveDaemons) == 0 {
		logrus.Info("no inactive daemons available for cleanup")
		return
	}

	// Sort by expiredAt from smallest to largest (oldest first)
	sort.Slice(inactiveDaemons, func(i, j int) bool {
		return inactiveDaemons[i].expiredAt < inactiveDaemons[j].expiredAt
	})

	// Clean up daemons until disk usage drops below 85% or no more daemons to clean
	cleaned := 0
	for _, item := range inactiveDaemons {
		d := item.daemon
		logrus.WithFields(d.daemonLogFields()).WithField("expired_at", d.expiredAt).Info("cleaning up inactive daemon due to disk pressure")

		mgr.cleanupDaemonResources(d)
		delete(mgr.daemons, d.meta.ID)
		cleaned++

		// Re-check disk usage after each cleanup
		usagePercent, err = mgr.getDiskUsage(mgr.root)
		if err != nil {
			logrus.Errorf("failed to re-check disk usage: %v", err)
			break
		}

		logrus.Infof("disk usage after cleanup: %.2f%%", usagePercent)

		// Stop if usage drops below 85%
		if usagePercent < 85.0 {
			logrus.Infof("disk usage dropped to %.2f%%, stopping cleanup", usagePercent)
			break
		}
	}

	logrus.Infof("disk pressure GC completed, cleaned %d inactive daemons", cleaned)
}

func (mgr *manager) gcWorker() {
	gcTicker := time.NewTicker(2 * time.Minute)
	defer gcTicker.Stop()

	for range gcTicker.C {
		mgr.mu.RLock()
		total := len(mgr.daemons)
		mgr.mu.RUnlock()
		logrus.Infof("try gc daemons, total daemons number: %d", total)

		// First check if disk pressure requires urgent cleanup
		mgr.gcDaemonsByDiskPressure()

		// Then run normal GC for expired daemons
		mgr.gcDaemons()
	}
}

// CleanupDaemon manually cleans up a daemon and all its resources.
// The daemon must be in Stopped state. Caller should Unmount() first if needed.
func (mgr *manager) CleanupDaemon(daemonID string) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	d, ok := mgr.daemons[daemonID]
	if !ok {
		return fmt.Errorf("daemon not found: %s", daemonID)
	}

	// Only allow cleanup when daemon is stopped
	state := d.getState()
	if state != DaemonStateStopped {
		return fmt.Errorf("daemon %s is not stopped (state=%d), unmount it first", daemonID, state)
	}

	mgr.cleanupDaemonResources(d)
	delete(mgr.daemons, d.meta.ID)
	logrus.WithFields(d.daemonLogFields()).Info("successfully cleaned daemon")

	return nil
}

// ListDaemons returns basic information about all daemons
func (mgr *manager) ListDaemons() []DaemonInfo {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	infos := make([]DaemonInfo, 0, len(mgr.daemons))
	for _, d := range mgr.daemons {
		infos = append(infos, DaemonInfo{
			ID:         d.meta.ID,
			Name:       d.meta.Name,
			MountPoint: d.meta.MountPoint,
			SourceType: d.meta.SourceType,
			IsAlive:    d.IsAlive(),
		})
	}

	return infos
}

// checkChunkDBStats runs 'distill_fs stats-chunk' and returns the parsed stats
func (mgr *manager) checkChunkDBStats() (*ChunkDBStats, error) {
	chunkDBDir := filepath.Join(mgr.root, "chunk_db")
	cmd := exec.Command(mgr.binPath, "stats-chunk", "--chunk-db-dir", chunkDBDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run stats-chunk: %w, stderr: %s", err, stripANSI(stderr.String()))
	}

	var stats ChunkDBStats
	if err := json.Unmarshal(stdout.Bytes(), &stats); err != nil {
		return nil, fmt.Errorf("failed to parse stats-chunk output: %w, stdout: %s, stderr: %s", err, stripANSI(stdout.String()), stripANSI(stderr.String()))
	}

	logrus.Debugf("stats-chunk: %s", formatChunkDBStats(&stats))

	return &stats, nil
}

// stripANSI removes ANSI escape codes from the given string
func stripANSI(s string) string {
	// Regex pattern matches all ANSI escape sequences
	ansiPattern := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return ansiPattern.ReplaceAllString(s, "")
}

// formatBytes converts bytes to human-readable format (KB, MB, GB, TB)
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp])
}

// formatChunkDBStats formats ChunkDB stats into a human-readable string
func formatChunkDBStats(stats *ChunkDBStats) string {
	newestTime := time.Unix(stats.AccessTime.NewestEpochSecs, 0).Format("2006-01-02 15:04:05")
	oldestTime := time.Unix(stats.AccessTime.OldestEpochSecs, 0).Format("2006-01-02 15:04:05")

	return fmt.Sprintf("chunks=%d, readers=%d/%d(stale_cleared=%d), usage=%s%%, used=%s, free=%s, total=%s, access_time=[%s ~ %s]",
		stats.Chunks.TotalCount,
		stats.Readers.Current,
		stats.Readers.Max,
		stats.Readers.StaleCleared,
		stats.Storage.UsagePercent,
		formatBytes(stats.Storage.UsedSizeBytes),
		formatBytes(stats.Storage.FreeSizeBytes),
		formatBytes(stats.Storage.TotalSizeBytes),
		oldestTime,
		newestTime)
}

// gcChunkDB runs 'distill_fs gc-chunk' to clean up the ChunkDB
func (mgr *manager) gcChunkDB() error {
	chunkDBDir := filepath.Join(mgr.root, "chunk_db")
	cmd := exec.Command(mgr.binPath, "gc-chunk", "--chunk-db-dir", chunkDBDir)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to run gc-chunk: %w, output: %s", err, stripANSI(string(output)))
	}

	logrus.Infof("gc-chunk completed successfully, output: %s", stripANSI(string(output)))
	return nil
}

// chunkDBCleanupWorker periodically checks ChunkDB usage and triggers cleanup when needed
func (mgr *manager) chunkDBCleanupWorker() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		stats, err := mgr.checkChunkDBStats()
		if err != nil {
			logrus.Errorf("failed to check ChunkDB stats: %v", err)
			continue
		}

		// Log the stats
		logrus.Infof("ChunkDB stats: %s", formatChunkDBStats(stats))

		// Parse usage percentage and check if cleanup is needed
		var usagePercent float64
		if _, err := fmt.Sscanf(stats.Storage.UsagePercent, "%f", &usagePercent); err != nil {
			logrus.Errorf("failed to parse usage percent '%s': %v", stats.Storage.UsagePercent, err)
			continue
		}

		if usagePercent > 80 {
			logrus.Warnf("ChunkDB usage (%.2f%%) exceeds 80%%, triggering cleanup", usagePercent)
			if err := mgr.gcChunkDB(); err != nil {
				logrus.Errorf("failed to cleanup ChunkDB: %v", err)
			} else {
				logrus.Infof("ChunkDB cleanup completed successfully")

				// Check stats again after cleanup
				if newStats, err := mgr.checkChunkDBStats(); err == nil {
					logrus.Infof("ChunkDB stats after cleanup: %s", formatChunkDBStats(newStats))
				}
			}
		}
	}
}
