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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imgcgroup"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/registryauth"
)

const (
	daemonExpiredPeriod     = 30 * time.Minute
	mountReadinessLogPeriod = time.Second
)

// Timeout configurations for daemon operations
var (
	daemonMountTimeout   = 60 * time.Second
	daemonUnmountTimeout = 60 * time.Second
	statfsFunc           = unix.Statfs
)

// DaemonState represents the lifecycle state of a daemon
type DaemonState int32

const (
	DaemonStateStopped DaemonState = iota
	DaemonStateMounting
	DaemonStateRunning
	DaemonStateUnmounting
)

// Stopper provides a thread-safe way to signal daemon stop
type Stopper struct {
	done chan struct{}
	once sync.Once
}

// NewStopper creates a new Stopper
func NewStopper() *Stopper {
	return &Stopper{done: make(chan struct{})}
}

// Done returns a receive-only channel that will be closed when Close is called
func (s *Stopper) Done() <-chan struct{} {
	return s.done
}

// Close safely closes the done channel, can be called multiple times
func (s *Stopper) Close() {
	s.once.Do(func() {
		close(s.done)
	})
}

// ProxyConfig maps to nydus_api::ProxyConfig
type ProxyConfig struct {
	Url               string `json:"url,omitempty"`
	PingUrl           string `json:"ping_url,omitempty"`
	Fallback          bool   `json:"fallback,omitempty"`
	CheckInterval     uint64 `json:"check_interval,omitempty"`
	UseHttp           bool   `json:"use_http,omitempty"`
	CheckPauseElapsed uint64 `json:"check_pause_elapsed,omitempty"`
}

// OssConfig maps to nydus_api::OssConfig
type OssConfig struct {
	Scheme          string       `json:"scheme,omitempty"`
	Endpoint        string       `json:"endpoint,omitempty"`
	BucketName      string       `json:"bucket_name,omitempty"`
	ObjectPrefix    string       `json:"object_prefix,omitempty"`
	AccessKeyId     string       `json:"access_key_id,omitempty"`
	AccessKeySecret string       `json:"access_key_secret,omitempty"`
	SkipVerify      bool         `json:"skip_verify,omitempty"`
	Timeout         uint32       `json:"timeout,omitempty"`
	ConnectTimeout  uint32       `json:"connect_timeout,omitempty"`
	RetryLimit      uint8        `json:"retry_limit,omitempty"`
	Proxy           *ProxyConfig `json:"proxy,omitempty"`
}

// RegistryConfig maps to nydus_api::RegistryConfig
type RegistryConfig struct {
	Scheme             string       `json:"scheme,omitempty"`
	Host               string       `json:"host,omitempty"`
	Repo               string       `json:"repo,omitempty"`
	Auth               string       `json:"auth,omitempty"`
	SkipVerify         bool         `json:"skip_verify,omitempty"`
	Timeout            uint32       `json:"timeout,omitempty"`
	ConnectTimeout     uint32       `json:"connect_timeout,omitempty"`
	RetryLimit         uint8        `json:"retry_limit,omitempty"`
	RegistryToken      string       `json:"registry_token,omitempty"`
	BlobUrlScheme      string       `json:"blob_url_scheme,omitempty"`
	BlobRedirectedHost string       `json:"blob_redirected_host,omitempty"`
	Proxy              *ProxyConfig `json:"proxy,omitempty"`
}

// BackendConfig maps to nydus_api::BackendConfigV2
type BackendConfig struct {
	BackendType string          `json:"type"` // "oss", "registry", "localfs", etc.
	Oss         *OssConfig      `json:"oss,omitempty"`
	Registry    *RegistryConfig `json:"registry,omitempty"`
}

// OSSAuthEntry represents authentication credentials for an OSS endpoint
type OSSAuthEntry struct {
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
}

// OSSAuthsConfig maps OSS "endpoint/bucket" to their authentication credentials
type OSSAuthsConfig map[string]OSSAuthEntry

// RegistryAuthEntry represents authentication credentials for a registry.
type RegistryAuthEntry = registryauth.Entry

// RegistryAuthsConfig maps registry hosts/repos to their authentication credentials.
type RegistryAuthsConfig = registryauth.Config

// DeepCopy returns a deep copy of BackendConfig, duplicating all pointer fields
func (cfg *BackendConfig) DeepCopy() BackendConfig {
	out := *cfg
	if cfg.Oss != nil {
		ossCopy := *cfg.Oss
		if cfg.Oss.Proxy != nil {
			proxyCopy := *cfg.Oss.Proxy
			ossCopy.Proxy = &proxyCopy
		}
		out.Oss = &ossCopy
	}
	if cfg.Registry != nil {
		regCopy := *cfg.Registry
		if cfg.Registry.Proxy != nil {
			proxyCopy := *cfg.Registry.Proxy
			regCopy.Proxy = &proxyCopy
		}
		out.Registry = &regCopy
	}
	return out
}

func (cfg *BackendConfig) LoadTemplate(templatePath string) error {
	file, err := os.Open(templatePath)
	if err != nil {
		return fmt.Errorf("failed to open backend config template file, err= %w", err)
	}
	defer file.Close()
	if err = json.NewDecoder(file).Decode(cfg); err != nil {
		return fmt.Errorf("invalid json fmt file, path = %s, err = %w", templatePath, err)
	}
	return nil
}

type DaemonMeta struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	CfgPath       string   `json:"cfg_path"`
	MountPoint    string   `json:"mount_point"`
	DaemonDir     string   `json:"daemon_dir"`
	DaemonLogPath string   `json:"daemon_log_path"`
	PidFilePath   string   `json:"pid_file_path"`
	CachePath     string   `json:"cache_path"`
	ImageMetaDir  string   `json:"image_meta_dir"`
	ChunkDBDir    string   `json:"chunk_db_dir"`
	SourceType    string   `json:"source_type,omitempty"`    // "oss" or "nydus"
	BootstrapPath string   `json:"bootstrap_path,omitempty"` // For Nydus: path to bootstrap file
	CacheDir      string   `json:"cache_dir,omitempty"`      // For Nydus: --cache-dir parameter
	ImageURL      string   `json:"image_url,omitempty"`      // For Nydus: image URL for bootstrap download
	Env           []string `json:"env,omitempty"`            // Environment variables from image config
	EnvResolved   bool     `json:"env_resolved,omitempty"`   // True after env has been extracted (distinguishes nil env from unresolved)
}

// DaemonInfo contains basic information about a daemon
type DaemonInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	MountPoint string `json:"mount_point"`
	SourceType string `json:"source_type"`
	IsAlive    bool   `json:"is_alive"`
}

type Daemon struct {
	mu          sync.Mutex
	ctx         context.Context
	meta        DaemonMeta
	binPath     string
	config      *BackendConfig // Backend configuration (OSS, Nydus/Registry, etc.)
	savedPath   string
	stopChan    chan struct{}
	kickStop    *Stopper
	state       atomic.Int32 // DaemonState
	expiredAt   int64
	nydusClient NydusClient           // For Nydus: client to fetch bootstrap
	proxyURL    string                // For Nydus: proxy URL for bootstrap download
	cgroupCtrl  *imgcgroup.Controller // Memory cgroup controller (nil = disabled)

	// watcherActive indicates if watcher goroutine is active
	watcherActive atomic.Bool

	// userStopped indicates the daemon was explicitly unmounted by user/API call.
	// When set, automatic remount is suppressed.
	userStopped atomic.Bool

	// mountFailed indicates a mount attempt timed out without success.
	// GC uses this to detect and clean up orphaned daemon processes.
	mountFailed atomic.Bool

	// isAliveFunc allows mocking IsAlive() for testing
	isAliveFunc func() bool
}

func (d *Daemon) daemonLogFields() logrus.Fields {
	sourceType := d.meta.SourceType
	if sourceType == "" {
		sourceType = "oss"
	}

	fields := logrus.Fields{
		"daemon_id":   d.meta.ID,
		"daemon_name": d.meta.Name,
		"mount_point": d.meta.MountPoint,
		"source_type": sourceType,
	}
	if d.meta.ImageURL != "" {
		fields["image_url"] = d.meta.ImageURL
	}
	return fields
}

func (d *Daemon) saveMeta() error {
	file, err := os.OpenFile(d.savedPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", d.savedPath, err)
	}
	defer file.Close()
	if err = json.NewEncoder(file).Encode(&d.meta); err != nil {
		return fmt.Errorf("failed to dump json format: %w", err)
	}
	return nil
}

func (d *Daemon) loadBackendConfig() error {
	file, err := os.Open(d.meta.CfgPath)
	if err != nil {
		return fmt.Errorf("failed to load backend config, err = %w", err)
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(d.config)
}

func (d *Daemon) MountPoint() string {
	return d.meta.MountPoint
}

func (d *Daemon) Env() []string {
	return d.meta.Env
}

func (d *Daemon) Name() string {
	return d.meta.Name
}

func (d *Daemon) getState() DaemonState {
	return DaemonState(d.state.Load())
}

func (d *Daemon) setState(state DaemonState) {
	d.state.Store(int32(state))
}

// compareAndSwapState atomically compares and swaps the state
func (d *Daemon) compareAndSwapState(old, new DaemonState) bool {
	return d.state.CompareAndSwap(int32(old), int32(new))
}

func (d *Daemon) getPid() int {
	info, err := os.ReadFile(d.meta.PidFilePath)
	if err != nil {
		return -1
	}
	pid, err := strconv.Atoi(strings.TrimRight(string(info), "\n"))
	if err != nil {
		logrus.WithFields(d.daemonLogFields()).Warn("can't parse daemon pid file")
		return -1
	}
	return pid
}

func (d *Daemon) IsAlive() bool {
	// Allow mocking for tests
	if d.isAliveFunc != nil {
		return d.isAliveFunc()
	}

	pid := d.getPid()
	if pid <= 0 {
		return false
	}
	binPath, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	return binPath == d.binPath
}

func (d *Daemon) LoadExisted(metaFilePath string) error {
	file, err := os.Open(metaFilePath)
	if err != nil {
		return fmt.Errorf("failed to load from meta file, %w", err)
	}
	defer file.Close()
	if err = json.NewDecoder(file).Decode(&d.meta); err != nil {
		return fmt.Errorf("invalid json format, %w", err)
	}

	// Backward compatibility: default to "oss" if SourceType is not set
	if d.meta.SourceType == "" {
		d.meta.SourceType = "oss"
	}

	// Load backend config (works for both OSS and Nydus)
	d.config = &BackendConfig{}
	if err = d.loadBackendConfig(); err != nil {
		return err
	}

	if d.IsAlive() {
		d.kickStop = NewStopper()
		d.stopChan = make(chan struct{})
		d.setState(DaemonStateRunning)
		d.startWatch()
		logrus.WithFields(d.daemonLogFields()).Info("load active daemon")
	} else {
		d.setState(DaemonStateStopped)
		logrus.WithFields(d.daemonLogFields()).Info("load non-active daemon")
	}
	return nil
}

func (d *Daemon) updateExpired() {
	atomic.StoreInt64(&d.expiredAt, time.Now().Add(daemonExpiredPeriod).UnixNano())
}

func (d *Daemon) tick() bool {
	if !d.IsAlive() {
		return false
	}
	d.updateExpired()
	return true
}

func (d *Daemon) shouldRemount() bool {
	// Never remount if explicitly stopped by user/API
	if d.userStopped.Load() {
		return false
	}
	// Only remount if daemon was running (not mounting/unmounting/stopped)
	return d.getState() == DaemonStateRunning
}

func (d *Daemon) startWatch() {
	d.watcherActive.Store(true)
	go d.watch()
}

func (d *Daemon) watch() {
	ticker := time.NewTicker(5 * time.Second)
	defer func() {
		ticker.Stop()
		logrus.WithFields(d.daemonLogFields()).Info("daemon exited")
		close(d.stopChan)
		// Set watcherActive to false before remount
		// remount will call startWatch() which sets it back to true
		d.watcherActive.Store(false)
		if d.shouldRemount() {
			go d.remount()
		}
	}()

	for {
		select {
		case <-ticker.C:
			if !d.tick() {
				return
			}
		case <-d.kickStop.Done():
			for d.IsAlive() {
				time.Sleep(10 * time.Millisecond)
			}
			return
		}
	}
}

func (d *Daemon) remount() {
	// Early check: skip if user explicitly unmounted.
	// The authoritative check happens inside mount(false) under d.mu to close the race
	// window where Unmount() could execute between this check and acquiring the lock.
	if d.userStopped.Load() {
		logrus.WithFields(d.daemonLogFields()).Info("skip remount: daemon was explicitly unmounted")
		return
	}
	logrus.WithFields(d.daemonLogFields()).Info("try remount daemon")
	os.Remove(d.meta.PidFilePath)
	if err := d.mount(false); err != nil {
		logrus.WithFields(d.daemonLogFields()).WithError(err).Error("failed to remount daemon")
	}
}

func (d *Daemon) applyConfig() error {
	file, err := os.OpenFile(d.meta.CfgPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create config file, err = %w", err)
	}
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("failed to protect config file, err = %w", err)
	}

	// Write backend config (works for both OSS and Nydus)
	return json.NewEncoder(file).Encode(d.config)
}

// buildMountArgs generates CLI arguments for distill_fs based on source type
func (d *Daemon) buildMountArgs() []string {
	// Common arguments for both OSS and Nydus
	args := []string{
		"mount",
		"--daemon",
		"--log-file", d.meta.DaemonLogPath,
		"--pid-file", d.meta.PidFilePath,
		"--name", d.meta.Name,
		"--mountpoint", d.meta.MountPoint,
	}

	// Source-specific arguments
	sourceType := d.meta.SourceType
	if sourceType == "" {
		sourceType = "oss" // Default to OSS for backward compatibility
	}

	switch sourceType {
	case "nydus":
		args = append(args,
			"--cache-dir", d.meta.CacheDir,
			"--src", "nydus",
			"--bootstrap", d.meta.BootstrapPath,
		)
	case "oss":
		fallthrough
	default:
		args = append(args,
			"--cache-file", d.meta.CachePath,
			"--src", "oss",
		)
	}

	// Common arguments after source-specific ones
	args = append(args,
		"--cfg", d.meta.CfgPath,
		"--chunk-db-dir", d.meta.ChunkDBDir,
		"--image-meta-dir", d.meta.ImageMetaDir,
	)

	return args
}

func (d *Daemon) Mount() error {
	return d.mount(true)
}

// mount is the internal mount implementation.
// When userInitiated is true (explicit Mount call), userStopped is cleared to re-enable auto-remount.
// When userInitiated is false (auto-remount), userStopped is checked under lock and mount is
// rejected if the daemon was explicitly unmounted, closing the race window between remount()
// checking the flag and acquiring the lock.
func (d *Daemon) mount(userInitiated bool) error {
	// Start timing operation
	timing, _ := StartTimedOperation(d.ctx, "daemon.Mount", d.meta.ID)
	defer timing.End()
	logrus.WithFields(d.daemonLogFields()).Info("daemon mount path started")

	d.mu.Lock()
	defer d.mu.Unlock()

	// Clear mountFailed: a new mount attempt supersedes any prior timeout.
	// GC's unmountForGC checks this flag under d.mu, so they serialize correctly.
	d.mountFailed.Store(false)

	if userInitiated {
		// Clear userStopped flag: explicit Mount() re-enables auto-remount
		d.userStopped.Store(false)
	} else {
		// Auto-remount: recheck under lock to close the race with Unmount()
		if d.userStopped.Load() {
			logrus.WithFields(d.daemonLogFields()).Info("skip mount: daemon was explicitly unmounted")
			return fmt.Errorf("daemon %s was explicitly unmounted, skip auto-remount", d.meta.ID)
		}
	}

	// Check if daemon is already alive
	isAlive := d.IsAlive()
	state := d.getState()

	// Fast path: if already running and alive, return immediately
	if state == DaemonStateRunning && isAlive {
		logrus.WithFields(d.daemonLogFields()).Info("daemon already mounted")
		return nil
	}

	// If already mounting, skip starting new process but wait for it to complete
	if state != DaemonStateMounting {
		// Set state to Mounting at the beginning
		d.setState(DaemonStateMounting)

		// Start daemon process in background
		go d.startDaemonProcess()
	}

	// Wait for daemon to become running
	timeout := time.NewTimer(daemonMountTimeout)
	defer timeout.Stop()

	checkStart := time.Now()
	for {
		select {
		case <-timeout.C:
			d.mountFailed.Store(true)
			err := fmt.Errorf("timeout waiting for daemon %s to start", d.meta.ID)
			logrus.WithFields(d.daemonLogFields()).WithError(err).Error("daemon mount path failed")
			timing.Fail(err)
			return err
		default:
			state := d.getState()
			if state == DaemonStateRunning {
				timing.Stage("wait_daemon_running", time.Since(checkStart))
				logrus.WithFields(d.daemonLogFields()).Info("daemon mount path completed")
				return nil
			}
			if state == DaemonStateStopped {
				err := fmt.Errorf("daemon %s failed to start", d.meta.ID)
				logrus.WithFields(d.daemonLogFields()).WithError(err).Error("daemon mount path failed")
				timing.Fail(err)
				return err
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// startDaemonProcess starts the daemon process in background
func (d *Daemon) startDaemonProcess() {
	timing, ctx := StartTimedOperation(d.ctx, "daemon.startDaemonProcess", d.meta.ID)
	defer timing.End()

	// Ensure state is reset to Stopped on error
	defer func() {
		if d.getState() == DaemonStateMounting {
			d.setState(DaemonStateStopped)
		}
	}()

	if !d.watcherActive.Load() {
		if err := d.initializeDaemon(ctx, timing); err != nil {
			return
		}
	}

	// Stage 6: Wait for mount ready
	stageStart := time.Now()
	var lastProgressLog time.Time
	var lastErrorLog time.Time
	logrus.WithFields(d.daemonLogFields()).Info("waiting for mount readiness via statfs zero blocks")
	for {
		select {
		case <-d.stopChan:
			d.setState(DaemonStateStopped)
			logrus.WithFields(d.daemonLogFields()).Error("daemon exited abnormally")
			timing.Fail(fmt.Errorf("daemon exited"))
			return
		default:
			now := time.Now()
			isMountReady, fs, err := checkMountReady(d.MountPoint())
			if err != nil {
				if shouldLogMountReadiness(now, lastErrorLog) {
					lastErrorLog = now
					fields := d.daemonLogFields()
					fields["wait_elapsed_ms"] = now.Sub(stageStart).Milliseconds()
					logrus.WithFields(fields).WithError(err).Warn("mount readiness statfs failed, keep waiting")
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if isMountReady {
				elapsed := time.Since(stageStart)
				d.setState(DaemonStateRunning)
				timing.Stage("wait_mount_ready", elapsed)
				fields := d.daemonLogFields()
				fields["wait_elapsed_ms"] = elapsed.Milliseconds()
				logrus.WithFields(fields).Info("mount daemon successfully")
				return
			}
			if shouldLogMountReadiness(now, lastProgressLog) {
				lastProgressLog = now
				fields := d.daemonLogFields()
				fields["wait_elapsed_ms"] = now.Sub(stageStart).Milliseconds()
				fields["statfs_blocks"] = fs.Blocks
				fields["statfs_bsize"] = fs.Bsize
				logrus.WithFields(fields).Info("mount not ready yet, waiting for statfs zero blocks")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func checkMountReady(path string) (bool, unix.Statfs_t, error) {
	var fs unix.Statfs_t
	if err := statfsFunc(path, &fs); err != nil {
		return false, fs, fmt.Errorf("failed to statfs mountpoint %s: %w", path, err)
	}

	// distillfs is a FUSE filesystem. A successful statfs reporting zero blocks
	// is sufficient to prove the FUSE server is ready.
	return reportsZeroSize(&fs), fs, nil
}

func reportsZeroSize(fs *unix.Statfs_t) bool {
	return fs.Blocks == 0
}

func shouldLogMountReadiness(now, lastLog time.Time) bool {
	return lastLog.IsZero() || now.Sub(lastLog) >= mountReadinessLogPeriod
}

// initializeDaemon performs the full daemon initialization sequence:
// - Downloads Nydus bootstrap if needed
// - Cleans mount point
// - Applies configuration
// - Starts daemon process
// - Saves metadata
// - Initializes channels and starts watcher
func (d *Daemon) initializeDaemon(ctx context.Context, timing *TimedOperation) error {
	// For Nydus: download bootstrap if not exists
	if d.meta.SourceType == "nydus" && d.meta.BootstrapPath == "" {
		if d.meta.ImageURL == "" || d.nydusClient == nil {
			err := fmt.Errorf("ImageURL and nydusClient required for Nydus daemon")
			logrus.WithFields(d.daemonLogFields()).WithError(err).Error("failed to start daemon")
			timing.Fail(err)
			return err
		}

		stageStart := time.Now()
		logrus.WithFields(d.daemonLogFields()).Info("fetching Nydus bootstrap")
		extractedPath, envVars, err := d.nydusClient.FetchAndExtractBootstrap(ctx, d.meta.ImageURL, d.meta.DaemonDir, d.proxyURL)
		if err != nil {
			logrus.WithFields(d.daemonLogFields()).WithError(err).Error("failed to fetch and extract bootstrap")
			timing.Fail(err)
			return err
		}
		d.meta.BootstrapPath = extractedPath
		d.meta.Env = envVars
		d.meta.EnvResolved = true
		logrus.WithFields(d.daemonLogFields()).WithField("bootstrap_path", extractedPath).Info("extracted bootstrap")
		timing.Stage("fetch_bootstrap", time.Since(stageStart))

		// Save metadata with bootstrap path
		if err = d.saveMeta(); err != nil {
			logrus.WithFields(d.daemonLogFields()).WithError(err).Error("failed to save daemon meta after bootstrap download")
			timing.Fail(err)
			return err
		}
	} else if d.meta.SourceType == "nydus" && d.meta.BootstrapPath != "" && !d.meta.EnvResolved {
		// Inactive daemon with bootstrap already cached but env never resolved
		// (old metadata predating env support). Re-fetch to extract env.
		if d.nydusClient != nil && d.meta.ImageURL != "" {
			stageStart := time.Now()
			_, envVars, err := d.nydusClient.FetchAndExtractBootstrap(ctx, d.meta.ImageURL, d.meta.DaemonDir, d.proxyURL)
			if err != nil {
				logrus.WithFields(d.daemonLogFields()).WithError(err).Debug("failed to fetch env for existing daemon")
			} else {
				d.meta.Env = envVars
				d.meta.EnvResolved = true
				if saveErr := d.saveMeta(); saveErr != nil {
					logrus.WithFields(d.daemonLogFields()).WithError(saveErr).Warn("failed to persist env to daemon meta")
				}
			}
			timing.Stage("fetch_env_for_existing_daemon", time.Since(stageStart))
		}
	}

	// Stage 1: Clean mount point
	stageStart := time.Now()
	if err := d.cleanMountPoint(); err != nil {
		logrus.WithFields(d.daemonLogFields()).WithError(err).Error("failed to clean mountpoint")
		timing.Fail(err)
		return err
	}
	timing.Stage("clean_mount_point", time.Since(stageStart))

	// Stage 2: Apply config
	stageStart = time.Now()
	if err := d.applyConfig(); err != nil {
		logrus.WithFields(d.daemonLogFields()).WithError(err).Error("failed to apply config")
		timing.Fail(err)
		return err
	}
	timing.Stage("apply_config", time.Since(stageStart))

	// Stage 3: Build args and start process
	stageStart = time.Now()
	args := d.buildMountArgs()
	c := exec.CommandContext(ctx, d.binPath, args...)
	logrus.WithFields(d.daemonLogFields()).WithField("command", fmt.Sprintf("%s %s", d.binPath, strings.Join(args, " "))).Info("mounting daemon")

	// Apply cgroup settings before starting (v2: CgroupFD for clone3)
	d.cgroupCtrl.Apply(c)

	err := c.Start()
	if err != nil {
		logrus.WithFields(d.daemonLogFields()).WithError(err).Error("failed to start distill daemon")
		timing.Fail(err)
		return err
	}
	if err = c.Wait(); err != nil {
		logrus.WithFields(d.daemonLogFields()).WithError(err).Error("distill daemon exited abnormal")
		timing.Fail(err)
		return err
	}
	timing.Stage("start_daemon_process", time.Since(stageStart))

	// Add daemon PID to cgroup (v1: primary mechanism; v2: no-op)
	if pid := d.getPid(); pid > 0 {
		if err := d.cgroupCtrl.AddPID(pid); err != nil {
			logrus.WithFields(d.daemonLogFields()).Warnf("cgroup: failed to add pid %d: %v", pid, err)
		}
	}

	// Stage 4: Save metadata
	stageStart = time.Now()
	if err = d.saveMeta(); err != nil {
		logrus.WithFields(d.daemonLogFields()).WithError(err).Error("failed to save daemon meta")
		timing.Fail(err)
		return err
	}
	timing.Stage("save_metadata", time.Since(stageStart))

	// Stage 5: Initialize channels and start watch
	d.stopChan = make(chan struct{})
	d.kickStop = NewStopper()
	d.startWatch()

	return nil
}

func isMountPoint(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to stat path %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("could not get syscall.Stat_t for %s", path)
	}
	parentPath := filepath.Dir(path)
	parentInfo, err := os.Lstat(parentPath)
	if err != nil {
		return false, fmt.Errorf("failed to stat parent path %s: %w", parentPath, err)
	}

	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("could not get syscall.Stat_t for parent %s", parentPath)
	}
	if stat.Dev != parentStat.Dev {
		return true, nil
	}
	if path == parentPath {
		return true, nil
	}
	return false, nil
}

func (d *Daemon) cleanMountPoint() error {
	isMount, err := isMountPoint(d.meta.MountPoint)
	if err != nil {
		return fmt.Errorf("could not determine if '%s' is a mount point: %w", d.meta.MountPoint, err)
	}
	if !isMount {
		return nil
	}
	if err := syscall.Unmount(d.meta.MountPoint, 0); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("failed to unmount '%s' due to permission denied. Did you run as root? Error: %w",
				d.meta.MountPoint, err)
		}
		if errors.Is(err, syscall.EBUSY) {
			return fmt.Errorf("failed to unmount '%s' because it is busy. Error: %w", d.meta.MountPoint, err)
		}
		return fmt.Errorf("unmount syscall failed for '%s': %w", d.meta.MountPoint, err)
	}
	logrus.WithFields(d.daemonLogFields()).Info("successfully unmount using syscall")
	return nil
}

func (d *Daemon) Unmount() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.unmountLocked()
}

// unmountForGC attempts to unmount a daemon that was marked as mount-failed.
// It checks mountFailed under d.mu: if a new mount() cleared the flag, the
// unmount is aborted. This closes the race window where GC releases mgr.mu
// and a mount request arrives before unmount begins.
func (d *Daemon) unmountForGC() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.mountFailed.Load() {
		logrus.WithFields(d.daemonLogFields()).Info("gc: abort unmount, new mount cleared mountFailed")
		return false
	}
	d.unmountLocked()
	return true
}

// unmountLocked performs the actual unmount. Caller must hold d.mu.
func (d *Daemon) unmountLocked() error {
	// Start timing operation
	timing, _ := StartTimedOperation(d.ctx, "daemon.Unmount", d.meta.ID)
	defer timing.End()
	logrus.WithFields(d.daemonLogFields()).Info("daemon unmount path started")

	timeout := time.NewTimer(daemonUnmountTimeout)
	defer timeout.Stop()
	defer func() {
		stageStart := time.Now()
		err := d.cleanMountPoint()
		if err != nil {
			logrus.WithFields(d.daemonLogFields()).WithError(err).Warn("failed to clean mount point")
		}
		timing.Stage("clean_mount_point", time.Since(stageStart))

		// clean pid file
		if err = os.Remove(d.meta.PidFilePath); err != nil {
			logrus.WithFields(d.daemonLogFields()).WithError(err).Warn("failed to clean daemon pid file")
		}
		d.setState(DaemonStateStopped)
		d.updateExpired()
	}()

	// Mark as explicitly stopped to prevent automatic remount
	d.userStopped.Store(true)

	// Set state to Unmounting to prevent remount
	d.setState(DaemonStateUnmounting)

	// Stage 1: Signal daemon to stop
	stageStart := time.Now()
	if d.kickStop != nil {
		d.kickStop.Close()
	}
	timing.Stage("signal_stop", time.Since(stageStart))

	// Check if process is alive
	if !d.IsAlive() {
		logrus.WithFields(d.daemonLogFields()).Info("daemon is not alive, skip signal and wait for watch goroutine")
		// Wait for watch goroutine to exit only if it was started
		// The watch goroutine is started only when stopChan is created in startDaemonProcess()
		// If daemon never started successfully, stopChan will be nil
		if d.stopChan != nil {
			select {
			case <-d.stopChan:
				logrus.WithFields(d.daemonLogFields()).Info("daemon watch goroutine exited")
			case <-timeout.C:
				logrus.WithFields(d.daemonLogFields()).Warn("wait daemon watch goroutine timeout")
			}
		}
		logrus.WithFields(d.daemonLogFields()).Info("daemon unmount path completed")
		return nil
	}

	pid := d.getPid()
	if pid <= 0 {
		return nil
	}

	// Stage 2: Send SIGTERM
	stageStart = time.Now()
	p, _ := os.FindProcess(pid)
	logrus.WithFields(d.daemonLogFields()).WithField("pid", p.Pid).Info("send termination signal to daemon")
	err := p.Signal(syscall.SIGTERM)
	if err != nil {
		logrus.WithFields(d.daemonLogFields()).WithError(err).Error("daemon unmount path failed")
		timing.Fail(err)
		return fmt.Errorf("failed to send terminal signal to daemon %s, err = %w", d.meta.ID, err)
	}
	timing.Stage("send_sigterm", time.Since(stageStart))

	// Stage 3: Wait for graceful shutdown
	stageStart = time.Now()
	select {
	case <-d.stopChan:
		timing.Stage("wait_graceful_exit", time.Since(stageStart))
		logrus.WithFields(d.daemonLogFields()).Info("daemon unmount path completed")
		return nil
	case <-timeout.C:
		timing.Stage("wait_graceful_exit_timeout", time.Since(stageStart))
		logrus.WithFields(d.daemonLogFields()).Warn("wait daemon exited timeout, force kill it")

		// Stage 4: Force kill
		stageStart = time.Now()
		err = p.Kill()
		if err != nil {
			logrus.WithFields(d.daemonLogFields()).WithError(err).Warn("failed to send kill signal to daemon")
		}
		timing.Stage("send_sigkill", time.Since(stageStart))
	}

	timeout.Reset(5 * time.Second)

	// Stage 5: Final wait
	stageStart = time.Now()
	select {
	case <-d.stopChan:
		timing.Stage("wait_forced_exit", time.Since(stageStart))
		logrus.WithFields(d.daemonLogFields()).Info("daemon unmount path completed")
		return nil
	case <-timeout.C:
		timing.Stage("wait_forced_exit_timeout", time.Since(stageStart))
		err := fmt.Errorf("daemon %s is not exited", d.meta.ID)
		logrus.WithFields(d.daemonLogFields()).WithError(err).Error("daemon unmount path failed")
		timing.Fail(err)
		return err
	}
}
