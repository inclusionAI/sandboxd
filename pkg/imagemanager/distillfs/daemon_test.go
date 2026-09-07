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
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func TestBackendConfig_DeepCopy(t *testing.T) {
	tests := []struct {
		name string
		cfg  BackendConfig
	}{
		{
			name: "OSS config with proxy",
			cfg: BackendConfig{
				BackendType: "oss",
				Oss: &OssConfig{
					Endpoint:        "oss-cn-hangzhou.aliyuncs.com",
					BucketName:      "test-bucket",
					ObjectPrefix:    "prefix/",
					AccessKeyId:     "test-key",
					AccessKeySecret: "test-secret",
					Proxy: &ProxyConfig{
						Url:      "http://proxy:8080",
						Fallback: true,
					},
				},
			},
		},
		{
			name: "Registry config with proxy",
			cfg: BackendConfig{
				BackendType: "registry",
				Registry: &RegistryConfig{
					Host:   "docker.io",
					Repo:   "library/alpine",
					Auth:   "base64auth",
					Scheme: "https",
					Proxy: &ProxyConfig{
						Url:      "http://proxy:8080",
						Fallback: false,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copied := tt.cfg.DeepCopy()

			// Test that values are equal
			if copied.BackendType != tt.cfg.BackendType {
				t.Errorf("BackendType mismatch: got %s, want %s", copied.BackendType, tt.cfg.BackendType)
			}

			// Test that pointers are different (deep copy)
			if tt.cfg.Oss != nil {
				if copied.Oss == tt.cfg.Oss {
					t.Error("Oss config was not deep copied (same pointer)")
				}
				if copied.Oss.Endpoint != tt.cfg.Oss.Endpoint {
					t.Errorf("Oss.Endpoint mismatch: got %s, want %s", copied.Oss.Endpoint, tt.cfg.Oss.Endpoint)
				}
				if tt.cfg.Oss.Proxy != nil && copied.Oss.Proxy == tt.cfg.Oss.Proxy {
					t.Error("Oss.Proxy was not deep copied (same pointer)")
				}
			}

			if tt.cfg.Registry != nil {
				if copied.Registry == tt.cfg.Registry {
					t.Error("Registry config was not deep copied (same pointer)")
				}
				if copied.Registry.Host != tt.cfg.Registry.Host {
					t.Errorf("Registry.Host mismatch: got %s, want %s", copied.Registry.Host, tt.cfg.Registry.Host)
				}
				if tt.cfg.Registry.Proxy != nil && copied.Registry.Proxy == tt.cfg.Registry.Proxy {
					t.Error("Registry.Proxy was not deep copied (same pointer)")
				}
			}

			// Modify copied config and ensure original is unchanged
			if copied.Oss != nil {
				copied.Oss.Endpoint = "modified-endpoint"
				if tt.cfg.Oss.Endpoint == "modified-endpoint" {
					t.Error("Modifying copied config affected original")
				}
			}
		})
	}
}

func TestBackendConfig_LoadTemplate(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		wantErr     bool
		validate    func(*testing.T, *BackendConfig)
	}{
		{
			name: "valid OSS config",
			fileContent: `{
				"type": "oss",
				"oss": {
					"endpoint": "oss-cn-hangzhou.aliyuncs.com",
					"bucket_name": "test-bucket",
					"object_prefix": "images/"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *BackendConfig) {
				if cfg.BackendType != "oss" {
					t.Errorf("BackendType = %s, want oss", cfg.BackendType)
				}
				if cfg.Oss == nil {
					t.Fatal("Oss config is nil")
				}
				if cfg.Oss.Endpoint != "oss-cn-hangzhou.aliyuncs.com" {
					t.Errorf("Endpoint = %s, want oss-cn-hangzhou.aliyuncs.com", cfg.Oss.Endpoint)
				}
			},
		},
		{
			name: "valid registry config",
			fileContent: `{
				"type": "registry",
				"registry": {
					"host": "docker.io",
					"repo": "library/alpine",
					"scheme": "https"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, cfg *BackendConfig) {
				if cfg.BackendType != "registry" {
					t.Errorf("BackendType = %s, want registry", cfg.BackendType)
				}
				if cfg.Registry == nil {
					t.Fatal("Registry config is nil")
				}
				if cfg.Registry.Host != "docker.io" {
					t.Errorf("Host = %s, want docker.io", cfg.Registry.Host)
				}
			},
		},
		{
			name:        "invalid JSON",
			fileContent: `{invalid json}`,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "config.json")

			if err := os.WriteFile(tmpFile, []byte(tt.fileContent), 0644); err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}

			cfg := &BackendConfig{}
			err := cfg.LoadTemplate(tmpFile)

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestDaemon_SaveAndLoadMeta(t *testing.T) {
	tmpDir := t.TempDir()
	savedPath := filepath.Join(tmpDir, "daemon.json")

	originalMeta := DaemonMeta{
		ID:            "test-daemon-id",
		Name:          "test-daemon",
		MountPoint:    "/tmp/mnt",
		DaemonDir:     "/tmp/daemon",
		DaemonLogPath: "/tmp/daemon/log",
		PidFilePath:   "/tmp/daemon/pid",
		CfgPath:       "/tmp/daemon/cfg",
		CachePath:     "/tmp/daemon/cache",
		ImageMetaDir:  "/tmp/meta",
		ChunkDBDir:    "/tmp/chunkdb",
		SourceType:    "oss",
	}

	d := &Daemon{
		meta:      originalMeta,
		savedPath: savedPath,
	}

	// Test save
	if err := d.saveMeta(); err != nil {
		t.Fatalf("saveMeta() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(savedPath); os.IsNotExist(err) {
		t.Fatal("Meta file was not created")
	}

	// Test load
	loadedMeta := DaemonMeta{}
	file, err := os.Open(savedPath)
	if err != nil {
		t.Fatalf("Failed to open saved file: %v", err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&loadedMeta); err != nil {
		t.Fatalf("Failed to decode meta: %v", err)
	}

	// Verify loaded data matches original
	if loadedMeta.ID != originalMeta.ID {
		t.Errorf("ID = %s, want %s", loadedMeta.ID, originalMeta.ID)
	}
	if loadedMeta.Name != originalMeta.Name {
		t.Errorf("Name = %s, want %s", loadedMeta.Name, originalMeta.Name)
	}
	if loadedMeta.SourceType != originalMeta.SourceType {
		t.Errorf("SourceType = %s, want %s", loadedMeta.SourceType, originalMeta.SourceType)
	}
}

func TestDaemon_UpdateExpired(t *testing.T) {
	d := &Daemon{}

	before := time.Now()
	d.updateExpired()
	after := time.Now()

	expectedMin := before.Add(daemonExpiredPeriod).UnixNano()
	expectedMax := after.Add(daemonExpiredPeriod).UnixNano()

	if d.expiredAt < expectedMin || d.expiredAt > expectedMax {
		t.Errorf("expiredAt = %d, want between %d and %d", d.expiredAt, expectedMin, expectedMax)
	}
}

func TestDaemon_BuildMountArgs(t *testing.T) {
	tests := []struct {
		name        string
		daemon      *Daemon
		contains    []string
		notContains []string
	}{
		{
			name: "OSS daemon",
			daemon: &Daemon{
				meta: DaemonMeta{
					ID:            "oss-daemon",
					Name:          "test-oss",
					MountPoint:    "/mnt/oss",
					DaemonLogPath: "/var/log/daemon.log",
					PidFilePath:   "/var/run/daemon.pid",
					CachePath:     "/var/cache/daemon",
					CfgPath:       "/etc/daemon/config.json",
					ChunkDBDir:    "/var/chunkdb",
					ImageMetaDir:  "/var/meta",
					SourceType:    "oss",
				},
			},
			contains: []string{
				"mount",
				"--daemon",
				"--src", "oss",
				"--cache-file", "/var/cache/daemon",
				"--name", "test-oss",
				"--mountpoint", "/mnt/oss",
			},
			notContains: []string{"--bootstrap", "--cache-dir"},
		},
		{
			name: "Nydus daemon",
			daemon: &Daemon{
				meta: DaemonMeta{
					ID:            "nydus-daemon",
					Name:          "test-nydus",
					MountPoint:    "/mnt/nydus",
					DaemonLogPath: "/var/log/daemon.log",
					PidFilePath:   "/var/run/daemon.pid",
					CacheDir:      "/var/cache/nydus",
					BootstrapPath: "/var/bootstrap/image.boot",
					CfgPath:       "/etc/daemon/config.json",
					ChunkDBDir:    "/var/chunkdb",
					ImageMetaDir:  "/var/meta",
					SourceType:    "nydus",
				},
			},
			contains: []string{
				"mount",
				"--daemon",
				"--src", "nydus",
				"--cache-dir", "/var/cache/nydus",
				"--bootstrap", "/var/bootstrap/image.boot",
				"--name", "test-nydus",
				"--mountpoint", "/mnt/nydus",
			},
			notContains: []string{"--cache-file"},
		},
		{
			name: "Default to OSS when SourceType empty",
			daemon: &Daemon{
				meta: DaemonMeta{
					Name:          "default-daemon",
					MountPoint:    "/mnt/default",
					DaemonLogPath: "/var/log/daemon.log",
					PidFilePath:   "/var/run/daemon.pid",
					CachePath:     "/var/cache/daemon",
					CfgPath:       "/etc/daemon/config.json",
					ChunkDBDir:    "/var/chunkdb",
					ImageMetaDir:  "/var/meta",
					SourceType:    "", // Empty, should default to OSS
				},
			},
			contains: []string{
				"--src", "oss",
				"--cache-file", "/var/cache/daemon",
			},
			notContains: []string{"--bootstrap"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.daemon.buildMountArgs()

			// Check that all expected strings are present
			for _, s := range tt.contains {
				found := false
				for _, arg := range args {
					if arg == s {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected arg %q not found in %v", s, args)
				}
			}

			// Check that unwanted strings are not present
			for _, s := range tt.notContains {
				for _, arg := range args {
					if arg == s {
						t.Errorf("Unexpected arg %q found in %v", s, args)
					}
				}
			}
		})
	}
}

func TestDaemonCreateOpt_OverwriteOSSConfig(t *testing.T) {
	tests := []struct {
		name string
		opts *DaemonCreateOpt
		want bool
	}{
		{
			name: "All OSS fields provided",
			opts: &DaemonCreateOpt{
				Endpoint:     "oss-cn-hangzhou.aliyuncs.com",
				Bucket:       "test-bucket",
				ObjectPrefix: "prefix/",
			},
			want: true,
		},
		{
			name: "Missing endpoint",
			opts: &DaemonCreateOpt{
				Bucket:       "test-bucket",
				ObjectPrefix: "prefix/",
			},
			want: false,
		},
		{
			name: "Missing bucket",
			opts: &DaemonCreateOpt{
				Endpoint:     "oss-cn-hangzhou.aliyuncs.com",
				ObjectPrefix: "prefix/",
			},
			want: false,
		},
		{
			name: "Root object has empty prefix",
			opts: &DaemonCreateOpt{
				Endpoint: "oss-cn-hangzhou.aliyuncs.com",
				Bucket:   "test-bucket",
			},
			want: true,
		},
		{
			name: "All fields empty",
			opts: &DaemonCreateOpt{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.overwriteOSSConfig(); got != tt.want {
				t.Errorf("overwriteOSSConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

// mockDaemon creates a daemon with mocked dependencies for testing
type mockDaemon struct {
	*Daemon
	mockIsAlive    func() bool
	mockStartMount func() error
	mockStopMount  func() error
}

func (m *mockDaemon) IsAlive() bool {
	if m.mockIsAlive != nil {
		return m.mockIsAlive()
	}
	// Call the actual implementation directly to avoid infinite recursion
	// Check if PID file exists and process is running
	pidData, err := os.ReadFile(m.meta.PidFilePath)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func newMockDaemon(tmpDir string) *mockDaemon {
	d := &Daemon{
		ctx: context.Background(),
		meta: DaemonMeta{
			ID:            "test-daemon",
			Name:          "test",
			MountPoint:    filepath.Join(tmpDir, "mnt"),
			DaemonDir:     filepath.Join(tmpDir, "daemon"),
			DaemonLogPath: filepath.Join(tmpDir, "daemon.log"),
			PidFilePath:   filepath.Join(tmpDir, "daemon.pid"),
			CfgPath:       filepath.Join(tmpDir, "config.json"),
			CachePath:     filepath.Join(tmpDir, "cache"),
			ImageMetaDir:  filepath.Join(tmpDir, "meta"),
			ChunkDBDir:    filepath.Join(tmpDir, "chunkdb"),
			SourceType:    "oss",
		},
		savedPath: filepath.Join(tmpDir, "daemon.json"),
		binPath:   "/usr/bin/distillfs",
		config:    &BackendConfig{},
	}
	d.setState(DaemonStateStopped)
	d.kickStop = NewStopper()
	// Don't initialize stopChan here - it should only be created when daemon actually starts
	// in startDaemonProcess(). This prevents Unmount() from waiting forever on a channel
	// that will never be closed.

	mock := &mockDaemon{Daemon: d}

	// Set up the isAliveFunc to use the mock's function
	d.isAliveFunc = func() bool {
		return mock.IsAlive()
	}

	return mock
}

func TestDaemon_StartWatchOnlyOnce(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)
	mock.stopChan = make(chan struct{})
	mock.kickStop = NewStopper()
	mock.mockIsAlive = func() bool { return false }
	mock.setState(DaemonStateUnmounting)

	for i := 0; i < 10; i++ {
		mock.startWatch()
	}
	mock.kickStop.Close()

	select {
	case <-mock.stopChan:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop")
	}

	deadline := time.Now().Add(time.Second)
	for mock.watcherActive.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if mock.watcherActive.Load() {
		t.Fatal("watcher remained active after stopping")
	}
}

func TestDaemonApplyConfigProtectsCredentials(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	mock.config = &BackendConfig{
		BackendType: "registry",
		Registry: &RegistryConfig{
			Host: "registry.example.com",
			Auth: "sensitive-auth",
		},
	}

	if err := mock.applyConfig(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(mock.meta.CfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0600); got != want {
		t.Fatalf("config mode = %o, want %o", got, want)
	}
}

func TestDaemon_Mount_AlreadyRunning(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Set daemon to running state and mock IsAlive to return true
	mock.setState(DaemonStateRunning)
	mock.mockIsAlive = func() bool { return true }

	// Mount should return immediately without error
	err := mock.Mount()
	if err != nil {
		t.Errorf("Mount() on already running daemon should succeed, got error: %v", err)
	}

	// State should remain Running
	if mock.getState() != DaemonStateRunning {
		t.Errorf("State = %v, want %v", mock.getState(), DaemonStateRunning)
	}
}

func TestCheckMountReady_StatfsZeroBlocksStillReady(t *testing.T) {
	prevStatfs := statfsFunc
	t.Cleanup(func() {
		statfsFunc = prevStatfs
	})

	statfsFunc = func(path string, stat *unix.Statfs_t) error {
		stat.Bsize = 4096
		stat.Blocks = 0
		return nil
	}

	isReady, fs, err := checkMountReady("/mnt/test")
	if err != nil {
		t.Fatalf("checkMountReady() error = %v, want nil", err)
	}
	if !isReady {
		t.Fatal("checkMountReady() = false, want true")
	}
	if fs.Blocks != 0 {
		t.Fatalf("statfs blocks = %d, want 0", fs.Blocks)
	}
}

func TestCheckMountReady_StatfsNonZeroBlocksWaits(t *testing.T) {
	prevStatfs := statfsFunc
	t.Cleanup(func() {
		statfsFunc = prevStatfs
	})

	statfsFunc = func(path string, stat *unix.Statfs_t) error {
		stat.Bsize = 4096
		stat.Blocks = 1
		return nil
	}

	isReady, fs, err := checkMountReady("/mnt/test")
	if err != nil {
		t.Fatalf("checkMountReady() error = %v, want nil", err)
	}
	if isReady {
		t.Fatal("checkMountReady() = true, want false")
	}
	if fs.Blocks != 1 {
		t.Fatalf("statfs blocks = %d, want 1", fs.Blocks)
	}
}

func TestCheckMountReady_StatfsErrorReturnsError(t *testing.T) {
	prevStatfs := statfsFunc
	t.Cleanup(func() {
		statfsFunc = prevStatfs
	})

	statfsFunc = func(path string, stat *unix.Statfs_t) error {
		return syscall.EIO
	}

	isReady, _, err := checkMountReady("/mnt/test")
	if err == nil {
		t.Fatal("checkMountReady() error = nil, want non-nil")
	}
	if isReady {
		t.Fatal("checkMountReady() = true, want false")
	}
	if !strings.Contains(err.Error(), "failed to statfs mountpoint") {
		t.Fatalf("error %q does not contain statfs context", err.Error())
	}
}

func TestDaemon_StartDaemonProcess_RequiresStatfsReady(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	prevStatfs := statfsFunc
	t.Cleanup(func() {
		statfsFunc = prevStatfs
	})

	mock.watcherActive.Store(true)
	mock.stopChan = make(chan struct{})
	mock.setState(DaemonStateMounting)

	statfsFunc = func(path string, stat *unix.Statfs_t) error {
		stat.Bsize = 4096
		stat.Blocks = 0
		return nil
	}

	mock.startDaemonProcess()

	if mock.getState() != DaemonStateRunning {
		t.Errorf("State = %v, want %v", mock.getState(), DaemonStateRunning)
	}
}

func TestDaemon_StartDaemonProcess_NonZeroBlocksLogsProgressAndRecovers(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	prevStatfs := statfsFunc
	prevOutput := logrus.StandardLogger().Out
	prevLevel := logrus.GetLevel()
	t.Cleanup(func() {
		statfsFunc = prevStatfs
		logrus.SetOutput(prevOutput)
		logrus.SetLevel(prevLevel)
	})

	mock.watcherActive.Store(true)
	mock.stopChan = make(chan struct{})
	mock.setState(DaemonStateMounting)

	var statfsCalls atomic.Int32
	statfsFunc = func(path string, stat *unix.Statfs_t) error {
		if statfsCalls.Add(1) == 1 {
			stat.Bsize = 4096
			stat.Blocks = 1
			return nil
		}
		stat.Bsize = 4096
		stat.Blocks = 0
		return nil
	}

	var buf bytes.Buffer
	logrus.SetOutput(&buf)
	logrus.SetLevel(logrus.InfoLevel)

	mock.startDaemonProcess()

	if mock.getState() != DaemonStateRunning {
		t.Errorf("State = %v, want %v", mock.getState(), DaemonStateRunning)
	}
	if !strings.Contains(buf.String(), "mount not ready yet, waiting for statfs zero blocks") {
		t.Fatalf("progress log missing, got %q", buf.String())
	}
	if got := statfsCalls.Load(); got < 2 {
		t.Errorf("statfs calls = %d, want at least 2", got)
	}
}

func TestDaemon_StartDaemonProcess_ZeroSizeRuns(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	prevStatfs := statfsFunc
	t.Cleanup(func() {
		statfsFunc = prevStatfs
	})

	mock.watcherActive.Store(true)
	mock.stopChan = make(chan struct{})
	mock.setState(DaemonStateMounting)

	statfsFunc = func(path string, stat *unix.Statfs_t) error {
		stat.Bsize = 4096
		stat.Blocks = 0
		return nil
	}

	mock.startDaemonProcess()

	if mock.getState() != DaemonStateRunning {
		t.Errorf("State = %v, want %v", mock.getState(), DaemonStateRunning)
	}
}

func TestDaemon_StartDaemonProcess_StatfsErrorWarnsAndWaits(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	prevStatfs := statfsFunc
	prevOutput := logrus.StandardLogger().Out
	prevLevel := logrus.GetLevel()
	t.Cleanup(func() {
		statfsFunc = prevStatfs
		logrus.SetOutput(prevOutput)
		logrus.SetLevel(prevLevel)
	})

	mock.watcherActive.Store(true)
	mock.stopChan = make(chan struct{})
	mock.setState(DaemonStateMounting)

	statfsFunc = func(path string, stat *unix.Statfs_t) error {
		return syscall.EIO
	}

	var buf bytes.Buffer
	logrus.SetOutput(&buf)
	logrus.SetLevel(logrus.WarnLevel)

	done := make(chan struct{})
	go func() {
		mock.startDaemonProcess()
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)

	if mock.getState() != DaemonStateMounting {
		t.Errorf("State = %v, want %v", mock.getState(), DaemonStateMounting)
	}
	if !strings.Contains(buf.String(), "mount readiness statfs failed, keep waiting") {
		t.Fatalf("warning log missing, got %q", buf.String())
	}

	close(mock.stopChan)

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("startDaemonProcess() did not exit after stopChan closed")
	}

	if mock.getState() != DaemonStateStopped {
		t.Errorf("Final state = %v, want %v", mock.getState(), DaemonStateStopped)
	}
}

func TestDaemon_Mount_RemountDeadProcess(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Set daemon to running state but mock IsAlive to return false (dead process)
	mock.setState(DaemonStateRunning)
	mock.mockIsAlive = func() bool { return false }

	// Mount should detect dead process and attempt remount
	// This will fail because we don't have actual binary, but we can verify state transition
	err := mock.Mount()
	if err == nil {
		t.Error("Mount() should fail when trying to start actual process")
	}

	// State should have transitioned through Starting
	// Final state depends on mount failure, but it shouldn't be Running
	if mock.getState() == DaemonStateRunning {
		t.Error("State should not be Running after failed mount")
	}
}

func TestDaemon_Mount_ConcurrentCalls(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	mock.mockIsAlive = func() bool { return false }

	// Launch multiple concurrent Mount calls
	const numGoroutines = 10
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			errChan <- mock.Mount()
		}()
	}

	// Collect all errors
	errors := make([]error, 0, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		errors = append(errors, <-errChan)
	}

	// All should fail (no actual binary), but importantly, no panic or race condition
	for i, err := range errors {
		if err == nil {
			t.Errorf("Goroutine %d: expected error, got nil", i)
		}
	}
}

func TestDaemon_Mount_StateTransitions(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Initial state should be Stopped
	if mock.getState() != DaemonStateStopped {
		t.Errorf("Initial state = %v, want %v", mock.getState(), DaemonStateStopped)
	}

	mock.mockIsAlive = func() bool { return false }

	// Attempt mount (will fail without actual binary)
	_ = mock.Mount()

	// State should not be Running after failed mount
	if mock.getState() == DaemonStateRunning {
		t.Error("State should not be Running after failed mount")
	}
}

func TestDaemon_Unmount_NotRunning(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Daemon is in Stopped state
	mock.setState(DaemonStateStopped)

	// Unmount on stopped daemon - will complete but log warnings
	err := mock.Unmount()
	// Should succeed (no error) as it cleans up mount point
	if err != nil {
		t.Errorf("Unmount() on stopped daemon returned error: %v", err)
	}

	// State should be Stopped
	if mock.getState() != DaemonStateStopped {
		t.Errorf("State = %v, want %v", mock.getState(), DaemonStateStopped)
	}
}

func TestDaemon_Unmount_AlreadyUnmounting(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Set daemon to Unmounting state
	mock.setState(DaemonStateUnmounting)

	// Unmount should complete
	err := mock.Unmount()
	if err != nil {
		t.Errorf("Unmount() returned error: %v", err)
	}
}

func TestDaemon_Unmount_ConcurrentCalls(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Set daemon to Running state with channels initialized
	mock.setState(DaemonStateRunning)
	stopChan := make(chan struct{})
	mock.stopChan = stopChan
	mock.kickStop = NewStopper()
	mock.mockIsAlive = func() bool { return false } // Process not alive

	// Simulate the watch goroutine by closing stopChan when kickStop is triggered
	go func() {
		<-mock.kickStop.Done()
		close(stopChan)
	}()

	// Launch multiple concurrent Unmount calls
	const numGoroutines = 5
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			errChan <- mock.Unmount()
		}()
	}

	// Collect all errors - all should succeed since process is not alive
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		if err != nil {
			t.Errorf("Unmount() call %d failed: %v", i, err)
		}
	}

	// Final state should be Stopped
	if mock.getState() != DaemonStateStopped {
		t.Errorf("Final state = %v, want %v", mock.getState(), DaemonStateStopped)
	}
}

func TestDaemon_Unmount_StateTransition(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Set daemon to Running state
	mock.setState(DaemonStateRunning)
	mock.stopChan = make(chan struct{})
	mock.kickStop = NewStopper()
	mock.mockIsAlive = func() bool { return false }

	// Simulate the watch goroutine by closing stopChan when kickStop is triggered
	go func() {
		<-mock.kickStop.Done()
		close(mock.stopChan)
	}()

	// Unmount should transition to Unmounting then Stopped
	err := mock.Unmount()
	if err != nil {
		t.Errorf("Unmount() failed: %v", err)
	}

	// Final state should be Stopped
	if mock.getState() != DaemonStateStopped {
		t.Errorf("Final state = %v, want %v", mock.getState(), DaemonStateStopped)
	}
}

func TestDaemon_Mount_Unmount_Sequence(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Initial state: Stopped
	if mock.getState() != DaemonStateStopped {
		t.Errorf("Initial state = %v, want %v", mock.getState(), DaemonStateStopped)
	}

	// Unmount on stopped daemon should succeed (cleanup)
	err := mock.Unmount()
	if err != nil {
		t.Errorf("Unmount() on stopped daemon failed: %v", err)
	}

	// Set to Running state (simulating successful mount)
	mock.setState(DaemonStateRunning)
	mock.stopChan = make(chan struct{})
	mock.kickStop = NewStopper()
	mock.mockIsAlive = func() bool { return true }

	// Mount on running daemon should succeed immediately
	err = mock.Mount()
	if err != nil {
		t.Errorf("Mount() on running daemon failed: %v", err)
	}

	// Unmount should succeed
	// Use a fake PID that doesn't exist to avoid sending signals to the test process
	fakePid := 99999
	err = os.WriteFile(mock.meta.PidFilePath, []byte(fmt.Sprintf("%d\n", fakePid)), 0644)
	if err != nil {
		t.Fatalf("Failed to create PID file: %v", err)
	}

	// Make IsAlive return false so Unmount doesn't try to signal the process
	mock.mockIsAlive = func() bool { return false }

	// Simulate the watch goroutine closing stopChan when daemon stops
	go func() {
		// Wait a bit to simulate daemon stopping
		time.Sleep(10 * time.Millisecond)
		close(mock.stopChan)
	}()

	err = mock.Unmount()
	if err != nil {
		t.Errorf("Unmount() failed: %v", err)
	}

	// Final state should be Stopped
	if mock.getState() != DaemonStateStopped {
		t.Errorf("Final state = %v, want %v", mock.getState(), DaemonStateStopped)
	}
}

func TestDaemon_CompareAndSwapState(t *testing.T) {
	tmpDir := t.TempDir()
	mock := newMockDaemon(tmpDir)

	// Set initial state
	mock.setState(DaemonStateStopped)

	// Successful CAS
	if !mock.compareAndSwapState(DaemonStateStopped, DaemonStateMounting) {
		t.Error("compareAndSwapState should succeed")
	}
	if mock.getState() != DaemonStateMounting {
		t.Errorf("State = %v, want %v", mock.getState(), DaemonStateMounting)
	}

	// Failed CAS (wrong old value)
	if mock.compareAndSwapState(DaemonStateStopped, DaemonStateRunning) {
		t.Error("compareAndSwapState should fail with wrong old value")
	}
	if mock.getState() != DaemonStateMounting {
		t.Errorf("State = %v, want %v (should be unchanged)", mock.getState(), DaemonStateMounting)
	}
}
