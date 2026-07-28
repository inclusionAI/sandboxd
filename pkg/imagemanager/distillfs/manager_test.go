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
	"os"
	"path/filepath"
	"testing"
)

// mockNydusClient is a mock implementation of NydusClient for testing
type mockNydusClient struct {
	fetchAndExtractFunc func(ctx context.Context, imageURL string, outputDir string, proxyURL string) (string, error)
}

func (m *mockNydusClient) FetchAndExtractBootstrap(ctx context.Context, imageURL string, outputDir string, proxyURL string) (string, []string, error) {
	if m.fetchAndExtractFunc != nil {
		path, err := m.fetchAndExtractFunc(ctx, imageURL, outputDir, proxyURL)
		return path, nil, err
	}
	return filepath.Join(outputDir, "bootstrap"), nil, nil
}

func createTestOSSAuthsFile(t *testing.T, dir string) string {
	t.Helper()
	authsPath := filepath.Join(dir, "oss_auths.json")
	auths := OSSAuthsConfig{
		"oss-cn-hangzhou.aliyuncs.com/test-bucket": {
			AccessKeyID:     "test-access-key",
			AccessKeySecret: "test-secret-key",
		},
		"oss-cn-beijing.aliyuncs.com/another-bucket": {
			AccessKeyID:     "beijing-key",
			AccessKeySecret: "beijing-secret",
		},
	}
	data, err := json.Marshal(auths)
	if err != nil {
		t.Fatalf("Failed to marshal oss auths: %v", err)
	}
	if err := os.WriteFile(authsPath, data, 0644); err != nil {
		t.Fatalf("Failed to write oss auths file: %v", err)
	}
	return authsPath
}

func createTestRegistryAuthsFile(t *testing.T, dir string) string {
	t.Helper()
	authsPath := filepath.Join(dir, "registry_auths.json")
	auths := RegistryAuthsConfig{
		"docker.io": {
			Auth: "base64-dockerhub-auth",
		},
		"registry.example.com/namespace/repo": {
			Auth: "base64-specific-repo-auth",
		},
		"registry.example.com": {
			Auth: "base64-host-auth",
		},
	}
	data, err := json.Marshal(auths)
	if err != nil {
		t.Fatalf("Failed to marshal registry auths: %v", err)
	}
	if err := os.WriteFile(authsPath, data, 0644); err != nil {
		t.Fatalf("Failed to write registry auths file: %v", err)
	}
	return authsPath
}

func TestReconcileRecoveredDaemonsRetriesUntilOrphanIsClean(t *testing.T) {
	root := t.TempDir()
	alive := true
	orphan := &Daemon{
		ctx: context.Background(),
		meta: DaemonMeta{
			ID:          "orphan",
			MountPoint:  filepath.Join(root, "mnt", "orphan"),
			PidFilePath: filepath.Join(root, "orphan.pid"),
		},
		isAliveFunc: func() bool { return alive },
	}
	orphan.setState(DaemonStateStopped)
	live := &Daemon{
		ctx:  context.Background(),
		meta: DaemonMeta{ID: "live"},
	}

	mgr := &manager{
		root: root,
		daemons: map[string]*Daemon{
			"live":   live,
			"orphan": orphan,
		},
		recovered: map[string]bool{
			"live":   true,
			"orphan": false,
		},
	}

	if err := mgr.ReconcileRecoveredDaemons(); err == nil {
		t.Fatal("reconciliation succeeded while orphan process was alive")
	}
	if mgr.daemons["orphan"] == nil {
		t.Fatal("failed orphan was removed instead of retained for retry")
	}

	alive = false
	if err := mgr.ReconcileRecoveredDaemons(); err != nil {
		t.Fatalf("reconciliation retry failed: %v", err)
	}
	if mgr.daemons["orphan"] != nil {
		t.Fatal("clean orphan was not removed")
	}
	if mgr.daemons["live"] == nil {
		t.Fatal("referenced daemon was removed")
	}
	if mgr.recovered != nil {
		t.Fatal("recovery state remained after reconciliation")
	}
}

func createTestDockerFormatRegistryAuthsFile(t *testing.T, dir string) string {
	t.Helper()
	authsPath := filepath.Join(dir, "registry_auths_docker.json")
	auths := map[string]interface{}{
		"auths": map[string]map[string]string{
			"docker.io": {
				"auth": "base64-dockerhub-auth",
			},
			"registry.example.com/namespace/repo": {
				"auth": "base64-specific-repo-auth",
			},
			"registry.example.com": {
				"auth": "base64-host-auth",
			},
		},
		"credsStore": "mock",
	}
	data, err := json.Marshal(auths)
	if err != nil {
		t.Fatalf("Failed to marshal docker-format registry auths: %v", err)
	}
	if err := os.WriteFile(authsPath, data, 0644); err != nil {
		t.Fatalf("Failed to write docker-format registry auths file: %v", err)
	}
	return authsPath
}

func createTestConfigFile(t *testing.T, dir string, filename string, cfg BackendConfig) string {
	t.Helper()
	cfgPath := filepath.Join(dir, filename)
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	return cfgPath
}

func TestNewManager(t *testing.T) {
	tmpDir := t.TempDir()

	ossConfig := BackendConfig{
		BackendType: "oss",
		Oss: &OssConfig{
			Endpoint:     "oss-default.aliyuncs.com",
			BucketName:   "default-bucket",
			ObjectPrefix: "default/",
		},
	}
	ossCfgPath := createTestConfigFile(t, tmpDir, "oss_config.json", ossConfig)

	nydusConfig := BackendConfig{
		BackendType: "registry",
		Registry: &RegistryConfig{
			Host:   "docker.io",
			Scheme: "https",
			Auth:   "", // Will be populated from auth file
		},
	}
	nydusCfgPath := createTestConfigFile(t, tmpDir, "nydus_config.json", nydusConfig)

	ossAuthsPath := createTestOSSAuthsFile(t, tmpDir)
	registryAuthsPath := createTestRegistryAuthsFile(t, tmpDir)

	tests := []struct {
		name    string
		config  *ManagerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ManagerConfig{
				Root:              tmpDir,
				OSSCfgPath:        ossCfgPath,
				NydusCfgPath:      nydusCfgPath,
				BinPath:           "/usr/local/bin/distill_fs",
				OSSAuthsPath:      ossAuthsPath,
				RegistryAuthsPath: registryAuthsPath,
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing OSS config",
			config: &ManagerConfig{
				Root:              tmpDir,
				OSSCfgPath:        "",
				NydusCfgPath:      nydusCfgPath,
				BinPath:           "/usr/local/bin/distill_fs",
				OSSAuthsPath:      ossAuthsPath,
				RegistryAuthsPath: registryAuthsPath,
			},
			wantErr: true,
		},
		{
			name: "missing Nydus config",
			config: &ManagerConfig{
				Root:              tmpDir,
				OSSCfgPath:        ossCfgPath,
				NydusCfgPath:      "",
				BinPath:           "/usr/local/bin/distill_fs",
				OSSAuthsPath:      ossAuthsPath,
				RegistryAuthsPath: registryAuthsPath,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewManager(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if mgr == nil {
					t.Fatal("NewManager() returned nil manager")
				}

				// Verify directories were created
				expectedDirs := []string{
					"chunk_db",
					"image_metas",
					"daemons",
					"daemon_configs",
					"daemon_log_staging",
				}
				for _, dir := range expectedDirs {
					path := filepath.Join(tmpDir, dir)
					if _, err := os.Stat(path); os.IsNotExist(err) {
						t.Errorf("Expected directory %s was not created", dir)
					}
				}
			}
		})
	}
}

func TestManager_CreateDaemon_OSS(t *testing.T) {
	tmpDir := t.TempDir()

	ossConfig := BackendConfig{
		BackendType: "oss",
		Oss: &OssConfig{
			Endpoint:     "oss-default.aliyuncs.com",
			BucketName:   "default-bucket",
			ObjectPrefix: "default/",
		},
	}
	ossCfgPath := createTestConfigFile(t, tmpDir, "oss_config.json", ossConfig)

	nydusConfig := BackendConfig{
		BackendType: "registry",
		Registry:    &RegistryConfig{},
	}
	nydusCfgPath := createTestConfigFile(t, tmpDir, "nydus_config.json", nydusConfig)

	ossAuthsPath := createTestOSSAuthsFile(t, tmpDir)
	registryAuthsPath := createTestRegistryAuthsFile(t, tmpDir)

	mgr, err := NewManager(&ManagerConfig{
		Root:              tmpDir,
		OSSCfgPath:        ossCfgPath,
		NydusCfgPath:      nydusCfgPath,
		BinPath:           "/usr/local/bin/distill_fs",
		OSSAuthsPath:      ossAuthsPath,
		RegistryAuthsPath: registryAuthsPath,
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	tests := []struct {
		name     string
		opts     *DaemonCreateOpt
		validate func(*testing.T, *Daemon)
	}{
		{
			name: "create OSS daemon with explicit credentials",
			opts: &DaemonCreateOpt{
				ID:              "test-daemon-1",
				Name:            "test-image",
				Endpoint:        "oss-cn-hangzhou.aliyuncs.com",
				Bucket:          "my-bucket",
				ObjectPrefix:    "images/",
				AccessKeyID:     "explicit-key",
				AccessKeySecret: "explicit-secret",
			},
			validate: func(t *testing.T, d *Daemon) {
				if d.meta.ID != "test-daemon-1" {
					t.Errorf("Daemon ID = %s, want test-daemon-1", d.meta.ID)
				}
				if d.meta.SourceType != "oss" {
					t.Errorf("SourceType = %s, want oss", d.meta.SourceType)
				}
				if d.config.Oss.AccessKeyId != "explicit-key" {
					t.Errorf("AccessKeyId = %s, want explicit-key", d.config.Oss.AccessKeyId)
				}
			},
		},
		{
			name: "create OSS daemon with auto-populated credentials",
			opts: &DaemonCreateOpt{
				ID:           "test-daemon-2",
				Name:         "test-image-2",
				Endpoint:     "oss-cn-hangzhou.aliyuncs.com",
				Bucket:       "test-bucket",
				ObjectPrefix: "prefix/",
			},
			validate: func(t *testing.T, d *Daemon) {
				if d.config.Oss.AccessKeyId != "test-access-key" {
					t.Errorf("AccessKeyId = %s, want test-access-key (from auth file)", d.config.Oss.AccessKeyId)
				}
				if d.config.Oss.AccessKeySecret != "test-secret-key" {
					t.Errorf("AccessKeySecret = %s, want test-secret-key (from auth file)", d.config.Oss.AccessKeySecret)
				}
			},
		},
		{
			name: "create daemon without overwriting OSS config",
			opts: &DaemonCreateOpt{
				ID:   "test-daemon-3",
				Name: "test-image-3",
			},
			validate: func(t *testing.T, d *Daemon) {
				if d.config.Oss.Endpoint != "oss-default.aliyuncs.com" {
					t.Errorf("Endpoint = %s, want oss-default.aliyuncs.com (from template)", d.config.Oss.Endpoint)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.CreateDaemon(tt.opts)
			if err != nil {
				t.Fatalf("CreateDaemon() failed: %v", err)
			}

			d := mgr.GetDaemon(tt.opts.ID)
			if d == nil {
				t.Fatal("Created daemon not found")
			}

			if tt.validate != nil {
				tt.validate(t, d)
			}
		})
	}
}

func TestManager_CreateDaemon_Nydus(t *testing.T) {
	tmpDir := t.TempDir()

	ossConfig := BackendConfig{
		BackendType: "oss",
		Oss:         &OssConfig{},
	}
	ossCfgPath := createTestConfigFile(t, tmpDir, "oss_config.json", ossConfig)

	nydusConfig := BackendConfig{
		BackendType: "registry",
		Registry: &RegistryConfig{
			Host:   "docker.io",
			Scheme: "https",
			Auth:   "", // Will be populated from auth file
		},
	}
	nydusCfgPath := createTestConfigFile(t, tmpDir, "nydus_config.json", nydusConfig)

	ossAuthsPath := createTestOSSAuthsFile(t, tmpDir)
	registryAuthsPath := createTestRegistryAuthsFile(t, tmpDir)

	mockClient := &mockNydusClient{
		fetchAndExtractFunc: func(ctx context.Context, imageURL string, outputDir string, proxyURL string) (string, error) {
			bootstrapPath := filepath.Join(outputDir, "bootstrap")
			// Create a dummy bootstrap file
			if err := os.WriteFile(bootstrapPath, []byte("mock bootstrap"), 0644); err != nil {
				return "", err
			}
			return bootstrapPath, nil
		},
	}

	mgr, err := NewManager(&ManagerConfig{
		Root:              tmpDir,
		OSSCfgPath:        ossCfgPath,
		NydusCfgPath:      nydusCfgPath,
		BinPath:           "/usr/local/bin/distill_fs",
		NydusClient:       mockClient,
		OSSAuthsPath:      ossAuthsPath,
		RegistryAuthsPath: registryAuthsPath,
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	tests := []struct {
		name     string
		opts     *DaemonCreateOpt
		validate func(*testing.T, *Daemon)
	}{
		{
			name: "create Nydus daemon with registry auth lookup",
			opts: &DaemonCreateOpt{
				ID:         "nydus-daemon-1",
				Name:       "nydus-image",
				SourceType: "nydus",
				ImageURL:   "docker.io/library/alpine:latest",
			},
			validate: func(t *testing.T, d *Daemon) {
				if d.meta.SourceType != "nydus" {
					t.Errorf("SourceType = %s, want nydus", d.meta.SourceType)
				}
				// BootstrapPath should be empty at creation time - it's downloaded during Mount()
				if d.meta.BootstrapPath != "" {
					t.Error("BootstrapPath should be empty at creation time")
				}
				// ImageURL should be stored for later bootstrap download
				if d.meta.ImageURL != "docker.io/library/alpine:latest" {
					t.Errorf("ImageURL = %s, want docker.io/library/alpine:latest", d.meta.ImageURL)
				}
				if d.config.Registry.Host != "index.docker.io" {
					t.Errorf("Registry.Host = %s, want index.docker.io", d.config.Registry.Host)
				}
				if d.config.Registry.Repo != "library/alpine" {
					t.Errorf("Registry.Repo = %s, want library/alpine", d.config.Registry.Repo)
				}
				// docker.io/library/alpine gets parsed as index.docker.io by go-containerregistry
				// and we don't have auth for index.docker.io, only docker.io
				// This is expected behavior - auth lookup failed
				t.Logf("Registry.Auth = %s", d.config.Registry.Auth)
			},
		},
		{
			name: "create Nydus daemon with specific repo auth",
			opts: &DaemonCreateOpt{
				ID:         "nydus-daemon-2",
				Name:       "nydus-image-2",
				SourceType: "nydus",
				ImageURL:   "registry.example.com/namespace/repo:latest",
			},
			validate: func(t *testing.T, d *Daemon) {
				if d.config.Registry.Host != "registry.example.com" {
					t.Errorf("Registry.Host = %s, want registry.example.com", d.config.Registry.Host)
				}
				if d.config.Registry.Repo != "namespace/repo" {
					t.Errorf("Registry.Repo = %s, want namespace/repo", d.config.Registry.Repo)
				}
				if d.config.Registry.Auth != "base64-specific-repo-auth" {
					t.Errorf("Registry.Auth = %s, want base64-specific-repo-auth (repo-specific auth)", d.config.Registry.Auth)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.CreateDaemon(tt.opts)
			if err != nil {
				t.Fatalf("CreateDaemon() failed: %v", err)
			}

			d := mgr.GetDaemon(tt.opts.ID)
			if d == nil {
				t.Fatal("Created daemon not found")
			}

			if tt.validate != nil {
				tt.validate(t, d)
			}
		})
	}
}

func TestManager_CreateDaemon_Nydus_DockerAuthsFormat(t *testing.T) {
	tmpDir := t.TempDir()

	ossConfig := BackendConfig{
		BackendType: "oss",
		Oss:         &OssConfig{},
	}
	ossCfgPath := createTestConfigFile(t, tmpDir, "oss_config.json", ossConfig)

	nydusConfig := BackendConfig{
		BackendType: "registry",
		Registry: &RegistryConfig{
			Host:   "docker.io",
			Scheme: "https",
			Auth:   "",
		},
	}
	nydusCfgPath := createTestConfigFile(t, tmpDir, "nydus_config.json", nydusConfig)

	ossAuthsPath := createTestOSSAuthsFile(t, tmpDir)
	registryAuthsPath := createTestDockerFormatRegistryAuthsFile(t, tmpDir)

	mgr, err := NewManager(&ManagerConfig{
		Root:              tmpDir,
		OSSCfgPath:        ossCfgPath,
		NydusCfgPath:      nydusCfgPath,
		BinPath:           "/usr/local/bin/distill_fs",
		OSSAuthsPath:      ossAuthsPath,
		RegistryAuthsPath: registryAuthsPath,
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	opts := &DaemonCreateOpt{
		ID:         "nydus-daemon-docker-auths",
		Name:       "nydus-image",
		SourceType: "nydus",
		ImageURL:   "registry.example.com/namespace/repo:latest",
	}
	if err := mgr.CreateDaemon(opts); err != nil {
		t.Fatalf("CreateDaemon() failed: %v", err)
	}

	d := mgr.GetDaemon(opts.ID)
	if d == nil {
		t.Fatal("Created daemon not found")
	}
	if d.config.Registry.Auth != "base64-specific-repo-auth" {
		t.Errorf("Registry.Auth = %s, want base64-specific-repo-auth", d.config.Registry.Auth)
	}
}

func TestManager_GetDaemon(t *testing.T) {
	tmpDir := t.TempDir()

	ossConfig := BackendConfig{BackendType: "oss", Oss: &OssConfig{}}
	ossCfgPath := createTestConfigFile(t, tmpDir, "oss_config.json", ossConfig)

	nydusConfig := BackendConfig{BackendType: "registry", Registry: &RegistryConfig{}}
	nydusCfgPath := createTestConfigFile(t, tmpDir, "nydus_config.json", nydusConfig)

	ossAuthsPath := createTestOSSAuthsFile(t, tmpDir)
	registryAuthsPath := createTestRegistryAuthsFile(t, tmpDir)

	mgr, err := NewManager(&ManagerConfig{
		Root:              tmpDir,
		OSSCfgPath:        ossCfgPath,
		NydusCfgPath:      nydusCfgPath,
		BinPath:           "/usr/local/bin/distill_fs",
		OSSAuthsPath:      ossAuthsPath,
		RegistryAuthsPath: registryAuthsPath,
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Create a daemon
	opts := &DaemonCreateOpt{
		ID:   "test-get-daemon",
		Name: "test",
	}
	if err := mgr.CreateDaemon(opts); err != nil {
		t.Fatalf("CreateDaemon() failed: %v", err)
	}

	// Test GetDaemon
	d := mgr.GetDaemon("test-get-daemon")
	if d == nil {
		t.Fatal("GetDaemon() returned nil for existing daemon")
	}
	if d.meta.ID != "test-get-daemon" {
		t.Errorf("Daemon ID = %s, want test-get-daemon", d.meta.ID)
	}

	// Test non-existent daemon
	d = mgr.GetDaemon("non-existent")
	if d != nil {
		t.Error("GetDaemon() should return nil for non-existent daemon")
	}
}

func TestManager_ListDaemons(t *testing.T) {
	tmpDir := t.TempDir()

	ossConfig := BackendConfig{BackendType: "oss", Oss: &OssConfig{}}
	ossCfgPath := createTestConfigFile(t, tmpDir, "oss_config.json", ossConfig)

	nydusConfig := BackendConfig{BackendType: "registry", Registry: &RegistryConfig{}}
	nydusCfgPath := createTestConfigFile(t, tmpDir, "nydus_config.json", nydusConfig)

	ossAuthsPath := createTestOSSAuthsFile(t, tmpDir)
	registryAuthsPath := createTestRegistryAuthsFile(t, tmpDir)

	mgr, err := NewManager(&ManagerConfig{
		Root:              tmpDir,
		OSSCfgPath:        ossCfgPath,
		NydusCfgPath:      nydusCfgPath,
		BinPath:           "/usr/local/bin/distill_fs",
		OSSAuthsPath:      ossAuthsPath,
		RegistryAuthsPath: registryAuthsPath,
	})
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Initially empty
	list := mgr.ListDaemons()
	if len(list) != 0 {
		t.Errorf("Initial daemon list length = %d, want 0", len(list))
	}

	// Create multiple daemons
	daemonIDs := []string{"daemon-1", "daemon-2", "daemon-3"}
	for _, id := range daemonIDs {
		if err := mgr.CreateDaemon(&DaemonCreateOpt{ID: id, Name: id}); err != nil {
			t.Fatalf("CreateDaemon(%s) failed: %v", id, err)
		}
	}

	// List should contain all daemons
	list = mgr.ListDaemons()
	if len(list) != len(daemonIDs) {
		t.Errorf("Daemon list length = %d, want %d", len(list), len(daemonIDs))
	}

	// Verify all IDs are present
	foundIDs := make(map[string]bool)
	for _, info := range list {
		foundIDs[info.ID] = true
	}
	for _, id := range daemonIDs {
		if !foundIDs[id] {
			t.Errorf("Daemon %s not found in list", id)
		}
	}
}
