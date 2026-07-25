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

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/nydus"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
)

// mustNewHttpWorker creates an HttpWorker for testing, failing the test on error.
func mustNewHttpWorker(t *testing.T, mgr distillfs.Manager) *HttpWorker {
	t.Helper()
	w, err := NewHttpWorker(&HttpWorkerConfig{Manager: mgr})
	if err != nil {
		t.Fatalf("NewHttpWorker: %v", err)
	}
	return w
}

// mockDaemon is a mock implementation for testing
type mockDaemon struct {
	meta        distillfs.DaemonMeta
	mountFunc   func() error
	unmountFunc func() error
}

func (m *mockDaemon) Mount() error {
	if m.mountFunc != nil {
		return m.mountFunc()
	}
	return nil
}

func (m *mockDaemon) Unmount() error {
	if m.unmountFunc != nil {
		return m.unmountFunc()
	}
	return nil
}

func (m *mockDaemon) MountPoint() string {
	return m.meta.MountPoint
}

func (m *mockDaemon) Name() string {
	return m.meta.Name
}

func (m *mockDaemon) IsAlive() bool {
	return true
}

// mockManager is a mock implementation of distillfs.Manager for testing
type mockManager struct {
	createDaemonFunc  func(opts *distillfs.DaemonCreateOpt) error
	getDaemonFunc     func(id string) *distillfs.Daemon
	cleanupDaemonFunc func(daemonID string) error
	listDaemonsFunc   func() []distillfs.DaemonInfo
	daemons           map[string]*mockDaemon
}

func newMockManager() *mockManager {
	return &mockManager{
		daemons: make(map[string]*mockDaemon),
	}
}

func (m *mockManager) CreateDaemon(opts *distillfs.DaemonCreateOpt) error {
	if m.createDaemonFunc != nil {
		return m.createDaemonFunc(opts)
	}

	// Default implementation for tests
	daemon := &mockDaemon{
		meta: distillfs.DaemonMeta{
			ID:         opts.ID,
			Name:       opts.Name,
			MountPoint: "/mnt/" + opts.ID,
		},
	}
	m.daemons[opts.ID] = daemon
	return nil
}

func (m *mockManager) GetDaemon(id string) *distillfs.Daemon {
	if m.getDaemonFunc != nil {
		return m.getDaemonFunc(id)
	}

	// Return nil for mock - tests should use getDaemonFunc if they need a daemon
	return nil
}

func (m *mockManager) CleanupDaemon(daemonID string) error {
	if m.cleanupDaemonFunc != nil {
		return m.cleanupDaemonFunc(daemonID)
	}
	if daemonID == "" {
		return fmt.Errorf("daemon ID is empty")
	}
	delete(m.daemons, daemonID)
	return nil
}

func (m *mockManager) ListDaemons() []distillfs.DaemonInfo {
	if m.listDaemonsFunc != nil {
		return m.listDaemonsFunc()
	}
	return []distillfs.DaemonInfo{}
}

func TestHttpWorker_MountOSS_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     *OSSMountRequest
		wantErr bool
	}{
		{
			name: "invalid object - trailing slash",
			req: &OSSMountRequest{
				Endpoint: "oss-cn-hangzhou.aliyuncs.com",
				Bucket:   "test-bucket",
				Object:   "images/",
			},
			wantErr: true,
		},
		{
			name: "invalid object - empty",
			req: &OSSMountRequest{
				Endpoint: "oss-cn-hangzhou.aliyuncs.com",
				Bucket:   "test-bucket",
				Object:   "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newMockManager()
			worker := mustNewHttpWorker(t, mgr)

			_, err := worker.MountOSS(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("MountOSS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHttpWorker_CleanupDaemon(t *testing.T) {
	tests := []struct {
		name    string
		req     *CleanupDaemonRequest
		wantErr bool
	}{
		{
			name:    "valid cleanup request",
			req:     &CleanupDaemonRequest{DaemonID: "test-daemon-id"},
			wantErr: false,
		},
		{
			name:    "empty daemon ID",
			req:     &CleanupDaemonRequest{DaemonID: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newMockManager()
			worker := mustNewHttpWorker(t, mgr)

			err := worker.CleanupDaemon(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CleanupDaemon() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHttpWorker_ListDaemons(t *testing.T) {
	expectedDaemons := []distillfs.DaemonInfo{
		{
			ID:         "daemon-1",
			Name:       "test-daemon-1",
			MountPoint: "/mnt/daemon-1",
			SourceType: "oss",
			IsAlive:    true,
		},
		{
			ID:         "daemon-2",
			Name:       "test-daemon-2",
			MountPoint: "/mnt/daemon-2",
			SourceType: "nydus",
			IsAlive:    false,
		},
	}

	mgr := &mockManager{
		listDaemonsFunc: func() []distillfs.DaemonInfo {
			return expectedDaemons
		},
	}

	worker := mustNewHttpWorker(t, mgr)
	daemons, err := worker.ListDaemons()

	if err != nil {
		t.Fatalf("ListDaemons() error = %v", err)
	}

	if len(daemons) != len(expectedDaemons) {
		t.Errorf("ListDaemons() returned %d daemons, want %d", len(daemons), len(expectedDaemons))
	}

	for i, daemon := range daemons {
		if daemon.ID != expectedDaemons[i].ID {
			t.Errorf("Daemon[%d].ID = %s, want %s", i, daemon.ID, expectedDaemons[i].ID)
		}
		if daemon.IsAlive != expectedDaemons[i].IsAlive {
			t.Errorf("Daemon[%d].IsAlive = %v, want %v", i, daemon.IsAlive, expectedDaemons[i].IsAlive)
		}
	}
}

func TestHttpHandler_OSSMount(t *testing.T) {
	mgr := newMockManager()
	worker := mustNewHttpWorker(t, mgr)
	handler := worker.prepareHttp()

	tests := []struct {
		name           string
		method         string
		body           interface{}
		expectedStatus int
	}{
		{
			name:           "invalid method GET",
			method:         http.MethodGet,
			body:           nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid JSON body",
			method:         http.MethodPost,
			body:           "invalid json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "invalid object",
			method: http.MethodPost,
			body: OSSMountRequest{
				Endpoint: "oss-cn-hangzhou.aliyuncs.com",
				Bucket:   "test-bucket",
				Object:   "images/", // trailing slash
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != nil {
				if str, ok := tt.body.(string); ok {
					body = bytes.NewBufferString(str)
				} else {
					jsonData, _ := json.Marshal(tt.body)
					body = bytes.NewReader(jsonData)
				}
			}

			req := httptest.NewRequest(tt.method, "/oss_mount", body)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status code = %d, want %d. Body: %s", w.Code, tt.expectedStatus, w.Body.String())
			}
		})
	}
}

func TestHttpHandler_OSSUmount(t *testing.T) {
	mgr := newMockManager()
	worker := mustNewHttpWorker(t, mgr)
	handler := worker.prepareHttp()

	tests := []struct {
		name           string
		method         string
		body           interface{}
		expectedStatus int
	}{
		{
			name:           "invalid method GET",
			method:         http.MethodGet,
			body:           nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "daemon not found",
			method: http.MethodPost,
			body: OSSUmountRequest{
				Endpoint: "oss-cn-hangzhou.aliyuncs.com",
				Bucket:   "test-bucket",
				Object:   "test.tar",
			},
			expectedStatus: http.StatusInternalServerError, // No daemon exists
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != nil {
				jsonData, _ := json.Marshal(tt.body)
				body = bytes.NewReader(jsonData)
			}

			req := httptest.NewRequest(tt.method, "/oss_umount", body)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status code = %d, want %d", w.Code, tt.expectedStatus)
			}
		})
	}
}

func TestHttpHandler_ListDaemons(t *testing.T) {
	expectedDaemons := []distillfs.DaemonInfo{
		{ID: "test-1", Name: "daemon-1", IsAlive: true},
	}

	mgr := &mockManager{
		listDaemonsFunc: func() []distillfs.DaemonInfo {
			return expectedDaemons
		},
	}

	worker := mustNewHttpWorker(t, mgr)
	handler := worker.prepareHttp()

	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "valid GET request",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid POST method",
			method:         http.MethodPost,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/list_daemons", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status code = %d, want %d", w.Code, tt.expectedStatus)
			}

			if w.Code == http.StatusOK {
				var daemons []distillfs.DaemonInfo
				if err := json.NewDecoder(w.Body).Decode(&daemons); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if len(daemons) != len(expectedDaemons) {
					t.Errorf("Got %d daemons, want %d", len(daemons), len(expectedDaemons))
				}
			}
		})
	}
}

func TestHttpHandler_CleanupDaemon(t *testing.T) {
	mgr := newMockManager()
	worker := mustNewHttpWorker(t, mgr)
	handler := worker.prepareHttp()

	tests := []struct {
		name           string
		method         string
		body           interface{}
		expectedStatus int
	}{
		{
			name:   "valid cleanup request",
			method: http.MethodPost,
			body: CleanupDaemonRequest{
				DaemonID: "test-daemon-id",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid method GET",
			method:         http.MethodGet,
			body:           nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "empty daemon ID",
			method: http.MethodPost,
			body: CleanupDaemonRequest{
				DaemonID: "",
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != nil {
				jsonData, _ := json.Marshal(tt.body)
				body = bytes.NewReader(jsonData)
			}

			req := httptest.NewRequest(tt.method, "/cleanup_daemon", body)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status code = %d, want %d. Body: %s", w.Code, tt.expectedStatus, w.Body.String())
			}
		})
	}
}

func TestHttpWorker_MountOCI_NydusMountFailureDoesNotFallback(t *testing.T) {
	t.Run("detected on original image URL", func(t *testing.T) {
		mgr := newMockManager()
		expectedErr := errors.New("mock nydus create failure")
		var gotImageURL string
		mgr.createDaemonFunc = func(opts *distillfs.DaemonCreateOpt) error {
			gotImageURL = opts.ImageURL
			if opts.SourceType != "nydus" {
				t.Fatalf("SourceType = %q, want %q", opts.SourceType, "nydus")
			}
			return expectedErr
		}

		ociMgr, err := oci.NewManager(t.TempDir(), "")
		if err != nil {
			t.Fatalf("oci.NewManager() error: %v", err)
		}
		defer ociMgr.Close()

		worker, err := NewHttpWorker(&HttpWorkerConfig{
			Manager:     mgr,
			OCIManager:  ociMgr,
			NydusClient: &nydus.RegistryClient{},
		})
		if err != nil {
			t.Fatalf("NewHttpWorker() error: %v", err)
		}

		imageURL := "%%%original"
		worker.nydusCache.Set(imageURL, true)

		resp, err := worker.MountOCI(&OCIMountRequest{ImageURL: imageURL})
		if err == nil {
			t.Fatal("MountOCI() error = nil, want non-nil")
		}
		if resp != nil {
			t.Fatalf("MountOCI() resp = %v, want nil", resp)
		}
		if !strings.Contains(err.Error(), "failed to mount Nydus image") {
			t.Fatalf("MountOCI() error = %q, want Nydus mount failure", err.Error())
		}
		if !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Fatalf("MountOCI() error = %q, want underlying create error", err.Error())
		}
		if gotImageURL != imageURL {
			t.Fatalf("CreateDaemon imageURL = %q, want %q", gotImageURL, imageURL)
		}
	})

	t.Run("detected on suffix image URL", func(t *testing.T) {
		mgr := newMockManager()
		expectedErr := errors.New("mock suffix nydus create failure")
		var gotImageURL string
		mgr.createDaemonFunc = func(opts *distillfs.DaemonCreateOpt) error {
			gotImageURL = opts.ImageURL
			if opts.SourceType != "nydus" {
				t.Fatalf("SourceType = %q, want %q", opts.SourceType, "nydus")
			}
			return expectedErr
		}

		ociMgr, err := oci.NewManager(t.TempDir(), "")
		if err != nil {
			t.Fatalf("oci.NewManager() error: %v", err)
		}
		defer ociMgr.Close()

		worker, err := NewHttpWorker(&HttpWorkerConfig{
			Manager:     mgr,
			OCIManager:  ociMgr,
			NydusClient: &nydus.RegistryClient{},
			NydusSuffix: "-nydus",
		})
		if err != nil {
			t.Fatalf("NewHttpWorker() error: %v", err)
		}

		imageURL := "%%%base"
		suffixedImageURL := imageURL + "-nydus"
		worker.nydusCache.Set(imageURL, false)
		worker.nydusCache.Set(suffixedImageURL, true)

		resp, err := worker.MountOCI(&OCIMountRequest{ImageURL: imageURL})
		if err == nil {
			t.Fatal("MountOCI() error = nil, want non-nil")
		}
		if resp != nil {
			t.Fatalf("MountOCI() resp = %v, want nil", resp)
		}
		if !strings.Contains(err.Error(), "failed to mount Nydus image") {
			t.Fatalf("MountOCI() error = %q, want Nydus mount failure", err.Error())
		}
		if !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Fatalf("MountOCI() error = %q, want underlying create error", err.Error())
		}
		if gotImageURL != suffixedImageURL {
			t.Fatalf("CreateDaemon imageURL = %q, want %q", gotImageURL, suffixedImageURL)
		}
	})
}

func TestHttpWorker_MountNydusOnce_PreservesAttemptOnError(t *testing.T) {
	worker := &HttpWorker{}
	expectedErr := errors.New("mock nydus mount failure")

	attempt, err := worker.mountNydusOnce("test-image", func() (nydusMountAttempt, error) {
		return nydusMountAttempt{detected: true}, expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("mountNydusOnce() error = %v, want %v", err, expectedErr)
	}
	if !attempt.detected {
		t.Fatal("mountNydusOnce() lost detected=true on error")
	}
}

func TestHttpHandler_ListOCIMounts(t *testing.T) {
	t.Run("valid GET request", func(t *testing.T) {
		mgr := newMockManager()
		ociMgr, err := oci.NewManager(t.TempDir(), "")
		if err != nil {
			t.Fatalf("oci.NewManager() error: %v", err)
		}
		defer ociMgr.Close()

		worker, err := NewHttpWorker(&HttpWorkerConfig{
			Manager:    mgr,
			OCIManager: ociMgr,
		})
		if err != nil {
			t.Fatalf("NewHttpWorker() error: %v", err)
		}
		handler := worker.prepareHttp()

		req := httptest.NewRequest(http.MethodGet, "/list_oci_mounts", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Status code = %d, want %d, body=%s", w.Code, http.StatusOK, w.Body.String())
		}

		var resp struct {
			ImageURLs []string `json:"image_urls"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(resp.ImageURLs) != 0 {
			t.Fatalf("expected empty mounted OCI list, got %v", resp.ImageURLs)
		}
	})

	t.Run("invalid POST method", func(t *testing.T) {
		mgr := newMockManager()
		worker := mustNewHttpWorker(t, mgr)
		handler := worker.prepareHttp()

		req := httptest.NewRequest(http.MethodPost, "/list_oci_mounts", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("Status code = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("oci manager not initialized", func(t *testing.T) {
		mgr := newMockManager()
		worker := mustNewHttpWorker(t, mgr)
		handler := worker.prepareHttp()

		req := httptest.NewRequest(http.MethodGet, "/list_oci_mounts", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("Status code = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})
}

func TestHttpHandler_ListOCIMountDetails(t *testing.T) {
	t.Run("valid GET request", func(t *testing.T) {
		mgr := newMockManager()
		ociMgr, err := oci.NewManager(t.TempDir(), "")
		if err != nil {
			t.Fatalf("oci.NewManager() error: %v", err)
		}
		defer ociMgr.Close()

		worker, err := NewHttpWorker(&HttpWorkerConfig{
			Manager:    mgr,
			OCIManager: ociMgr,
		})
		if err != nil {
			t.Fatalf("NewHttpWorker() error: %v", err)
		}
		handler := worker.prepareHttp()

		req := httptest.NewRequest(http.MethodGet, "/list_oci_mount_details", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Status code = %d, want %d, body=%s", w.Code, http.StatusOK, w.Body.String())
		}
		var resp struct {
			Mounts []oci.OciMountRecord `json:"mounts"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(resp.Mounts) != 0 {
			t.Fatalf("expected empty mount details, got %v", resp.Mounts)
		}
	})

	t.Run("invalid POST method", func(t *testing.T) {
		mgr := newMockManager()
		worker := mustNewHttpWorker(t, mgr)
		handler := worker.prepareHttp()

		req := httptest.NewRequest(http.MethodPost, "/list_oci_mount_details", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("Status code = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("oci manager not initialized", func(t *testing.T) {
		mgr := newMockManager()
		worker := mustNewHttpWorker(t, mgr)
		handler := worker.prepareHttp()

		req := httptest.NewRequest(http.MethodGet, "/list_oci_mount_details", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("Status code = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})
}
