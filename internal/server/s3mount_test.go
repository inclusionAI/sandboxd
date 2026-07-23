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
	"sync"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
)

// newTestS3MountManager creates a manager with a mock unmount function for testing.
func newTestS3MountManager() (*s3MountManager, *mockUnmountTracker) {
	tracker := &mockUnmountTracker{}
	mgr := &s3MountManager{
		entries:  make(map[string]*imageMountEntry),
		unmountF: tracker.unmount,
	}
	return mgr, tracker
}

// mockUnmountTracker tracks unmount calls for testing.
type mockUnmountTracker struct {
	mu           sync.Mutex
	unmountCalls []string // keys that were unmounted
}

func (m *mockUnmountTracker) unmount(endpoint, bucket, object string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s/%s", endpoint, bucket, object)
	m.unmountCalls = append(m.unmountCalls, key)
	return nil
}

func (m *mockUnmountTracker) getUnmountCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.unmountCalls))
	copy(result, m.unmountCalls)
	return result
}

func makeS3Config(endpoint, bucket, object string) *runtime.S3Config {
	return &runtime.S3Config{
		Endpoint:        endpoint,
		Bucket:          bucket,
		Object:          object,
		AccessKeyID:     "ak",
		AccessKeySecret: "sk",
	}
}

// TestS3MountManager_RefCount tests the reference counting logic.
func TestS3MountManager_RefCount(t *testing.T) {
	mgr, _ := newTestS3MountManager()
	cfg := makeS3Config("https://s3.example.com", "bucket1", "data.tar")
	key := s3MountKey(cfg)

	// Simulate first mount: manually insert entry
	mgr.mu.Lock()
	mgr.entries[key] = &imageMountEntry{
		refcount: 1,
		path:     "/fuse/bucket1/data.tar",
	}
	mgr.mu.Unlock()

	// Second call should increment refcount, not call image-manager
	mgr.mu.Lock()
	entry, ok := mgr.entries[key]
	if !ok {
		t.Fatal("expected entry to exist")
	}
	entry.refcount++
	mgr.mu.Unlock()

	if entry.refcount != 2 {
		t.Fatalf("expected refcount=2, got %d", entry.refcount)
	}

	// First unmount: refcount decrements to 1
	mgr.mu.Lock()
	entry.refcount--
	if entry.refcount != 1 {
		t.Fatalf("expected refcount=1 after first unmount, got %d", entry.refcount)
	}
	// Should NOT delete
	_, stillExists := mgr.entries[key]
	if !stillExists {
		t.Fatal("entry should still exist after first unmount")
	}
	mgr.mu.Unlock()

	// Second unmount: refcount hits 0, should delete
	mgr.mu.Lock()
	entry.refcount--
	if entry.refcount != 0 {
		t.Fatalf("expected refcount=0 after second unmount, got %d", entry.refcount)
	}
	delete(mgr.entries, key)
	mgr.mu.Unlock()

	// Entry should be gone
	mgr.mu.Lock()
	_, gone := mgr.entries[key]
	mgr.mu.Unlock()
	if gone {
		t.Fatal("entry should be deleted after all refs released")
	}
}

// TestS3MountManager_OrphanProtection verifies that two sandboxes sharing
// the same S3 mount don't interfere with each other.
func TestS3MountManager_OrphanProtection(t *testing.T) {
	mgr, _ := newTestS3MountManager()
	cfg := makeS3Config("https://s3.example.com", "shared", "model.bin")
	key := s3MountKey(cfg)

	// Sandbox A and B both use the same S3 mount
	mgr.mu.Lock()
	mgr.entries[key] = &imageMountEntry{
		refcount: 2,
		path:     "/fuse/shared/model.bin",
	}
	mgr.mu.Unlock()

	// Sandbox A deletes: decrement refcount
	mgr.mu.Lock()
	entry := mgr.entries[key]
	entry.refcount--
	remainingA := entry.refcount
	mgr.mu.Unlock()

	if remainingA != 1 {
		t.Fatalf("expected refcount=1 after sandbox A delete, got %d", remainingA)
	}

	// Path should still be accessible for sandbox B
	mgr.mu.Lock()
	e, ok := mgr.entries[key]
	if !ok {
		t.Fatal("mount should still exist for sandbox B")
	}
	if e.path != "/fuse/shared/model.bin" {
		t.Fatalf("mount path changed unexpectedly: %s", e.path)
	}
	mgr.mu.Unlock()

	// Sandbox B deletes: refcount hits 0
	mgr.mu.Lock()
	e = mgr.entries[key]
	e.refcount--
	if e.refcount == 0 {
		delete(mgr.entries, key)
	}
	mgr.mu.Unlock()

	// Now mount should be gone
	mgr.mu.Lock()
	_, gone := mgr.entries[key]
	mgr.mu.Unlock()
	if gone {
		t.Fatal("mount should be removed after all sandboxes deleted")
	}
}

// TestS3MountManager_CleanupAll verifies that cleanupAllS3Unmounts
// properly clears all entries and calls unmount for each.
func TestS3MountManager_CleanupAll(t *testing.T) {
	mgr, tracker := newTestS3MountManager()

	// Simulate 3 different S3 mounts
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("endpoint%d\x00bucket%d\x00obj%d", i, i, i)
		mgr.entries[key] = &imageMountEntry{
			refcount: 1,
			path:     fmt.Sprintf("/fuse/mount%d", i),
		}
	}

	if len(mgr.entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(mgr.entries))
	}

	// Call the actual cleanup method
	mgr.cleanupAllS3Unmounts()

	if len(mgr.entries) != 0 {
		t.Fatalf("expected 0 entries after cleanup, got %d", len(mgr.entries))
	}

	// Verify unmount was called for each entry
	calls := tracker.getUnmountCalls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 unmount calls, got %d", len(calls))
	}
}

// TestS3MountKey tests the key generation for S3 mount deduplication.
func TestS3MountKey(t *testing.T) {
	cfg1 := makeS3Config("https://s3.example.com", "bucket", "obj")
	cfg2 := makeS3Config("https://s3.example.com", "bucket", "obj")
	cfg3 := makeS3Config("https://s3.example.com", "bucket", "different")

	key1 := s3MountKey(cfg1)
	key2 := s3MountKey(cfg2)
	key3 := s3MountKey(cfg3)

	if key1 != key2 {
		t.Fatalf("identical configs should produce same key: %q vs %q", key1, key2)
	}
	if key1 == key3 {
		t.Fatal("different objects should produce different keys")
	}
}

// TestS3MountManager_Validation tests that mountS3 validates S3Config fields.
func TestS3MountManager_Validation(t *testing.T) {
	mgr, _ := newTestS3MountManager()

	tests := []struct {
		name    string
		cfg     *runtime.S3Config
		wantErr bool
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: true,
		},
		{
			name: "empty endpoint",
			cfg: &runtime.S3Config{
				Endpoint: "",
				Bucket:   "bucket",
				Object:   "obj",
			},
			wantErr: true,
		},
		{
			name: "empty bucket",
			cfg: &runtime.S3Config{
				Endpoint: "https://s3.example.com",
				Bucket:   "",
				Object:   "obj",
			},
			wantErr: true,
		},
		{
			name: "empty object",
			cfg: &runtime.S3Config{
				Endpoint: "https://s3.example.com",
				Bucket:   "bucket",
				Object:   "",
			},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg: &runtime.S3Config{
				Endpoint: "https://s3.example.com",
				Bucket:   "bucket",
				Object:   "obj",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For valid config, we need to insert an entry first since mountS3
			// would call image-manager which we can't mock here.
			if !tt.wantErr && tt.cfg != nil {
				key := s3MountKey(tt.cfg)
				mgr.mu.Lock()
				mgr.entries[key] = &imageMountEntry{
					refcount: 1,
					path:     "/fuse/test",
				}
				mgr.mu.Unlock()
			}

			_, err := mgr.mountS3(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("mountS3() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestS3MountManager_ConcurrentAccess tests concurrent mount/unmount operations.
func TestS3MountManager_ConcurrentAccess(t *testing.T) {
	mgr, tracker := newTestS3MountManager()
	cfg := makeS3Config("https://s3.example.com", "bucket", "object")
	key := s3MountKey(cfg)

	// Pre-populate with high refcount
	mgr.mu.Lock()
	mgr.entries[key] = &imageMountEntry{
		refcount: 100,
		path:     "/fuse/bucket/object",
	}
	mgr.mu.Unlock()

	var wg sync.WaitGroup
	numGoroutines := 50
	decrementsPerGoroutine := 2

	// Concurrent decrements
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < decrementsPerGoroutine; j++ {
				mgr.mu.Lock()
				if entry, ok := mgr.entries[key]; ok {
					entry.refcount--
					if entry.refcount == 0 {
						delete(mgr.entries, key)
					}
				}
				mgr.mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Verify final state
	mgr.mu.Lock()
	entry, exists := mgr.entries[key]
	mgr.mu.Unlock()

	expectedRefs := 100 - (numGoroutines * decrementsPerGoroutine)
	if expectedRefs <= 0 {
		if exists {
			t.Fatalf("expected entry to be deleted, but exists with refcount=%d", entry.refcount)
		}
	} else {
		if !exists {
			t.Fatal("expected entry to exist")
		}
		if entry.refcount != expectedRefs {
			t.Fatalf("expected refcount=%d, got %d", expectedRefs, entry.refcount)
		}
	}

	// No unmount should have been called yet (we didn't use unmountS3)
	calls := tracker.getUnmountCalls()
	if len(calls) != 0 {
		t.Fatalf("expected 0 unmount calls during concurrent access, got %d", len(calls))
	}
}

// TestS3MountManager_UnmountS3 tests the unmountS3 method with refcounting.
func TestS3MountManager_UnmountS3(t *testing.T) {
	mgr, tracker := newTestS3MountManager()
	cfg := makeS3Config("https://s3.example.com", "bucket", "obj")
	key := s3MountKey(cfg)

	// Setup: refcount of 2
	mgr.mu.Lock()
	mgr.entries[key] = &imageMountEntry{
		refcount: 2,
		path:     "/fuse/bucket/obj",
	}
	mgr.mu.Unlock()

	// First unmount: should decrement but not call real unmount
	err := mgr.unmountS3(cfg)
	if err != nil {
		t.Fatalf("first unmountS3 failed: %v", err)
	}

	mgr.mu.Lock()
	entry, exists := mgr.entries[key]
	mgr.mu.Unlock()

	if !exists {
		t.Fatal("entry should still exist after first unmount")
	}
	if entry.refcount != 1 {
		t.Fatalf("expected refcount=1, got %d", entry.refcount)
	}

	calls := tracker.getUnmountCalls()
	if len(calls) != 0 {
		t.Fatal("unmount should not have been called yet")
	}

	// Second unmount: should delete entry and call unmount
	err = mgr.unmountS3(cfg)
	if err != nil {
		t.Fatalf("second unmountS3 failed: %v", err)
	}

	mgr.mu.Lock()
	_, exists = mgr.entries[key]
	mgr.mu.Unlock()

	if exists {
		t.Fatal("entry should be deleted after second unmount")
	}

	calls = tracker.getUnmountCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 unmount call, got %d", len(calls))
	}
	if calls[0] != "https://s3.example.com/bucket/obj" {
		t.Fatalf("unexpected unmount call: %s", calls[0])
	}
}

// --- OCI Mount Manager Tests ---

// newTestOciMountManager creates an OCI manager with a mock unmount function for testing.
func newTestOciMountManager() (*ociMountManager, *mockOciUnmountTracker) {
	tracker := &mockOciUnmountTracker{}
	mgr := &ociMountManager{
		entries:  make(map[string]*imageMountEntry),
		unmountF: tracker.unmount,
	}
	return mgr, tracker
}

// mockOciUnmountTracker tracks OCI unmount calls for testing.
type mockOciUnmountTracker struct {
	mu           sync.Mutex
	unmountCalls []string // image URLs that were unmounted
}

func (m *mockOciUnmountTracker) unmount(imageURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unmountCalls = append(m.unmountCalls, imageURL)
	return nil
}

func (m *mockOciUnmountTracker) getUnmountCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.unmountCalls))
	copy(result, m.unmountCalls)
	return result
}

// TestOciMountManager_RefCount tests OCI image mount reference counting.
func TestOciMountManager_RefCount(t *testing.T) {
	mgr, _ := newTestOciMountManager()
	imageURL := "docker.io/library/nginx:latest"
	key := imageURL

	// Simulate first mount: manually insert entry
	mgr.mu.Lock()
	mgr.entries[key] = &imageMountEntry{
		refcount: 1,
		path:     "/fuse/nginx",
	}
	mgr.mu.Unlock()

	// Second mount should increment refcount
	mgr.mu.Lock()
	entry, ok := mgr.entries[key]
	if !ok {
		t.Fatal("expected entry to exist")
	}
	entry.refcount++
	mgr.mu.Unlock()

	if entry.refcount != 2 {
		t.Fatalf("expected refcount=2, got %d", entry.refcount)
	}

	// First unmount: refcount decrements to 1
	mgr.mu.Lock()
	entry.refcount--
	if entry.refcount != 1 {
		t.Fatalf("expected refcount=1 after first unmount, got %d", entry.refcount)
	}
	_, stillExists := mgr.entries[key]
	if !stillExists {
		t.Fatal("entry should still exist after first unmount")
	}
	mgr.mu.Unlock()

	// Second unmount: refcount hits 0, should delete
	mgr.mu.Lock()
	entry.refcount--
	if entry.refcount != 0 {
		t.Fatalf("expected refcount=0 after second unmount, got %d", entry.refcount)
	}
	delete(mgr.entries, key)
	mgr.mu.Unlock()

	// Entry should be gone
	mgr.mu.Lock()
	_, gone := mgr.entries[key]
	mgr.mu.Unlock()
	if gone {
		t.Fatal("entry should be deleted after all refs released")
	}
}

// TestOciMountManager_CleanupAll verifies cleanupAllOciUnmounts.
func TestOciMountManager_CleanupAll(t *testing.T) {
	mgr, tracker := newTestOciMountManager()

	// Simulate 3 different OCI image mounts
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("docker.io/library/app%d:v1", i)
		mgr.entries[key] = &imageMountEntry{
			refcount: 1,
			path:     fmt.Sprintf("/fuse/app%d", i),
		}
	}

	if len(mgr.entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(mgr.entries))
	}

	// Call the actual cleanup method
	mgr.cleanupAllOciUnmounts()

	if len(mgr.entries) != 0 {
		t.Fatalf("expected 0 entries after cleanup, got %d", len(mgr.entries))
	}

	// Verify unmount was called for each entry
	calls := tracker.getUnmountCalls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 unmount calls, got %d", len(calls))
	}
}

// TestOciMountManager_Validation tests that mountOCI validates imageURL.
func TestOciMountManager_Validation(t *testing.T) {
	mgr, _ := newTestOciMountManager()

	// Empty imageURL should fail
	_, err := mgr.mountOCI("")
	if err == nil {
		t.Fatal("expected error for empty imageURL")
	}
}

// TestOciMountManager_UnmountOCI tests the unmountOCI method with refcounting.
func TestOciMountManager_UnmountOCI(t *testing.T) {
	mgr, tracker := newTestOciMountManager()
	imageURL := "docker.io/library/alpine:latest"
	key := imageURL

	// Setup: refcount of 2
	mgr.mu.Lock()
	mgr.entries[key] = &imageMountEntry{
		refcount: 2,
		path:     "/fuse/alpine",
	}
	mgr.mu.Unlock()

	// First unmount: should decrement but not call real unmount
	err := mgr.unmountOCI(imageURL)
	if err != nil {
		t.Fatalf("first unmountOCI failed: %v", err)
	}

	mgr.mu.Lock()
	entry, exists := mgr.entries[key]
	mgr.mu.Unlock()

	if !exists {
		t.Fatal("entry should still exist after first unmount")
	}
	if entry.refcount != 1 {
		t.Fatalf("expected refcount=1, got %d", entry.refcount)
	}

	calls := tracker.getUnmountCalls()
	if len(calls) != 0 {
		t.Fatal("unmount should not have been called yet")
	}

	// Second unmount: should delete entry and call unmount
	err = mgr.unmountOCI(imageURL)
	if err != nil {
		t.Fatalf("second unmountOCI failed: %v", err)
	}

	mgr.mu.Lock()
	_, exists = mgr.entries[key]
	mgr.mu.Unlock()

	if exists {
		t.Fatal("entry should be deleted after second unmount")
	}

	calls = tracker.getUnmountCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 unmount call, got %d", len(calls))
	}
	if calls[0] != imageURL {
		t.Fatalf("unexpected unmount call: %s", calls[0])
	}
}

// TestOciMountManager_ConcurrentAccess tests concurrent mount/unmount operations.
func TestOciMountManager_ConcurrentAccess(t *testing.T) {
	mgr, _ := newTestOciMountManager()
	imageURL := "docker.io/library/test:v1"
	key := imageURL

	// Pre-populate with high refcount
	mgr.mu.Lock()
	mgr.entries[key] = &imageMountEntry{
		refcount: 100,
		path:     "/fuse/test",
	}
	mgr.mu.Unlock()

	var wg sync.WaitGroup
	numGoroutines := 50
	decrementsPerGoroutine := 2

	// Concurrent decrements
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < decrementsPerGoroutine; j++ {
				mgr.mu.Lock()
				if entry, ok := mgr.entries[key]; ok {
					entry.refcount--
					if entry.refcount == 0 {
						delete(mgr.entries, key)
					}
				}
				mgr.mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Verify final state
	mgr.mu.Lock()
	entry, exists := mgr.entries[key]
	mgr.mu.Unlock()

	expectedRefs := 100 - (numGoroutines * decrementsPerGoroutine)
	if expectedRefs <= 0 {
		if exists {
			t.Fatalf("expected entry to be deleted, but exists with refcount=%d", entry.refcount)
		}
	} else {
		if !exists {
			t.Fatal("expected entry to exist")
		}
		if entry.refcount != expectedRefs {
			t.Fatalf("expected refcount=%d, got %d", expectedRefs, entry.refcount)
		}
	}
}

// TestS3MountManager_CleanupAllInvalidKey tests that cleanupAllS3Unmounts
// handles malformed keys gracefully without panicking.
func TestS3MountManager_CleanupAllInvalidKey(t *testing.T) {
	mgr, tracker := newTestS3MountManager()

	// Insert an entry with a malformed key (missing separators)
	mgr.mu.Lock()
	mgr.entries["badkey"] = &imageMountEntry{refcount: 1, path: "/bad"}
	mgr.entries["only\x00two"] = &imageMountEntry{refcount: 1, path: "/bad2"}
	// Also add a valid key
	mgr.entries["ep\x00bkt\x00obj"] = &imageMountEntry{refcount: 1, path: "/good"}
	mgr.mu.Unlock()

	// Should not panic
	mgr.cleanupAllS3Unmounts()

	// Only the valid key should have been unmounted
	calls := tracker.getUnmountCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 unmount call, got %d", len(calls))
	}
	if calls[0] != "ep/bkt/obj" {
		t.Fatalf("unexpected unmount call: %s", calls[0])
	}

	// All entries should be cleared
	mgr.mu.Lock()
	if len(mgr.entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(mgr.entries))
	}
	mgr.mu.Unlock()
}

func TestRequireReadOnlyMount(t *testing.T) {
	cases := []struct {
		name    string
		options []string
		wantErr bool
	}{
		{"explicit ro", []string{"ro"}, false},
		{"ro with bind", []string{"bind", "ro"}, false},
		{"missing", []string{"bind"}, true},
		{"empty", nil, true},
		{"explicit rw", []string{"rw"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireReadOnlyMount(&runtime.Mount{Target: "/data", Options: tc.options})
			if (err != nil) != tc.wantErr {
				t.Fatalf("options=%v want err=%v got %v", tc.options, tc.wantErr, err)
			}
		})
	}
}
