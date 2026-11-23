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

package oci

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/internal/testregistry"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
)

func TestMountImageRetriesUnpublishedMountCleanup(t *testing.T) {
	registry := testregistry.New(t, "layer")
	registry.Unblock()
	m := newTestManager(t)
	defer m.store.close()
	m.registry, _ = imageregistry.NewClient("")

	primaryErr := errors.New("verify mounted image")
	mounts := 0
	m.mountFn = func(string, []string) error {
		mounts++
		if mounts == 1 {
			return primaryErr
		}
		return nil
	}
	unmounts := 0
	m.unmountFn = func(string) error {
		unmounts++
		if unmounts == 1 {
			return syscall.EBUSY
		}
		return nil
	}
	if _, _, err := m.MountImage(registry.ImageURL); !errors.Is(err, primaryErr) || !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("failed mount: %v", err)
	}
	if txn, err := m.store.getMountTxn(registry.ImageURL); err != nil || txn == nil {
		t.Fatalf("failed cleanup lost pending transaction: %v, %v", txn, err)
	}
	if _, _, err := m.MountImage(registry.ImageURL); err != nil {
		t.Fatalf("retry after recoverable cleanup failure: %v", err)
	}
	if mounts != 2 || unmounts != 2 {
		t.Fatalf("mounts=%d and unmounts=%d, want 2 each", mounts, unmounts)
	}
	if txn, err := m.store.getMountTxn(registry.ImageURL); err != nil || txn != nil {
		t.Fatalf("successful retry kept pending transaction: %v, %v", txn, err)
	}
	if layers, err := m.store.listLayers(); err != nil || len(layers) != 1 || layers[0].RefCount != 1 {
		t.Fatalf("successful retry leaked layer references: %v, %v", layers, err)
	}
	if chains, err := m.store.listChains(); err != nil || len(chains) != 1 || chains[0].RefCount != 1 {
		t.Fatalf("successful retry leaked chain references: %v, %v", chains, err)
	}
}

func TestCanceledImageWaiterDoesNotCancelOwner(t *testing.T) {
	registry := testregistry.New(t, "layer")
	m := newTestManager(t)
	m.registry, _ = imageregistry.NewClient("")
	owner := make(chan error, 1)
	go func() { _, _, err := m.MountImageWithContext(context.Background(), registry.ImageURL); owner <- err }()
	select {
	case <-registry.Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("owner download not reached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan error, 1)
	go func() { _, _, err := m.MountImageWithContext(ctx, registry.ImageURL); waiter <- err }()
	waitForCancellationLockWaiter(t, m, m.imageLocks, registry.ImageURL)
	cancel()
	select {
	case err := <-waiter:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		registry.Unblock()
		<-owner
		t.Fatal("canceled waiter blocked behind image owner")
	}
	select {
	case <-registry.Canceled:
		t.Fatal("waiter canceled owner's download")
	default:
	}
	registry.Unblock()
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
	if err := m.UnmountImage(registry.ImageURL); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledLayerOwnerDoesNotPoisonOtherImage(t *testing.T) {
	registry := testregistry.New(t, "layer")
	m := newTestManager(t)
	m.registry, _ = imageregistry.NewClient("")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, _, err := m.MountImageWithContext(ctx, registry.ImageURL); first <- err }()
	select {
	case <-registry.Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("download not reached")
	}
	otherURL := strings.TrimSuffix(registry.ImageURL, ":latest") + ":other"
	other := make(chan error, 1)
	go func() { _, _, err := m.MountImageWithContext(context.Background(), otherURL); other <- err }()
	// Both images have reached the same layer before cancelling its owner.
	waitForCancellationLockWaiter(t, m, m.layerLocks, "")
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		registry.Unblock()
		<-first
		t.Fatal("owner did not cancel")
	}
	registry.Unblock()
	select {
	case err := <-other:
		if err != nil {
			t.Fatalf("other image was poisoned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("other image remained blocked")
	}
	records, err := m.ListMountedDetails()
	if err != nil || len(records) != 1 || records[0].ImageURL != otherURL {
		t.Fatalf("mounts=%v err=%v", records, err)
	}
	layers, err := m.store.listLayers()
	if err != nil {
		t.Fatal(err)
	}
	for _, layer := range layers {
		if layer.RefCount != 1 {
			t.Fatalf("layer refcount = %d, want 1", layer.RefCount)
		}
	}
	if err := m.UnmountImage(otherURL); err != nil {
		t.Fatal(err)
	}
}

func waitForCancellationLockWaiter(t *testing.T, m *Manager, locks map[string]*imageLockEntry, key string) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		m.mutex.Lock()
		waiting := false
		for k, entry := range locks {
			if (key == "" || k == key) && entry.refs >= 2 {
				waiting = true
				break
			}
		}
		m.mutex.Unlock()
		if waiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("second consumer did not reach shared lock")
}
