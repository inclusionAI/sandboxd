package api

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedOwnerReleasePreservesOtherOwnersAndTaskRootfs(t *testing.T) {
	var mounts, unmounts atomic.Int32
	worker := &blockingImageService{mount: func(context.Context, *OCIMountRequest) (*OCIMountResponse, error) {
		mounts.Add(1)
		return &OCIMountResponse{MountPath: "/shared/lower"}, nil
	}, unmount: func(*OCIUmountRequest) error { unmounts.Add(1); return nil }}
	shared := NewSharedOCIService(worker)
	managed := newManagedMounts(shared)
	ctx := context.Background()
	request := &OCIMountRequest{ImageURL: "image"}
	for _, owner := range []string{"first", "second", "first"} {
		if _, err := managed.acquire(ctx, owner, request); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := shared.MountOCI(ctx, request); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"first", "second"} {
		if err := managed.releaseOwner(ctx, owner); err != nil {
			t.Fatal(err)
		}
	}
	if mounts.Load() != 1 || unmounts.Load() != 0 {
		t.Fatal("collection retirement released a live task rootfs")
	}
	if _, err := managed.acquire(ctx, "first", request); err == nil {
		t.Fatal("late acquire accepted after retirement")
	}
	if err := shared.UmountOCI(&OCIUmountRequest{ImageURL: "image"}); err != nil {
		t.Fatal(err)
	}
	if unmounts.Load() != 1 {
		t.Fatal("last rootfs reference was not released")
	}
}

func TestManagedRetirementJoinsPendingAcquire(t *testing.T) {
	entered := make(chan struct{})
	finish := make(chan struct{})
	var releaseMount sync.Once
	defer releaseMount.Do(func() { close(finish) })
	var unmounts atomic.Int32
	worker := &blockingImageService{mount: func(context.Context, *OCIMountRequest) (*OCIMountResponse, error) {
		close(entered)
		<-finish
		return &OCIMountResponse{}, nil
	}, unmount: func(*OCIUmountRequest) error { unmounts.Add(1); return nil }}
	m := newManagedMounts(worker)
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { _, err := m.acquire(ctx, "owner", &OCIMountRequest{ImageURL: "image"}); done <- err }()
	<-entered
	release := make(chan error, 1)
	go func() { release <- m.releaseOwner(ctx, "owner") }()
	// Wait for the release fence without relying on timing or sleeps.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		m.mu.Lock()
		retired := m.retired["owner"]
		m.mu.Unlock()
		if retired {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("owner retirement did not install its fence")
		default:
			runtime.Gosched()
		}
	}
	releaseMount.Do(func() { close(finish) })
	if err := <-done; err == nil {
		t.Fatal("retired mount was published to caller")
	}
	if err := <-release; err != nil {
		t.Fatal(err)
	}
	if unmounts.Load() != 1 {
		t.Fatal("pending mount survived retirement")
	}
}

func TestManagedReleaseFailureRetainsOwnershipForRetry(t *testing.T) {
	want := errors.New("busy")
	var attempts atomic.Int32
	worker := &blockingImageService{mount: func(context.Context, *OCIMountRequest) (*OCIMountResponse, error) { return &OCIMountResponse{}, nil }, unmount: func(*OCIUmountRequest) error {
		if attempts.Add(1) == 1 {
			return want
		}
		return nil
	}}
	m := newManagedMounts(worker)
	ctx := context.Background()
	if _, err := m.acquire(ctx, "owner", &OCIMountRequest{ImageURL: "image"}); err != nil {
		t.Fatal(err)
	}
	if err := m.releaseOwner(ctx, "owner"); !errors.Is(err, want) {
		t.Fatal("lost cleanup error")
	}
	if err := m.releaseOwner(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	if len(m.images) != 0 || attempts.Load() != 2 {
		t.Fatal("cleanup did not retry owned mount")
	}
}

func TestManagedRetirementRetriesFailedCancellationRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var unmounts atomic.Int32
	worker := &blockingImageService{mount: func(context.Context, *OCIMountRequest) (*OCIMountResponse, error) {
		cancel()
		return &OCIMountResponse{}, nil
	}, unmount: func(*OCIUmountRequest) error {
		if unmounts.Add(1) == 1 {
			return errors.New("rollback busy")
		}
		return nil
	}}
	shared := NewSharedOCIService(worker)
	m := newManagedMounts(shared)
	if _, err := m.acquire(ctx, "owner", &OCIMountRequest{ImageURL: "image"}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was lost")
	}
	if err := m.releaseOwner(context.Background(), "owner"); err != nil {
		t.Fatal(err)
	}
	if unmounts.Load() != 2 || len(shared.images) != 0 || len(m.failed) != 0 {
		t.Fatal("failed acquire lost its retryable rollback ownership")
	}
}
