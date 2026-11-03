package api

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingImageService struct {
	Service
	mount   func(context.Context, *OCIMountRequest) (*OCIMountResponse, error)
	unmount func(*OCIUmountRequest) error
}

func (s *blockingImageService) MountOCI(ctx context.Context, r *OCIMountRequest) (*OCIMountResponse, error) {
	return s.mount(ctx, r)
}
func (s *blockingImageService) UmountOCI(r *OCIUmountRequest) error {
	if s.unmount != nil {
		return s.unmount(r)
	}
	return nil
}

func TestSharedMountDifferentImagesDoNotQueueBehindRegistryIO(t *testing.T) {
	entered, release := make(chan struct{}, 2), make(chan struct{})
	service := NewSharedOCIService(&blockingImageService{mount: func(ctx context.Context, r *OCIMountRequest) (*OCIMountResponse, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return &OCIMountResponse{MountPath: r.ImageURL}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, image := range []string{"a", "b"} {
		wg.Add(1)
		go func(image string) { defer wg.Done(); _, _ = service.MountOCI(ctx, &OCIMountRequest{ImageURL: image}) }(image)
	}
	for range 2 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Error("unrelated image serialized behind slow download")
		}
	}
	close(release)
	wg.Wait()
}

func TestSharedMountSameImageCoalescesAndKeepsCanceledWaiterOutOfRefcount(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var mounts, unmounts atomic.Int32
	service := NewSharedOCIService(&blockingImageService{mount: func(context.Context, *OCIMountRequest) (*OCIMountResponse, error) {
		mounts.Add(1)
		close(entered)
		<-release
		return &OCIMountResponse{MountPath: "shared"}, nil
	}, unmount: func(*OCIUmountRequest) error { unmounts.Add(1); return nil }})
	request := &OCIMountRequest{ImageURL: "same"}
	done := make(chan error, 12)
	go func() { _, err := service.MountOCI(context.Background(), request); done <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := service.MountOCI(ctx, request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter did not cancel independently: %v", err)
	}
	for range 11 {
		go func() { _, err := service.MountOCI(context.Background(), request); done <- err }()
	}
	close(release)
	for range 12 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for range 12 {
		if err := service.UmountOCI(&OCIUmountRequest{ImageURL: "same"}); err != nil {
			t.Fatal(err)
		}
	}
	if mounts.Load() != 1 || unmounts.Load() != 1 || len(service.images) != 0 {
		t.Fatalf("ownership mounts=%d unmounts=%d held=%d", mounts.Load(), unmounts.Load(), len(service.images))
	}
	if len(service.operations.entries) != 0 {
		t.Fatal("completed operation locks leaked")
	}
}

func TestCanceledLeaderRollsBackBeforeLiveFollowerCanAcquire(t *testing.T) {
	entered := make(chan struct{})
	var calls, releases atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service := NewSharedOCIService(&blockingImageService{mount: func(ctx context.Context, _ *OCIMountRequest) (*OCIMountResponse, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
		}
		return &OCIMountResponse{MountPath: "late-success"}, nil
	}, unmount: func(*OCIUmountRequest) error { releases.Add(1); return nil }})
	done := make(chan error, 1)
	go func() { _, err := service.MountOCI(ctx, &OCIMountRequest{ImageURL: "same"}); done <- err }()
	<-entered
	cancel()
	if _, err := service.MountOCI(context.Background(), &OCIMountRequest{ImageURL: "same"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 2 || releases.Load() != 1 || service.images["same"].refs != 1 {
		t.Fatal("late success leaked or live follower lost ownership")
	}
}

func TestCanceledMountRetainsFailedRollbackForRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := true
	service := NewSharedOCIService(&blockingImageService{mount: func(context.Context, *OCIMountRequest) (*OCIMountResponse, error) {
		cancel()
		return &OCIMountResponse{MountPath: "owned"}, nil
	}, unmount: func(*OCIUmountRequest) error {
		if failed {
			return errors.New("busy")
		}
		return nil
	}})
	if _, err := service.MountOCI(ctx, &OCIMountRequest{ImageURL: "a"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if image := service.images["a"]; image == nil || image.refs != 0 {
		t.Fatal("failed rollback identity lost")
	}
	failed = false
	if err := service.UmountOCI(&OCIUmountRequest{ImageURL: "a"}); err != nil || len(service.images) != 0 {
		t.Fatalf("cleanup retry failed: %v", err)
	}
}
