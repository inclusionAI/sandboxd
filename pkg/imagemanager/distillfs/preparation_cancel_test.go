package distillfs

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestCanceledBootstrapIsJoinedAndCannotMountAfterFailure(t *testing.T) {
	for _, lateSuccess := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled-fetch", true: "late-fetch-success"}[lateSuccess], func(t *testing.T) {
			mock := newMockDaemon(t.TempDir())
			mock.mockIsAlive = func() bool { return false }
			mock.meta.SourceType = "nydus"
			mock.meta.ImageURL = "registry.test/managed/main@sha256:abc"
			entered, finished := make(chan struct{}), make(chan struct{})
			mock.nydusClient = &mockNydusClient{fetchAndExtractFunc: func(ctx context.Context, _, _, _ string) (string, error) {
				close(entered)
				<-ctx.Done()
				defer close(finished)
				if lateSuccess {
					return "cached-bootstrap", nil
				}
				return "", ctx.Err()
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- mock.MountContext(ctx) }()
			<-entered
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("preparation did not join canceled fetch")
			}
			select {
			case <-finished:
			default:
				t.Fatal("background fetch survived failed acquire")
			}
			if mock.getState() != DaemonStateStopped || !mock.userStopped.Load() || !mock.mountFailed.Load() {
				t.Fatal("canceled daemon can still remount")
			}
			if _, err := os.Stat(mock.meta.CfgPath); !os.IsNotExist(err) {
				t.Fatal("canceled bootstrap continued into process startup")
			}
		})
	}
}

func TestBootstrapUsesOwnerDeadline(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	mock.mockIsAlive = func() bool { return false }
	mock.meta.SourceType = "nydus"
	mock.meta.ImageURL = "registry.test/managed/main"
	mock.nydusClient = &mockNydusClient{fetchAndExtractFunc: func(ctx context.Context, _, _, _ string) (string, error) { <-ctx.Done(); return "", ctx.Err() }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := mock.MountContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost owner deadline: %v", err)
	}
	if mock.getState() != DaemonStateStopped {
		t.Fatal("deadline left a mounting daemon")
	}
}
