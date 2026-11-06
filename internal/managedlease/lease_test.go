package managedlease

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveSnapshotAndRestoredCloneProtectUntilLastReference(t *testing.T) {
	s := Store{Root: t.TempDir()}
	id := strings.Repeat("a", 32)
	if err := s.Create(id); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	live := filepath.Join(s.Root, "owners", "source")
	snapshot := filepath.Join(t.TempDir(), CheckpointFile)
	clone := filepath.Join(s.Root, "owners", "clone")
	for _, path := range []string{live, snapshot, clone} {
		if err := s.Pin(ctx, id, path); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	cleanup := func() error { calls++; return nil }
	for _, path := range []string{live, snapshot, clone} {
		if done, err := s.Collect(ctx, id, cleanup); done || err != nil {
			t.Fatalf("collected referenced collection: %v %v", done, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if done, err := s.Collect(ctx, id, cleanup); !done || err != nil {
		t.Fatalf("last release: %v %v", done, err)
	}
	if calls != 1 {
		t.Fatalf("cleanup calls: %d", calls)
	}
}

func TestRetirementDrainsOperationsAndFencesLatePins(t *testing.T) {
	s := Store{Root: t.TempDir()}
	id := strings.Repeat("b", 32)
	ctx := context.Background()
	if err := s.Create(id); err != nil {
		t.Fatal(err)
	}
	operation, err := s.Lock(ctx, id, false)
	if err != nil {
		t.Fatal(err)
	}
	timeout, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	called := false
	if _, err := s.Collect(timeout, id, func() error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("retirement did not drain operation: %v", err)
	}
	operation.Close()
	want := errors.New("busy bind mount")
	if done, err := s.Collect(ctx, id, func() error { return want }); done || !errors.Is(err, want) {
		t.Fatalf("lost cleanup failure: %v %v", done, err)
	}
	if err := s.Pin(ctx, id, filepath.Join(s.Root, "owners", "late")); err == nil {
		t.Fatal("retired capability acquired a new reference")
	}
	if done, err := s.Collect(ctx, id, func() error { return nil }); !done || err != nil {
		t.Fatalf("retry: %v %v", done, err)
	}
}

func TestPinDoesNotAdoptForeignLinkOrUnknownCollection(t *testing.T) {
	s := Store{Root: t.TempDir()}
	id := strings.Repeat("c", 32)
	ctx := context.Background()
	if err := s.Create(id); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Root, "owners", "foreign")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Pin(ctx, id, path); err == nil {
		t.Fatal("adopted a foreign lease")
	}
	if err := s.Pin(ctx, strings.Repeat("d", 32), path); err == nil {
		t.Fatal("invented an unknown lease")
	}
	if err := s.VerifyPin(ctx, id, path); err == nil {
		t.Fatal("copied checkpoint marker was accepted as a lease")
	}
}

func TestRetirementFenceSurvivesStoreRestartAndCleanupRetry(t *testing.T) {
	root := t.TempDir()
	s := Store{Root: root}
	id := strings.Repeat("e", 32)
	ctx := context.Background()
	if err := s.Create(id); err != nil {
		t.Fatal(err)
	}
	want := errors.New("provider release interrupted")
	if collected, err := s.Collect(ctx, id, func() error { return want }); collected || !errors.Is(err, want) {
		t.Fatalf("partial cleanup: %v %v", collected, err)
	}
	// Reopen from disk with no process-local state. A durable retirement marker
	// must reject new owners and remain retryable by the restarted collector.
	restarted := Store{Root: root}
	if err := restarted.Pin(ctx, id, filepath.Join(root, "owners", "late")); err == nil {
		t.Fatal("restart lost the retirement fence")
	}
	calls := 0
	collected, err := restarted.Collect(ctx, id, func() error { calls++; return nil })
	if !collected || err != nil || calls != 1 {
		t.Fatalf("restarted cleanup: %v %v calls=%d", collected, err, calls)
	}
	for _, path := range []string{restarted.anchor(id), restarted.retired(id)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("cleanup retained %s: %v", path, err)
		}
	}
}
