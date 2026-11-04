// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/stretchr/testify/require"
)

type ownershipBackend struct {
	imageapi.Service
	mounts, unmounts atomic.Int32
	failRelease      atomic.Bool
}

func (b *ownershipBackend) MountOCI(context.Context, *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	b.mounts.Add(1)
	return &imageapi.OCIMountResponse{MountPath: "/owned/rofs"}, nil
}
func (b *ownershipBackend) UmountOCI(*imageapi.OCIUmountRequest) error {
	b.unmounts.Add(1)
	if b.failRelease.Load() {
		return errors.New("busy")
	}
	return nil
}

// Block after the lower service has acquired ownership, before the upper
// manager publishes it. This exposes two overlapping first acquisitions.
type heldAcquireService struct {
	imageapi.Service
	entered chan string
	release chan struct{}
}

func (s *heldAcquireService) MountOCI(ctx context.Context, r *imageapi.OCIMountRequest) (*imageapi.OCIMountResponse, error) {
	resp, err := s.Service.MountOCI(ctx, r)
	s.entered <- r.ImageURL
	<-s.release // Deliberately exercise a backend that completes after cancellation.
	return resp, err
}
func holdAcquire(t *testing.T, service imageapi.Service) *heldAcquireService {
	s := &heldAcquireService{Service: service, entered: make(chan string, 8), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-s.release:
		default:
			close(s.release)
		}
	})
	return s
}
func awaitAcquire(t *testing.T, entered <-chan string) string {
	t.Helper()
	select {
	case image := <-entered:
		return image
	case <-time.After(3 * time.Second):
		t.Fatal("backend acquire did not start")
		return ""
	}
}
func awaitMount(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("mount did not complete")
		return nil
	}
}

func TestOCIMountConcurrentFirstAcquireOwnsOneLowerReference(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "legacy"
		if shared {
			name = "shared"
		}
		t.Run(name, func(t *testing.T) {
			backend := &ownershipBackend{}
			var service imageapi.Service = backend
			if shared {
				service = imageapi.NewSharedOCIService(service)
			}
			held := holdAcquire(t, service)
			manager := newOciMountManager(held)
			done := make(chan error, 2)
			go func() { _, err := manager.mountOCI("same"); done <- err }()
			require.Equal(t, "same", awaitAcquire(t, held.entered))
			go func() { _, err := manager.mountOCI("same"); done <- err }()
			// The upper manager must acquire the lower exactly once even when
			// the lower implements refcounts. Different layers cannot each
			// independently count both callers as owners.
			select {
			case <-held.entered:
				t.Error("duplicate lower acquire while first mount is unpublished")
			case <-time.After(100 * time.Millisecond):
			}
			close(held.release)
			require.NoError(t, awaitMount(t, done))
			require.NoError(t, awaitMount(t, done))
			require.NoError(t, manager.unmountOCI("same"))
			require.Zero(t, backend.unmounts.Load())
			require.NoError(t, manager.unmountOCI("same"))
			require.EqualValues(t, 1, backend.mounts.Load())
			require.EqualValues(t, 1, backend.unmounts.Load())
			require.Empty(t, manager.entries)
		})
	}
}

func TestOCIMountManagedOwnerSurvivesOrdinaryOwners(t *testing.T) {
	backend := &ownershipBackend{}
	service := imageapi.NewSharedOCIService(backend)
	_, err := service.MountOCI(context.Background(), &imageapi.OCIMountRequest{ImageURL: "same"})
	require.NoError(t, err)
	manager := newOciMountManager(service)
	for range 2 {
		_, err := manager.mountOCI("same")
		require.NoError(t, err)
	}
	for range 2 {
		require.NoError(t, manager.unmountOCI("same"))
	}
	require.Zero(t, backend.unmounts.Load(), "ordinary cleanup stopped managed lower")
	require.NoError(t, service.UmountOCI(&imageapi.OCIUmountRequest{ImageURL: "same"}))
	require.EqualValues(t, 1, backend.unmounts.Load())
}

func TestOCIMountFailedFinalReleaseCanBeRetried(t *testing.T) {
	backend := &ownershipBackend{}
	manager := newOciMountManager(imageapi.NewSharedOCIService(backend))
	_, err := manager.mountOCI("same")
	require.NoError(t, err)
	backend.failRelease.Store(true)
	require.Error(t, manager.unmountOCI("same"))
	require.Contains(t, manager.entries, "same", "failed release lost upper ownership")
	backend.failRelease.Store(false)
	require.NoError(t, manager.unmountOCI("same"))
	require.Empty(t, manager.entries)
	require.EqualValues(t, 2, backend.unmounts.Load())
}

func TestOCIMountWaiterCancellationAndIndependentImages(t *testing.T) {
	backend := &ownershipBackend{}
	held := holdAcquire(t, backend)
	manager := newOciMountManager(held)
	done := make(chan error, 2)
	go func() { _, err := manager.mountOCI("one"); done <- err }()
	require.Equal(t, "one", awaitAcquire(t, held.entered))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	canceled := make(chan error, 1)
	go func() { _, err := manager.mountOCIWithContext(ctx, "one"); canceled <- err }()
	require.ErrorIs(t, awaitMount(t, canceled), context.DeadlineExceeded)
	go func() { _, err := manager.mountOCI("two"); done <- err }()
	require.Equal(t, "two", awaitAcquire(t, held.entered), "unrelated images must not serialize")
	close(held.release)
	for range 2 {
		require.NoError(t, awaitMount(t, done))
	}
	require.EqualValues(t, 2, backend.mounts.Load())
	for _, image := range []string{"one", "two"} {
		require.NoError(t, manager.unmountOCI(image))
	}
	require.EqualValues(t, 2, backend.unmounts.Load())
}

func TestOCIMountCanceledLeaderRetainsFailedRollback(t *testing.T) {
	backend := &ownershipBackend{}
	held := holdAcquire(t, imageapi.NewSharedOCIService(backend))
	manager := newOciMountManager(held)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := manager.mountOCIWithContext(ctx, "same"); done <- err }()
	awaitAcquire(t, held.entered)
	backend.failRelease.Store(true)
	cancel()
	close(held.release)
	err := awaitMount(t, done)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "busy")
	require.Contains(t, manager.entries, "same")
	backend.failRelease.Store(false)
	_, err = manager.mountOCI("same")
	require.NoError(t, err)
	require.NoError(t, manager.unmountOCI("same"))
	require.Empty(t, manager.entries)
	require.EqualValues(t, 2, backend.mounts.Load(), "failed rollback must finish before reacquiring")
}

func TestOCIMountAcquireWaitsForFinalRelease(t *testing.T) {
	backend := &ownershipBackend{}
	manager := newOciMountManager(imageapi.NewSharedOCIService(backend))
	_, err := manager.mountOCI("same")
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	original := manager.unmountF
	var calls atomic.Int32
	manager.unmountF = func(image string) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return original(image)
	}
	released := make(chan error, 1)
	go func() { released <- manager.unmountOCI("same") }()
	<-entered
	acquired := make(chan error, 1)
	go func() { _, err := manager.mountOCI("same"); acquired <- err }()
	select {
	case err := <-acquired:
		t.Fatalf("new acquire overtook final release: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	require.NoError(t, awaitMount(t, released))
	require.NoError(t, awaitMount(t, acquired))
	require.EqualValues(t, 2, backend.mounts.Load())
	require.NoError(t, manager.unmountOCI("same"))
	require.Empty(t, manager.entries)
	require.EqualValues(t, 2, backend.unmounts.Load())
}

func TestOCIMountShutdownRetainsFailedRelease(t *testing.T) {
	backend := &ownershipBackend{}
	manager := newOciMountManager(imageapi.NewSharedOCIService(backend))
	for range 2 {
		_, err := manager.mountOCI("same")
		require.NoError(t, err)
	}
	backend.failRelease.Store(true)
	manager.cleanupAllOciUnmounts()
	require.Contains(t, manager.entries, "same")
	backend.failRelease.Store(false)
	manager.cleanupAllOciUnmounts()
	require.Empty(t, manager.entries)
	require.EqualValues(t, 2, backend.unmounts.Load())
}
