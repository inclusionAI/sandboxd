package api

import (
	"context"
	"errors"
	"testing"
)

type fakeSharedService struct {
	Service
	mounts, unmounts int
	failRelease      bool
}

func (f *fakeSharedService) MountOCI(context.Context, *OCIMountRequest) (*OCIMountResponse, error) {
	f.mounts++
	return &OCIMountResponse{MountPath: "/existing/rofs"}, nil
}
func (f *fakeSharedService) UmountOCI(*OCIUmountRequest) error {
	f.unmounts++
	if f.failRelease {
		return errors.New("busy")
	}
	return nil
}
func TestManagedAndRootfsOwnersShareDaemonLifetime(t *testing.T) {
	backend := &fakeSharedService{}
	service := NewSharedOCIService(backend)
	for range 2 {
		if _, err := service.MountOCI(context.Background(), &OCIMountRequest{ImageURL: "immutable"}); err != nil {
			t.Fatal(err)
		}
	}
	if backend.mounts != 1 {
		t.Fatal("shared lower was mounted twice")
	}
	if err := service.UmountOCI(&OCIUmountRequest{ImageURL: "immutable"}); err != nil {
		t.Fatal(err)
	}
	if backend.unmounts != 0 {
		t.Fatal("deleting rootfs stopped another owner's lower")
	}
	backend.failRelease = true
	if err := service.UmountOCI(&OCIUmountRequest{ImageURL: "immutable"}); err == nil {
		t.Fatal("release failure was lost")
	}
	if service.images["immutable"].refs != 1 {
		t.Fatal("failed release lost ownership")
	}
	backend.failRelease = false
	if err := service.UmountOCI(&OCIUmountRequest{ImageURL: "immutable"}); err != nil {
		t.Fatal(err)
	}
	if len(service.images) != 0 {
		t.Fatal("last release retained ownership")
	}
}
