package api

import (
	"context"
	"errors"
	"sync"

	"github.com/inclusionAI/sandboxd/internal/keyedlock"
)

// SharedOCIService keeps rootfs, image mounts and managed Docker consumers in
// one ownership domain. The underlying worker's unmount stops the ROFS daemon.
type SharedOCIService struct {
	Service
	mu         sync.Mutex
	images     map[string]*sharedOCI
	operations keyedlock.Locks
}

type sharedOCI struct {
	response OCIMountResponse
	refs     int
}

func NewSharedOCIService(service Service) *SharedOCIService {
	return &SharedOCIService{Service: service, images: make(map[string]*sharedOCI)}
}

func (s *SharedOCIService) MountOCI(ctx context.Context, request *OCIMountRequest) (*OCIMountResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	unlock, err := s.operations.Acquire(ctx, request.ImageURL)
	if err != nil {
		return nil, err
	}
	defer unlock()
	s.mu.Lock()
	image := s.images[request.ImageURL]
	if image != nil && image.refs > 0 {
		image.refs++
		copy := image.response
		s.mu.Unlock()
		return &copy, nil
	}
	s.mu.Unlock()
	if image != nil {
		// A previous canceled acquire reported a rollback failure. Keep that
		// ownership visible and finish cleanup before publishing another acquire.
		if err := s.Service.UmountOCI(&OCIUmountRequest{ImageURL: request.ImageURL}); err != nil {
			return nil, err
		}
		s.mu.Lock()
		delete(s.images, request.ImageURL)
		s.mu.Unlock()
	}
	response, err := s.Service.MountOCI(ctx, request)
	if err != nil {
		return nil, err
	}
	// A backend that completed concurrently with cancellation must not publish
	// an unowned mount. Preserve cleanup failure together with cancellation.
	if err := ctx.Err(); err != nil {
		cleanupErr := s.Service.UmountOCI(&OCIUmountRequest{ImageURL: request.ImageURL})
		if cleanupErr != nil {
			s.mu.Lock()
			s.images[request.ImageURL] = &sharedOCI{response: *response}
			s.mu.Unlock()
		}
		return nil, errors.Join(err, cleanupErr)
	}
	s.mu.Lock()
	s.images[request.ImageURL] = &sharedOCI{response: *response, refs: 1}
	s.mu.Unlock()
	copy := *response
	return &copy, nil
}

func (s *SharedOCIService) UmountOCI(request *OCIUmountRequest) error {
	unlock, _ := s.operations.Acquire(context.Background(), request.ImageURL)
	defer unlock()
	s.mu.Lock()
	image := s.images[request.ImageURL]
	if image != nil && image.refs > 1 {
		image.refs--
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	if err := s.Service.UmountOCI(request); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.images, request.ImageURL)
	s.mu.Unlock()
	return nil
}
