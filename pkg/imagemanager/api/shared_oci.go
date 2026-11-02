package api

import (
	"context"
	"sync"
)

// SharedOCIService keeps rootfs, image mounts and managed Docker consumers in
// one ownership domain. The underlying worker's unmount stops the ROFS daemon.
type SharedOCIService struct {
	Service
	mu     sync.Mutex
	images map[string]*sharedOCI
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if image := s.images[request.ImageURL]; image != nil {
		image.refs++
		copy := image.response
		return &copy, nil
	}
	response, err := s.Service.MountOCI(ctx, request)
	if err != nil {
		return nil, err
	}
	s.images[request.ImageURL] = &sharedOCI{response: *response, refs: 1}
	copy := *response
	return &copy, nil
}

func (s *SharedOCIService) UmountOCI(request *OCIUmountRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	image := s.images[request.ImageURL]
	if image != nil && image.refs > 1 {
		image.refs--
		return nil
	}
	if err := s.Service.UmountOCI(request); err != nil {
		return err
	}
	delete(s.images, request.ImageURL)
	return nil
}
