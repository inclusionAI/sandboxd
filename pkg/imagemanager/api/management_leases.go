package api

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/inclusionAI/sandboxd/internal/keyedlock"
)

type managedMount struct {
	response OCIMountResponse
	owners   map[string]bool
}

// One backend reference per image protects every collection using it. Legacy
// callers without an owner retain their service-lifetime reference.
type managedMounts struct {
	service    ManagedImageMounter
	mu         sync.Mutex
	images     map[string]*managedMount
	retired    map[string]bool
	pending    map[string]map[string]bool
	failed     map[string]map[string]bool
	operations keyedlock.Locks
}

func newManagedMounts(service ManagedImageMounter) *managedMounts {
	return &managedMounts{service: service, images: map[string]*managedMount{}, retired: map[string]bool{}, pending: map[string]map[string]bool{}, failed: map[string]map[string]bool{}}
}

func (m *managedMounts) acquire(ctx context.Context, owner string, request *OCIMountRequest) (*OCIMountResponse, error) {
	unlock, err := m.operations.Acquire(ctx, request.ImageURL)
	if err != nil {
		return nil, err
	}
	defer unlock()
	m.mu.Lock()
	if m.retired[owner] {
		m.mu.Unlock()
		return nil, fmt.Errorf("managed collection is retired")
	}
	image := m.images[request.ImageURL]
	if image != nil {
		image.owners[owner] = true
		copy := image.response
		m.mu.Unlock()
		return &copy, nil
	}
	if m.pending[owner] == nil {
		m.pending[owner] = map[string]bool{}
	}
	m.pending[owner][request.ImageURL] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.pending[owner], request.ImageURL)
		if len(m.pending[owner]) == 0 {
			delete(m.pending, owner)
		}
		m.mu.Unlock()
	}()
	response, err := m.service.MountOCI(ctx, request)
	if err != nil {
		if _, ok := m.service.(interface {
			CleanupUnowned(context.Context, string) error
		}); ok {
			m.mu.Lock()
			if m.failed[owner] == nil {
				m.failed[owner] = map[string]bool{}
			}
			m.failed[owner][request.ImageURL] = true
			m.mu.Unlock()
		}
		return nil, err
	}
	m.mu.Lock()
	m.images[request.ImageURL] = &managedMount{response: *response, owners: map[string]bool{owner: true}}
	retired := m.retired[owner]
	m.mu.Unlock()
	if retired {
		// Retirement may have started while this mount was in flight. It shares
		// this image lock, then observes and releases the just-published acquire.
		return nil, fmt.Errorf("managed collection retired during image preparation")
	}
	copy := *response
	return &copy, nil
}

func (m *managedMounts) releaseOwner(ctx context.Context, owner string) error {
	if owner == "" {
		return fmt.Errorf("legacy image ownership requires service drain")
	}
	m.mu.Lock()
	m.retired[owner] = true
	images := make(map[string]bool)
	// Include pending acquires, which might publish after this snapshot. The
	// collection's filesystem lease fences/drains all acquires before retirement.
	for image, entry := range m.images {
		if entry.owners[owner] {
			images[image] = true
		}
	}
	for image := range m.pending[owner] {
		images[image] = true
	}
	for image := range m.failed[owner] {
		images[image] = true
	}
	m.mu.Unlock()
	var failures []error
	for image := range images {
		unlock, err := m.operations.Acquire(ctx, image)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		m.mu.Lock()
		entry := m.images[image]
		if entry == nil || !entry.owners[owner] {
			m.mu.Unlock()
			unlock()
			continue
		}
		last := len(entry.owners) == 1
		if !last {
			delete(entry.owners, owner)
		}
		m.mu.Unlock()
		if last {
			if err := m.service.UmountOCI(&OCIUmountRequest{ImageURL: image}); err != nil {
				failures = append(failures, err)
			} else {
				m.mu.Lock()
				delete(m.images, image)
				m.mu.Unlock()
			}
		}
		unlock()
	}
	if cleaner, ok := m.service.(interface {
		CleanupUnowned(context.Context, string) error
	}); ok {
		m.mu.Lock()
		failed := make([]string, 0, len(m.failed[owner]))
		for image := range m.failed[owner] {
			failed = append(failed, image)
		}
		m.mu.Unlock()
		for _, image := range failed {
			if err := cleaner.CleanupUnowned(ctx, image); err != nil {
				failures = append(failures, err)
				continue
			}
			m.mu.Lock()
			delete(m.failed[owner], image)
			if len(m.failed[owner]) == 0 {
				delete(m.failed, owner)
			}
			m.mu.Unlock()
		}
	}
	return errors.Join(failures...)
}

func (m *managedMounts) close() {
	// ManagementServer has joined its callers before releasing these references.
	for image := range m.images {
		_ = m.service.UmountOCI(&OCIUmountRequest{ImageURL: image})
	}
	if cleaner, ok := m.service.(interface {
		CleanupUnowned(context.Context, string) error
	}); ok {
		seen := map[string]bool{}
		for _, images := range m.failed {
			for image := range images {
				if !seen[image] {
					seen[image] = true
					_ = cleaner.CleanupUnowned(context.Background(), image)
				}
			}
		}
	}
}
