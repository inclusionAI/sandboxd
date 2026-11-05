// Package managedlease owns node-local managed-image leases. Hard links from
// live sandboxes and local checkpoint directories keep one collection alive.
package managedlease

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const CheckpointFile = ".managed-runtime.lease"

var collectionID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Store requires a private, operator-owned root on the local checkpoint
// filesystem. Collection IDs are never reused, including after retirement.
type Store struct{ Root string }

func (s Store) anchor(id string) string  { return filepath.Join(s.Root, "leases", id) }
func (s Store) retired(id string) string { return filepath.Join(s.Root, "retired", id) }

func (s Store) Create(id string) error {
	if !collectionID.MatchString(id) {
		return fmt.Errorf("invalid managed collection identity")
	}
	for _, part := range []string{"leases", "retired", "owners", "pending"} {
		if err := os.MkdirAll(filepath.Join(s.Root, part), 0700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(s.anchor(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close(), syncDirectory(filepath.Dir(s.anchor(id))))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

// Lock serializes retirement, reference changes, and the node broker's image
// operations. The broker uses flock(LOCK_EX) on this same regular file.
func (s Store) Lock(ctx context.Context, id string, allowRetired bool) (*os.File, error) {
	if !collectionID.MatchString(id) {
		return nil, fmt.Errorf("invalid managed collection identity")
	}
	fd, err := unix.Open(s.anchor(id), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), s.anchor(id))
	for {
		if err = ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			f.Close()
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	actual, err := f.Stat()
	expected, pathErr := os.Lstat(s.anchor(id))
	if err != nil || pathErr != nil || !actual.Mode().IsRegular() || !os.SameFile(actual, expected) {
		f.Close()
		return nil, fmt.Errorf("managed collection lease is unavailable")
	}
	if !allowRetired {
		if _, err := os.Lstat(s.retired(id)); !os.IsNotExist(err) {
			f.Close()
			return nil, fmt.Errorf("managed collection is retired")
		}
	}
	return f, nil
}

// Pin creates a new durable reference while fenced against retirement. An
// existing path belongs to another acquisition and is never adopted.
func (s Store) Pin(ctx context.Context, id, path string) error {
	f, err := s.Lock(ctx, id, false)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.Link(s.anchor(id), path); err != nil {
		return fmt.Errorf("pin managed collection (requires the same local filesystem and a fresh owner): %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

// VerifyPin never repairs a copied or missing checkpoint lease. A descriptor
// alone cannot promise that its collection was retained for restoration.
func (s Store) VerifyPin(ctx context.Context, id, path string) error {
	f, err := s.Lock(ctx, id, false)
	if err != nil {
		return err
	}
	defer f.Close()
	expected, err := f.Stat()
	if err != nil {
		return err
	}
	actual, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !actual.Mode().IsRegular() || !os.SameFile(actual, expected) {
		return fmt.Errorf("checkpoint managed collection lease is invalid")
	}
	return nil
}

// Collect fences late operations before cleanup. Failed cleanup leaves the
// tombstone and anchor for an explicit retry; the capability stays revoked.
// Never infer unreferenced state from an unreadable or unknown legacy record.
func (s Store) Collect(ctx context.Context, id string, cleanup func() error) (bool, error) {
	f, err := s.Lock(ctx, id, true)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return false, nil
	}
	marker, err := os.OpenFile(s.retired(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil && !os.IsExist(err) {
		return false, err
	}
	if marker != nil {
		if err := errors.Join(marker.Sync(), marker.Close()); err != nil {
			return false, err
		}
	}
	if err := cleanup(); err != nil {
		return false, err
	}
	if err := os.Remove(s.anchor(id)); err != nil {
		return false, err
	}
	return true, os.Remove(s.retired(id))
}
