package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/inclusionAI/sandboxd/internal/managedlease"
	"github.com/moby/sys/mountinfo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const managedLifecycleVersion = 1

var managedOwnerKey = regexp.MustCompile(`^[a-f0-9]{64}-[a-f0-9]{32}$`)

func (h *sandboxService) managedLeases() managedlease.Store {
	return managedlease.Store{Root: h.config.ManagedRuntimeRoot}
}

func managedOwnerName(sandboxID string) string {
	hash := sha256.Sum256([]byte(sandboxID))
	return hex.EncodeToString(hash[:])
}

func (h *sandboxService) pinManagedOperation(ctx context.Context, record managedRecord) (func(), error) {
	if record.LifecycleVersion == 0 {
		return func() {}, nil
	}
	if record.LifecycleVersion != managedLifecycleVersion {
		return nil, fmt.Errorf("unsupported managed collection lifecycle")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	path := filepath.Join(h.config.ManagedRuntimeRoot, "pending", hex.EncodeToString(nonce[:]))
	if err := h.managedLeases().Pin(ctx, record.CollectionID, path); err != nil {
		return nil, err
	}
	return func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logrus.WithError(err).Warn("release managed operation lease")
		}
	}, nil
}

func (h *sandboxService) managedRecordForCollection(id string) (managedRecord, error) {
	var record managedRecord
	if !managedID.MatchString(id) {
		return record, fmt.Errorf("invalid managed collection identity")
	}
	data, err := os.ReadFile(filepath.Join(h.config.ManagedRuntimeRoot, "records", id+".json"))
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, err
	}
	if record.CollectionID != id {
		return record, fmt.Errorf("managed collection identity mismatch")
	}
	if record.LifecycleVersion != 0 && record.LifecycleVersion != managedLifecycleVersion {
		return record, fmt.Errorf("unsupported managed collection lifecycle")
	}
	return record, nil
}

func (h *sandboxService) claimManagedSandbox(ctx context.Context, sandboxID, id string) (string, func(), error) {
	if id == "" {
		return "", nil, nil
	}
	record, err := h.managedRecordForCollection(id)
	if err != nil {
		return "", nil, err
	}
	if record.LifecycleVersion != managedLifecycleVersion {
		return "", nil, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", nil, err
	}
	owner := managedOwnerName(sandboxID) + "-" + hex.EncodeToString(nonce[:])
	path := filepath.Join(h.config.ManagedRuntimeRoot, "owners", owner)
	if err := h.managedLeases().Pin(ctx, id, path); err != nil {
		return "", nil, err
	}
	return owner, func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logrus.WithError(err).Warn("release managed sandbox lease")
		}
	}, nil
}

func (h *sandboxService) releaseManagedSandbox(sandboxID, owner string) error {
	if h.config.ManagedRuntimeRoot == "" || owner == "" {
		return nil
	}
	if !managedOwnerKey.MatchString(owner) || !strings.HasPrefix(owner, managedOwnerName(sandboxID)+"-") {
		return fmt.Errorf("invalid managed sandbox owner")
	}
	err := os.Remove(filepath.Join(h.config.ManagedRuntimeRoot, "owners", owner))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (h *sandboxService) holdManagedCheckpoint(ctx context.Context, sandboxID string) (func(), error) {
	if h.config.ManagedRuntimeRoot == "" {
		return func() {}, nil
	}
	sandbox, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		return nil, err
	}
	id := sandbox.Metadata.Labels[managedCollectionLabel]
	if id == "" {
		return func() {}, nil
	}
	record, err := h.managedRecordForCollection(id)
	if err != nil {
		return nil, err
	}
	return h.pinManagedOperation(ctx, record)
}

type managedPlan struct {
	Images []struct {
		Reference string `json:"reference"`
		Root      string `json:"root"`
	} `json:"images"`
}

func (h *sandboxService) managedPlan(id string) (*managedPlan, error) {
	record, err := h.managedRecordForCollection(id)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(h.config.ManagedRuntimeRoot, "collections", id, ".metadata", "plan.json")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return nil, fmt.Errorf("invalid managed image plan")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var plan managedPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, err
	}
	unique := plan.Images[:0]
	seen := map[string]bool{}
	for _, image := range plan.Images {
		value := strings.TrimPrefix(image.Root, "/opt/akernel-images/")
		if len(value) != 64 || image.Root != "/opt/akernel-images/"+value {
			return nil, fmt.Errorf("invalid managed image root")
		}
		if _, err := hex.DecodeString(value); err != nil {
			return nil, err
		}
		ref, err := name.NewDigest(image.Reference)
		if err != nil || ref.DigestStr() != "sha256:"+value || ref.Context().RegistryStr() != record.Registry || !strings.HasPrefix(ref.Context().RepositoryStr(), record.RepositoryPrefix) {
			return nil, fmt.Errorf("invalid managed image dependency")
		}
		if !seen[image.Root] {
			seen[image.Root] = true
			unique = append(unique, image)
		}
	}
	plan.Images = unique
	return &plan, nil
}

func (h *sandboxService) collectManagedCollection(ctx context.Context, id string) (bool, error) {
	record, err := h.managedRecordForCollection(id)
	if err != nil {
		return false, err
	}
	if record.LifecycleVersion != managedLifecycleVersion {
		return false, nil
	} // Legacy ownership is unknown.
	// A cheap positive-reference hint avoids waiting behind active preparations.
	// The retirement lock rechecks the count before any destructive operation.
	info, err := os.Lstat(filepath.Join(h.config.ManagedRuntimeRoot, "leases", id))
	if err != nil {
		return false, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		return false, nil
	}
	return h.managedLeases().Collect(ctx, id, func() error {
		collection := filepath.Join(h.config.ManagedRuntimeRoot, "collections", id)
		// Include exports left by an interrupted prepare before plan publication.
		// The private collection lock has already drained broker operations. Read
		// mount metadata only: never enumerate or recurse through a ROFS root.
		mounts, err := mountinfo.GetMounts(nil)
		if err != nil {
			return err
		}
		for _, mount := range mounts {
			if strings.HasPrefix(mount.Mountpoint, collection+"/") {
				name := strings.TrimPrefix(mount.Mountpoint, collection+"/")
				if len(name) != 64 {
					return fmt.Errorf("unknown mount in managed collection")
				}
				if _, err := hex.DecodeString(name); err != nil {
					return fmt.Errorf("unknown mount in managed collection")
				}
			}
		}
		for _, mount := range mounts {
			if strings.HasPrefix(mount.Mountpoint, collection+"/") {
				if err := unix.Unmount(mount.Mountpoint, 0); err != nil && err != unix.EINVAL && err != unix.ENOENT {
					return err
				}
			}
		}
		if err := unix.Unmount(collection, 0); err != nil && err != unix.EINVAL && err != unix.ENOENT {
			return err
		}
		if h.imageMod == nil {
			return fmt.Errorf("managed image service unavailable")
		}
		if err := h.imageMod.ReleaseManagedImages(ctx, id); err != nil {
			return err
		}
		// Unmounts and provider release must all succeed before capability and
		// metadata deletion. A partial failure remains tombstoned for retry.
		for _, path := range []string{collection, filepath.Join(h.config.ManagedRuntimeRoot, "guests", id)} {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
		return os.Remove(filepath.Join(h.config.ManagedRuntimeRoot, "records", id+".json"))
	})
}

// Recovery runs before accepting new Start requests. Retained local checkpoint
// links remain independent of sandbox records and survive a source deletion.
func (h *sandboxService) recoverManagedCollections(ctx context.Context) error {
	if h.config.ManagedRuntimeRoot == "" {
		return nil
	}
	known := map[string]bool{}
	liveCollections := map[string]bool{}
	for _, sandbox := range h.sandboxManager.List() {
		if sandbox != nil && sandbox.Metadata != nil {
			if id := sandbox.Metadata.Labels[managedCollectionLabel]; id != "" {
				liveCollections[id] = true
				record, err := h.managedRecordForCollection(id)
				if err != nil {
					return err
				}
				if record.LifecycleVersion == managedLifecycleVersion {
					owner := sandbox.Metadata.Labels[managedOwnerLabel]
					if !managedOwnerKey.MatchString(owner) || !strings.HasPrefix(owner, managedOwnerName(sandbox.Metadata.ID)+"-") {
						return fmt.Errorf("missing managed runtime owner identity")
					}
					known[owner] = true
					path := filepath.Join(h.config.ManagedRuntimeRoot, "owners", owner)
					if err := h.managedLeases().VerifyPin(ctx, id, path); os.IsNotExist(err) {
						if err := h.managedLeases().Pin(ctx, id, path); err != nil {
							return err
						}
					} else if err != nil {
						return err
					}
				}
			}
		}
	}
	for _, part := range []string{"owners", "pending"} {
		entries, err := os.ReadDir(filepath.Join(h.config.ManagedRuntimeRoot, part))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				return fmt.Errorf("invalid managed lease entry")
			}
			if part == "pending" || !known[entry.Name()] {
				if err := os.Remove(filepath.Join(h.config.ManagedRuntimeRoot, part, entry.Name())); err != nil {
					return err
				}
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(h.config.ManagedRuntimeRoot, "records"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !managedID.MatchString(id) {
			continue
		}
		record, err := h.managedRecordForCollection(id)
		if err != nil {
			return err
		}
		if record.LifecycleVersion != managedLifecycleVersion {
			continue
		}
		collected, err := h.collectManagedCollection(ctx, id)
		if err != nil {
			return err
		}
		if collected {
			continue
		}
		lease, err := h.managedLeases().Lock(ctx, id, false)
		if err != nil {
			return err
		}
		if err := h.recoverManagedCollectionRoot(id, liveCollections[id]); err != nil {
			lease.Close()
			return err
		}
		plan, err := h.managedPlan(id)
		if err != nil {
			lease.Close()
			return err
		}
		for _, image := range plan.Images {
			mount, err := h.imageMod.AcquireManagedImage(ctx, id, image.Reference)
			if err != nil {
				lease.Close()
				return err
			}
			if err := h.recoverManagedBinding(id, image.Root, mount.MountPath, liveCollections[id]); err != nil {
				lease.Close()
				return err
			}
		}
		lease.Close()
	}
	return nil
}

func (h *sandboxService) recoverManagedCollectionRoot(id string, live bool) error {
	root := filepath.Join(h.config.ManagedRuntimeRoot, "collections", id)
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("managed collection storage is unavailable")
	}
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return err
	}
	mounted := false
	for _, mount := range mounts {
		if mount.Mountpoint == root {
			mounted = true
			for _, option := range strings.Fields(mount.Optional) {
				if strings.HasPrefix(option, "shared:") {
					return nil
				}
			}
		}
	}
	if live {
		return fmt.Errorf("live managed collection has no shared export root; refusing replacement")
	}
	if !mounted {
		if err := unix.Mount(root, root, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	return unix.Mount("", root, "", unix.MS_SHARED, "")
}

func (h *sandboxService) recoverManagedBinding(id, guestRoot, source string, live bool) error {
	destination := filepath.Join(h.config.ManagedRuntimeRoot, "collections", id, filepath.Base(guestRoot))
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return err
	}
	var from, to *mountinfo.Info
	for _, mount := range mounts {
		if mount.Mountpoint == source {
			from = mount
		}
		if mount.Mountpoint == destination {
			to = mount
		}
	}
	if from == nil {
		return fmt.Errorf("recovered managed ROFS is not mounted")
	}
	if to != nil && from.Major == to.Major && from.Minor == to.Minor && from.Root == to.Root && strings.Contains(","+to.Options+",", ",ro,") {
		return nil
	}
	if live {
		return fmt.Errorf("live managed collection has a stale export; refusing replacement")
	}
	if to != nil {
		if err := unix.Unmount(destination, 0); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(destination, 0755); err != nil {
		return err
	}
	if err := unix.Mount(source, destination, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := unix.Mount("", destination, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		return errors.Join(err, unix.Unmount(destination, 0))
	}
	return nil
}

func (h *sandboxService) startManagedCollectionGC() {
	if h.config.ManagedRuntimeRoot == "" {
		return
	}
	h.managedGCCancel = make(chan struct{})
	h.managedGCWait.Add(1)
	go func() {
		defer h.managedGCWait.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-h.managedGCCancel:
				return
			case <-ticker.C:
				entries, err := os.ReadDir(filepath.Join(h.config.ManagedRuntimeRoot, "records"))
				if err != nil {
					continue
				}
				for _, entry := range entries {
					select {
					case <-h.managedGCCancel:
						return
					default:
					}
					id := strings.TrimSuffix(entry.Name(), ".json")
					if !managedID.MatchString(id) {
						continue
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_, err := h.collectManagedCollection(ctx, id)
					cancel()
					if err != nil {
						logrus.WithError(err).WithField("collection_id", id).Warn("managed image collection cleanup deferred")
					}
				}
			}
		}
	}()
}
