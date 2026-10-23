// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"
)

// reconcileHostBoot keeps process restarts recoverable while retiring leases
// that cannot survive a kernel reboot. A Pod can retain its hostname when its
// worker reboots, so the existing Pod identity stamp cannot detect this case.
func reconcileHostBoot(storeDir string) error {
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fmt.Errorf("read host boot identity: %w", err)
	}
	return reconcileHostBootID(storeDir, strings.TrimSpace(string(bootID)))
}

func reconcileHostBootID(storeDir, current string) error {
	if current == "" {
		return errors.New("host boot identity is empty")
	}
	stamp := filepath.Join(storeDir, ".host_boot_id")
	previous, err := os.ReadFile(stamp)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read persisted host boot identity: %w", err)
	}
	if err == nil {
		stored := strings.TrimSpace(string(previous))
		if stored == "" {
			return errors.New("persisted host boot identity is empty")
		}
		if stored == current {
			return nil
		}
		if err := discardPreviousKernelLeases(filepath.Join(storeDir, "metadata.db")); err != nil {
			return err
		}
		logrus.Info("host boot changed; retired previous kernel cgroup and network leases")
	}
	// A legacy store without a boot stamp is adopted without discarding leases:
	// absence alone is not proof that its running kernel resources are gone.
	return persistHostBootID(storeDir, stamp, current)
}

func discardPreviousKernelLeases(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat kernel lease store: %w", err)
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("open previous kernel lease store: %w", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, key := range []string{config.CgroupBucket, config.BridgeIpBucket} {
			if err := tx.DeleteBucket([]byte(key)); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("retire previous kernel leases: %w", err)
	}
	return nil
}

func persistHostBootID(storeDir, stamp, current string) error {
	if err := os.MkdirAll(storeDir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(storeDir, ".host_boot_id-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(current); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), stamp); err != nil {
		return err
	}
	dir, err := os.Open(storeDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
