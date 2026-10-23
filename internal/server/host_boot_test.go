// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/stretchr/testify/require"
)

func seedBootResourceStore(t *testing.T, dir string) *store.BboltStoreImp {
	t.Helper()
	db := store.NewStoreImp(filepath.Join(dir, "metadata.db"))
	require.NoError(t, db.StoreRaw(config.CgroupBucket, []byte(`{"items":["/akernel/leased"]}`)))
	require.NoError(t, db.StoreRaw(config.BridgeIpBucket, []byte(`{"items":["active-tap"]}`)))
	require.NoError(t, db.StoreRaw("registration", []byte("retain-authoritative-metadata")))
	return db
}

func requireBootLeasesPresent(t *testing.T, db *store.BboltStoreImp) {
	t.Helper()
	for _, key := range []string{config.CgroupBucket, config.BridgeIpBucket} {
		data, err := db.LoadRaw(key)
		require.NoError(t, err)
		require.NotEmpty(t, data)
	}
}

func TestHostBootAdoptsUnstampedLegacyStoreWithoutReset(t *testing.T) {
	dir := t.TempDir()
	db := seedBootResourceStore(t, dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".pod_host"), []byte("same-pod"), 0644))

	require.NoError(t, reconcileHostBootID(dir, "boot-a"))
	requireBootLeasesPresent(t, db)
	stamp, err := os.ReadFile(filepath.Join(dir, ".host_boot_id"))
	require.NoError(t, err)
	require.Equal(t, "boot-a", string(stamp))
	pod, err := os.ReadFile(filepath.Join(dir, ".pod_host"))
	require.NoError(t, err)
	require.Equal(t, "same-pod", string(pod))
}

func TestHostBootSameKernelPreservesActiveLeases(t *testing.T) {
	dir := t.TempDir()
	db := seedBootResourceStore(t, dir)
	require.NoError(t, persistHostBootID(dir, filepath.Join(dir, ".host_boot_id"), "boot-a"))

	require.NoError(t, reconcileHostBootID(dir, "boot-a"))
	requireBootLeasesPresent(t, db)
}

func TestHostBootChangeRetiresOnlyKernelLeases(t *testing.T) {
	dir := t.TempDir()
	db := seedBootResourceStore(t, dir)
	require.NoError(t, persistHostBootID(dir, filepath.Join(dir, ".host_boot_id"), "boot-a"))
	bundle := filepath.Join(dir, "containers", "sandbox", "metadata.pb")
	require.NoError(t, os.MkdirAll(filepath.Dir(bundle), 0755))
	require.NoError(t, os.WriteFile(bundle, []byte("retain-for-normal-reconciliation"), 0600))

	require.NoError(t, reconcileHostBootID(dir, "boot-b"))
	for _, key := range []string{config.CgroupBucket, config.BridgeIpBucket} {
		_, err := db.LoadRaw(key)
		require.Error(t, err)
	}
	data, err := db.LoadRaw("registration")
	require.NoError(t, err)
	require.Equal(t, "retain-authoritative-metadata", string(data))
	data, err = os.ReadFile(bundle)
	require.NoError(t, err)
	require.Equal(t, "retain-for-normal-reconciliation", string(data))
	require.NoError(t, reconcileHostBootID(dir, "boot-b"))
}

func TestHostBootFailureDoesNotAdvanceStampOrEraseStore(t *testing.T) {
	dir := t.TempDir()
	stamp := filepath.Join(dir, ".host_boot_id")
	require.NoError(t, persistHostBootID(dir, stamp, "boot-a"))
	path := filepath.Join(dir, "metadata.db")
	corrupt := []byte("not-a-bbolt-database")
	require.NoError(t, os.WriteFile(path, corrupt, 0600))

	require.Error(t, reconcileHostBootID(dir, "boot-b"))
	data, err := os.ReadFile(stamp)
	require.NoError(t, err)
	require.Equal(t, "boot-a", string(data))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, corrupt, data)
}

func TestHostBootInvalidStampDoesNotEraseLeases(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "unreadable"}[directory], func(t *testing.T) {
			dir := t.TempDir()
			db := seedBootResourceStore(t, dir)
			stamp := filepath.Join(dir, ".host_boot_id")
			if directory {
				require.NoError(t, os.Mkdir(stamp, 0700))
			} else {
				require.NoError(t, os.WriteFile(stamp, nil, 0600))
			}
			require.Error(t, reconcileHostBootID(dir, "boot-b"))
			requireBootLeasesPresent(t, db)
		})
	}
}

func TestHostBootCanAdvanceAfterStoreWasRemoved(t *testing.T) {
	dir := t.TempDir()
	stamp := filepath.Join(dir, ".host_boot_id")
	require.NoError(t, persistHostBootID(dir, stamp, "boot-a"))
	require.NoError(t, reconcileHostBootID(dir, "boot-b"))
	require.NoFileExists(t, filepath.Join(dir, "metadata.db"))
	info, err := os.Stat(stamp)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestHostBootEmptyIdentityDoesNotAdoptStore(t *testing.T) {
	dir := t.TempDir()
	db := seedBootResourceStore(t, dir)
	require.Error(t, reconcileHostBootID(dir, ""))
	require.NoFileExists(t, filepath.Join(dir, ".host_boot_id"))
	requireBootLeasesPresent(t, db)
}
