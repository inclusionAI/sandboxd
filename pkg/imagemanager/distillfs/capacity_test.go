// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestChunkDBSizeValidation(t *testing.T) {
	for value, expected := range map[string]string{"": "", "8MiB": "8388608", "1GiB": "1073741824", "1048576": "1048576"} {
		actual, err := normalizeChunkDBSize(value)
		if err != nil || actual != expected {
			t.Fatalf("%q: %q, %v", value, actual, err)
		}
	}
	for _, value := range []string{"0", "-1", "1Mi", "1.5GiB", "1MB", "1048577", "1KiB", "18446744073709551615TiB"} {
		if _, err := normalizeChunkDBSize(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestChunkDBCapacityArguments(t *testing.T) {
	for _, command := range []string{"stats-chunk", "gc-chunk"} {
		want := []string{command, "--chunk-db-dir", "/cache", "--chunk-db-size", "8388608"}
		if got := chunkDBArgs(command, "/cache", "8388608"); !reflect.DeepEqual(got, want) {
			t.Fatal(got)
		}
		if got := chunkDBArgs(command, "/cache", ""); len(got) != 3 {
			t.Fatal(got)
		}
	}
	for _, source := range []string{"oss", "nydus"} {
		d := &Daemon{chunkDBSize: "8388608", meta: DaemonMeta{SourceType: source}}
		args := d.buildMountArgs()
		if strings.Join(args[len(args)-2:], " ") != "--chunk-db-size 8388608" {
			t.Fatal(args)
		}
		d.chunkDBSize = ""
		if strings.Contains(strings.Join(d.buildMountArgs(), " "), "--chunk-db-size") {
			t.Fatal("default must support old binaries")
		}
	}
}

// Run in a private mount namespace with /dev/fuse and mkfs.erofs available.
func TestChunkDBCapacityIntegration(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_DISTILLFS_INTEGRATION") != "1" {
		t.Skip("run make distillfs-test for privileged integration")
	}
	bin := os.Getenv("DISTILL_FS_BINARY")
	if bin == "" {
		t.Fatal("DISTILL_FS_BINARY must point to the distill-fs release binary")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0755); err != nil {
		t.Fatal(err)
	}
	expected := "chunk capacity integration\n"
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte(expected), 0644); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(root, "root.erofs")
	if output, err := exec.Command("mkfs.erofs", image, source).CombinedOutput(); err != nil {
		t.Fatalf("mkfs: %v: %s", err, output)
	}
	imageData, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, image) }))
	defer server.Close()
	// OSS forms bucket.endpoint; split 127.0.0.1 so no external DNS is needed.
	oss := BackendConfig{BackendType: "oss", Oss: &OssConfig{Scheme: "http", BucketName: "127", Endpoint: strings.TrimPrefix(server.URL, "http://127."), AccessKeyId: "test", AccessKeySecret: "test"}}
	cfg := &ManagerConfig{
		Root: filepath.Join(root, "manager"), BinPath: bin, DisableCgroup: true, ChunkDBSize: "8MiB",
		OSSCfgPath:   createTestConfigFile(t, root, "oss.json", oss),
		NydusCfgPath: createTestConfigFile(t, root, "nydus.json", BackendConfig{BackendType: "registry"}),
		OSSAuthsPath: createTestOSSAuthsFile(t, root), RegistryAuthsPath: createTestRegistryAuthsFile(t, root),
	}
	// Prepare without periodic workers so every test-owned process has a bounded lifetime.
	size, err := normalizeChunkDBSize(cfg.ChunkDBSize)
	if err != nil {
		t.Fatal(err)
	}
	mgr := &manager{ctx: context.Background(), root: cfg.Root, binPath: bin, chunkDBSize: size, daemons: map[string]*Daemon{}, recovered: map[string]bool{}}
	if err := mgr.prepare(cfg.OSSCfgPath, cfg.NydusCfgPath, cfg.OSSAuthsPath, cfg.RegistryAuthsPath); err != nil {
		t.Fatal(err)
	}
	checkStats := func() {
		t.Helper()
		stats, err := mgr.checkChunkDBStats()
		if err != nil {
			t.Fatal(err)
		}
		if stats.Storage.TotalSizeBytes != 8<<20 {
			t.Fatalf("capacity: %+v", stats.Storage)
		}
	}
	checkStats()
	if err := mgr.CreateDaemon(&DaemonCreateOpt{ID: "capacity", Name: "root.erofs"}); err != nil {
		t.Fatal(err)
	}
	d := mgr.GetDaemon("capacity")
	if err := d.Mount(); err != nil {
		log, _ := os.ReadFile(d.meta.DaemonLogPath)
		t.Fatalf("mount: %v: %s", err, log)
	}
	defer func() {
		if err := d.Unmount(); err != nil {
			t.Error(err)
		}
	}()
	checkRead := func() {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(d.MountPoint(), "root.erofs"))
		if err != nil || !bytes.Equal(data, imageData) {
			t.Fatalf("read: got %d bytes, want %d: %v", len(data), len(imageData), err)
		}
	}
	checkRead()
	checkStats()
	if err := mgr.gcChunkDB(); err != nil {
		t.Fatal(err)
	}
	checkRead()
	if err := d.Unmount(); err != nil {
		t.Fatal(err)
	}
	recovered := &manager{ctx: context.Background(), root: cfg.Root, binPath: bin, chunkDBSize: size, daemons: map[string]*Daemon{}, recovered: map[string]bool{}}
	if err := recovered.loadExistedDaemons(); err != nil {
		t.Fatal(err)
	}
	d = recovered.GetDaemon("capacity")
	if d == nil || d.chunkDBSize != size {
		t.Fatal("capacity lost during recovery")
	}
	if err := d.Mount(); err != nil {
		t.Fatal(err)
	}
	checkRead()
	checkStats()
}
