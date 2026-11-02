// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package runsc

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

func TestHostsSeedPreservesDirectoryMetadata(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.Mkdir(etc, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(etc, 0750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1234567890, 123456789)
	if err := os.Chtimes(etc, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(etc, "user.hosts-seed-test", []byte("preserved"), 0); err != nil {
		t.Fatal(err)
	}
	directoryXattrs := []struct {
		path   string
		values map[string][]byte
	}{
		{root, map[string][]byte{
			"user.hosts-seed-binary": {0xff, 0x00, 0x80},
			"user.hosts-seed-empty":  {},
			"user.overlay.opaque":    []byte("y"),
		}},
		{etc, map[string][]byte{
			"user.hosts-seed-binary": {0x80, '\n', '=', 0x00, 0xff},
			"user.hosts-seed-\xff":   []byte("name-preserved"),
			"user.overlay.redirect":  []byte("ordinary-xattr"),
		}},
	}
	for _, directory := range directoryXattrs {
		for name, value := range directory.values {
			if err := unix.Setxattr(directory.path, name, value, 0); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A minimal default ACL remains meaningful even without named users.
	acl := make([]byte, 4+3*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, entry := range [][2]uint16{{1, 7}, {4, 5}, {32, 0}} {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(acl[offset:], entry[0])
		binary.LittleEndian.PutUint16(acl[offset+2:], entry[1])
		binary.LittleEndian.PutUint32(acl[offset+4:], ^uint32(0))
	}
	if err := unix.Setxattr(etc, "system.posix_acl_default", acl, 0); err != nil {
		t.Fatal(err)
	}
	h := &Handler{}
	headers, err := h.readHostsSeedHeaders(t.TempDir(), &runtimecore.Spec{Root: &runtimecore.Root{Path: root}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(etc)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if headers[1].Mode != int64(stat.Mode&07777) || headers[1].Uid != int(stat.Uid) || headers[1].Gid != int(stat.Gid) || !headers[1].ModTime.Equal(mtime) {
		t.Fatalf("directory metadata changed: %+v, stat=%+v", headers[1], stat)
	}
	if headers[1].PAXRecords["SCHILY.xattr.user.hosts-seed-test"] != "preserved" || headers[1].PAXRecords["SCHILY.xattr.system.posix_acl_default"] != base64.RawStdEncoding.EncodeToString(acl) {
		t.Fatalf("xattrs or ACL were not preserved: %#v", headers[1].PAXRecords)
	}
	for index, directory := range directoryXattrs {
		for name, value := range directory.values {
			got, exists := headers[index].PAXRecords["SCHILY.xattr."+name]
			if !exists || !bytes.Equal([]byte(got), value) {
				t.Fatalf("header %q xattr %q = %x (exists=%t), want %x", headers[index].Name, name, got, exists, value)
			}
		}
	}
	data, err := encodeHostsSeed(headers, []runtimecore.InitialFile{{Path: "/etc/hosts", Content: []byte("initial\n"), Mode: 0644}})
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(bytes.NewReader(data))
	for _, name := range []string{"./", "./etc/", "./etc/hosts"} {
		header, err := reader.Next()
		if err != nil || header.Name != name {
			t.Fatalf("header=%+v error=%v, want %s", header, err, name)
		}
		if name == "./etc/" && (!header.ModTime.Equal(mtime) || header.Mode != int64(stat.Mode&07777)) {
			t.Fatalf("tar lost directory metadata: %+v", header)
		}
		for index, parentName := range []string{"./", "./etc/"} {
			if name == parentName {
				for attrName, value := range directoryXattrs[index].values {
					got, exists := header.PAXRecords["SCHILY.xattr."+attrName]
					if !exists || !bytes.Equal([]byte(got), value) {
						t.Fatalf("tar header %q xattr %q = %x (exists=%t), want %x", name, attrName, got, exists, value)
					}
				}
			}
		}
		if name == "./etc/hosts" {
			content, err := io.ReadAll(reader)
			if err != nil || string(content) != "initial\n" || header.Mode != 0644 || header.Uid != 0 || header.Gid != 0 {
				t.Fatalf("bad hosts entry %+v content=%q err=%v", header, content, err)
			}
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatalf("unexpected extra tar entry: %v", err)
	}
}

func TestHostsSeedRejectsUnsafeParents(t *testing.T) {
	for _, kind := range []string{"symlink", "file", "missing"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			switch kind {
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "etc")); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(filepath.Join(root, "etc"), nil, 0644); err != nil {
					t.Fatal(err)
				}
			}
			headers, err := (&Handler{}).readHostsSeedHeaders(t.TempDir(), &runtimecore.Spec{Root: &runtimecore.Root{Path: root}})
			if kind != "missing" {
				if err == nil {
					t.Fatal("accepted non-directory /etc")
				}
			} else if err != nil || headers[1].Mode != 0755 || headers[1].Uid != 0 || headers[1].Gid != 0 {
				t.Fatalf("missing parent: %+v, %v", headers, err)
			}
		})
	}
}

func TestHostsXattrRepresentation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{"", []byte("ok")}, {"user.bad=name", []byte("ok")}, {"user.bad\x00name", []byte("ok")},
	} {
		if _, err := hostsXattrPAXValue(tc.name, tc.value); err == nil {
			t.Fatalf("silently accepted unrepresentable attribute %q", tc.name)
		}
	}
	value := []byte{0, 255, 3}
	encoded, err := hostsXattrPAXValue("system.posix_acl_access", value)
	if err != nil || encoded != base64.RawStdEncoding.EncodeToString(value) {
		t.Fatalf("ACL encoding=%q, %v", encoded, err)
	}
	if encoded, err := hostsXattrPAXValue("security.selinux", []byte("label\x00")); err != nil || encoded != "label\x00" {
		t.Fatalf("PAX xattr trailing NUL was rejected: %q %v", encoded, err)
	}
	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{"user.binary", []byte{0xff, 0x00, 0x80}},
		{"user.binary", []byte{0x80, '\n', '=', 0x00, 0xff}},
		{"user.empty", nil},
		{"user.nonutf8-\xff", []byte("name-preserved")},
	} {
		encoded, err := hostsXattrPAXValue(tc.name, tc.value)
		if err != nil || !bytes.Equal([]byte(encoded), tc.value) {
			t.Fatalf("PAX xattr %q = %x, %v, want %x", tc.name, encoded, err, tc.value)
		}
	}
}

func TestHostsDirectoryXattrsExcludeOverlayControls(t *testing.T) {
	// The root overlay uses trusted.overlay.*, not userxattr mode. Its
	// controls must be skipped before reading values, even if inaccessible.
	want := map[string][]byte{
		"trusted.overlayish.opaque": []byte("preserved"),
		"trusted.overlay":           []byte("preserved"),
		"user.overlay.opaque":       []byte("y"),
		"user.overlay.redirect":     {0xff, 0x00, 0x80},
		"user.empty":                {},
	}
	names := []string{"trusted.overlay.opaque", "trusted.overlay.redirect", "trusted.overlay.metacopy", "trusted.overlay.origin", "trusted.overlay."}
	for name := range want {
		names = append(names, name)
	}
	got, err := hostsDirectoryXattrRecords([]byte(strings.Join(names, "\x00")+"\x00"), func(name string) ([]byte, error) {
		value, ok := want[name]
		if !ok {
			t.Fatalf("read overlay control attribute %q", name)
		}
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("unexpected seed xattrs: %#v", got)
	}
	for name, value := range want {
		encoded, exists := got["SCHILY.xattr."+name]
		if !exists || !bytes.Equal([]byte(encoded), value) {
			t.Fatalf("seed xattr %q = %x (exists=%t), want %x", name, encoded, exists, value)
		}
	}
}

func TestHostsEROFSMetadataMountCleanup(t *testing.T) {
	for _, failure := range []string{"", "mount", "metadata", "unmount"} {
		t.Run(failure, func(t *testing.T) {
			bundle := t.TempDir()
			if err := os.Mkdir(filepath.Join(bundle, "rootfs"), 0755); err != nil {
				t.Fatal(err)
			}
			originalUnmount := unmountRunscNVProxyPath
			t.Cleanup(func() { unmountRunscNVProxyPath = originalUnmount })
			unmounts := 0
			unmountRunscNVProxyPath = func(target string, flags int) error {
				unmounts++
				if target != filepath.Join(bundle, hostsMetadataLowerDir) {
					t.Fatalf("unexpected unmount %s", target)
				}
				if failure == "unmount" {
					return syscall.EPERM
				}
				return nil
			}
			h := &Handler{mountEROFS: func(source, target string) error {
				if source != "/image.erofs" {
					t.Fatalf("wrong source %s", source)
				}
				if failure == "mount" {
					return errors.New("mount failed")
				}
				if failure == "metadata" {
					return os.Symlink("/outside", filepath.Join(target, "etc"))
				}
				return os.Mkdir(filepath.Join(target, "etc"), 0711)
			}}
			spec := &runtimecore.Spec{Root: &runtimecore.Root{Path: "rootfs"}, Annotations: map[string]string{runtimecore.GVisorRootfsAnnotationPrefix + "type": "erofs", runtimecore.GVisorRootfsAnnotationPrefix + "source": "/image.erofs"}}
			headers, err := h.readHostsSeedHeaders(bundle, spec)
			if (err != nil) != (failure != "") {
				t.Fatalf("headers=%v err=%v failure=%s", headers, err, failure)
			}
			if unmounts == 0 {
				t.Fatal("metadata mount cleanup was skipped")
			}
			_, statErr := os.Stat(filepath.Join(bundle, hostsMetadataLowerDir))
			if failure != "unmount" && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("mount directory remains: %v", statErr)
			}
			if failure == "unmount" && (err == nil || !strings.Contains(err.Error(), "unmount")) {
				t.Fatal("unmount failure was swallowed")
			}
			if failure == "" && headers[1].Mode != 0711 {
				t.Fatalf("read OCI placeholder instead of image lower: %+v", headers[1])
			}
		})
	}
}

func TestHostsMetadataCleanupRejectsSymlink(t *testing.T) {
	bundle, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(bundle, hostsMetadataLowerDir)); err != nil {
		t.Fatal(err)
	}
	original := unmountRunscNVProxyPath
	t.Cleanup(func() { unmountRunscNVProxyPath = original })
	unmountRunscNVProxyPath = func(string, int) error { t.Fatal("attempted unmount through a symlink"); return nil }
	if err := cleanupHostsMetadataMount(bundle); err == nil {
		t.Fatal("accepted symlinked metadata mount")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("changed symlink target: %v", err)
	}
}

// Nydus without HAS_XATTR returns ENOSYS; Linux FUSE exposes EOPNOTSUPP
// (the same errno as ENOTSUP). Check both calls and retries: unsupported
// directory metadata is empty, but direct EROFS and other errors stay fatal.
func TestHostsDirectoryXattrBackendPolicy(t *testing.T) {
	for _, policy := range []struct {
		name  string
		value hostsXattrPolicy
	}{
		{"directory", hostsXattrsVisible},
		{"direct-erofs", hostsXattrsRequired},
	} {
		for _, cause := range []error{unix.ENOTSUP, unix.ENOSYS, unix.EACCES, unix.EIO, errors.New("backend failure")} {
			for failCall := 1; failCall <= 4; failCall++ {
				t.Run(fmt.Sprintf("%s/%s/call-%d", policy.name, cause, failCall), func(t *testing.T) {
					calls := 0
					list := func(fd int, names []byte) (int, error) {
						if fd != 123 {
							t.Fatalf("unexpected fd %d", fd)
						}
						calls++
						if calls == failCall {
							return 0, fmt.Errorf("backend: %w", cause)
						}
						if calls == 2 {
							return 0, unix.ERANGE
						}
						return len("user.fixture\x00"), nil
					}
					names, err := listHostsDirectoryXattrs(123, policy.value, list)
					allowEmpty := policy.value == hostsXattrsVisible && (cause == unix.ENOTSUP || cause == unix.ENOSYS)
					if allowEmpty {
						if err != nil || len(names) != 0 {
							t.Fatalf("unsupported directory xattrs: names=%q err=%v", names, err)
						}
					} else if !errors.Is(err, cause) {
						t.Fatalf("metadata failure was lost: got %v want %v", err, cause)
					}
					if calls != failCall {
						t.Fatalf("calls=%d want %d", calls, failCall)
					}
				})
			}
		}
	}
}

func TestHostsDirectoryXattrListRetries(t *testing.T) {
	for _, policy := range []hostsXattrPolicy{hostsXattrsVisible, hostsXattrsRequired} {
		for _, retry := range []string{"erange", "zero-size-race"} {
			for _, exhausted := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/exhausted-%t", policy, retry, exhausted), func(t *testing.T) {
					calls := 0
					const want = "user.fixture\x00"
					list := func(_ int, names []byte) (int, error) {
						calls++
						attempt := (calls - 1) / 2
						if calls%2 == 1 {
							if retry == "zero-size-race" && (exhausted || attempt == 0) {
								return 0, nil
							}
							return len(want), nil
						}
						if exhausted || attempt == 0 {
							if retry == "erange" {
								return 0, unix.ERANGE
							}
							return len(want), nil
						}
						return copy(names, want), nil
					}
					names, err := listHostsDirectoryXattrs(123, policy, list)
					if exhausted {
						if err == nil || calls != 6 {
							t.Fatalf("unbounded or ignored metadata changes: calls=%d err=%v", calls, err)
						}
					} else if err != nil || string(names) != want || calls != 4 {
						t.Fatalf("retry lost metadata: names=%q calls=%d err=%v", names, calls, err)
					}
				})
			}
		}
	}
}
