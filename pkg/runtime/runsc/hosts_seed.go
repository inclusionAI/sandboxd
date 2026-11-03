// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package runsc

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

const (
	hostsMetadataLowerDir   = "managed-hosts-lower"
	maxHostsSeedBytes       = 4 << 20
	maxDirectoryXattrsBytes = 1 << 20
)

type hostsXattrPolicy uint8

const (
	// Direct EROFS is parsed independently by runsc, so a host-kernel xattr
	// limitation must never cause image metadata to be silently discarded.
	hostsXattrsRequired hostsXattrPolicy = iota
	// Directory lowers expose the same metadata to sandboxd and the gofer.
	// A backend without listxattr support therefore has no visible xattrs.
	hostsXattrsVisible
)

func (p hostsXattrPolicy) unavailable(err error) bool {
	return p == hostsXattrsVisible && (errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS))
}

// readHostsSeedHeaders inspects the original lower, never the OCI placeholder
// or the private host overlay's synthesized mount-point directories. Nothing
// is written through an image-owned path. Restore reuses the saved tar instead.
func (r *Handler) readHostsSeedHeaders(bundle string, spec *runtimecore.Spec) (headers []*tar.Header, retErr error) {
	if spec == nil || spec.Root == nil || spec.Root.Path == "" {
		return nil, errors.New("hosts seed requires a root filesystem")
	}
	lower := spec.Root.Path
	if !filepath.IsAbs(lower) {
		lower = filepath.Join(bundle, lower)
	}
	xattrPolicy := hostsXattrsVisible
	if source, image := runscNVProxyEROFSImageSource(spec); image {
		xattrPolicy = hostsXattrsRequired
		lower = filepath.Join(bundle, hostsMetadataLowerDir)
		if err := cleanupHostsMetadataMount(bundle); err != nil {
			return nil, err
		}
		if err := os.Mkdir(lower, 0700); err != nil {
			return nil, err
		}
		defer func() { retErr = errors.Join(retErr, cleanupHostsMetadataMount(bundle)) }()
		mount := r.mountEROFS
		if mount == nil {
			mount = mountRunscNVProxyEROFSImage
		}
		if err := mount(source, lower); err != nil {
			return nil, fmt.Errorf("mount hosts metadata lower: %w", err)
		}
	}
	root, err := os.OpenFile(lower, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open hosts lower: %w", err)
	}
	defer root.Close()
	rootHeader, err := hostsDirectoryHeader(root, "./", xattrPolicy)
	if err != nil {
		return nil, err
	}
	etcFD, err := unix.Openat(int(root.Fd()), "etc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		// No image metadata exists to preserve for a newly created parent.
		return []*tar.Header{rootHeader, {Name: "./etc/", Typeflag: tar.TypeDir, Mode: 0755, ModTime: rootHeader.ModTime, Format: tar.FormatPAX}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open lower /etc as a directory without symlinks: %w", err)
	}
	etc := os.NewFile(uintptr(etcFD), filepath.Join(lower, "etc"))
	defer etc.Close()
	etcHeader, err := hostsDirectoryHeader(etc, "./etc/", xattrPolicy)
	if err != nil {
		return nil, err
	}
	return []*tar.Header{rootHeader, etcHeader}, nil
}

func cleanupHostsMetadataMount(bundle string) error {
	target := filepath.Join(bundle, hostsMetadataLowerDir)
	if info, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	} else if !info.IsDir() {
		return errors.New("hosts metadata mount point is not a directory")
	}
	if err := unmountRunscNVProxyMount(target); err != nil {
		return fmt.Errorf("unmount hosts metadata lower: %w", err)
	}
	return os.RemoveAll(target)
}

func hostsDirectoryHeader(file *os.File, name string, xattrPolicy hostsXattrPolicy) (*tar.Header, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("hosts seed parent %q is not a directory", name)
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("directory ownership is unavailable for %q", name)
	}
	header.Name, header.Typeflag, header.Format = name, tar.TypeDir, tar.FormatPAX
	header.Uid, header.Gid = int(stat.Uid), int(stat.Gid)
	header.Uname, header.Gname = "", ""
	// Preserve setuid/setgid/sticky bits as well as ordinary permissions.
	header.Mode = int64(stat.Mode & 07777)
	header.PAXRecords, err = hostsDirectoryXattrs(int(file.Fd()), xattrPolicy)
	if err != nil {
		return nil, fmt.Errorf("read metadata for seed parent %q: %w", name, err)
	}
	return header, nil
}

func readDirectoryXattr(fd int, name string) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		size, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return nil, err
		}
		if size > maxDirectoryXattrsBytes {
			return nil, errors.New("directory xattr exceeds seed metadata limit")
		}
		value := make([]byte, size)
		n, err := unix.Fgetxattr(fd, name, value)
		if errors.Is(err, unix.ERANGE) || (err == nil && n > len(value)) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return value[:n], nil
	}
	return nil, errors.New("directory xattr changed repeatedly during seed creation")
}

func listHostsDirectoryXattrs(fd int, policy hostsXattrPolicy, list func(int, []byte) (int, error)) ([]byte, error) {
	var names []byte
	for attempt := 0; attempt < 3; attempt++ {
		size, err := list(fd, nil)
		if err != nil {
			if policy.unavailable(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("list directory xattrs: %w", err)
		}
		if size > maxDirectoryXattrsBytes {
			return nil, errors.New("directory xattr names exceed seed metadata limit")
		}
		names = make([]byte, size)
		n, err := list(fd, names)
		if errors.Is(err, unix.ERANGE) || (err == nil && n > len(names)) {
			names = nil
			continue
		}
		if err != nil {
			if policy.unavailable(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("list directory xattrs: %w", err)
		}
		names = names[:n]
		break
	}
	if names == nil {
		return nil, errors.New("directory xattr list changed repeatedly during seed creation")
	}
	return names, nil
}

func hostsDirectoryXattrs(fd int, policy hostsXattrPolicy) (map[string]string, error) {
	names, err := listHostsDirectoryXattrs(fd, policy, unix.Flistxattr)
	if err != nil {
		return nil, err
	}
	return hostsDirectoryXattrRecords(names, func(name string) ([]byte, error) {
		return readDirectoryXattr(fd, name)
	})
}

func hostsDirectoryXattrRecords(names []byte, read func(string) ([]byte, error)) (map[string]string, error) {
	records := make(map[string]string)
	total := len(names)
	for _, name := range strings.Split(string(names), "\x00") {
		// Match runsc's root overlay copy-up: it uses the default trusted
		// namespace, so lower overlay controls must not configure the upper.
		// user.overlay.* remains ordinary metadata without userxattr mode.
		if name == "" || strings.HasPrefix(name, "trusted.overlay.") {
			continue
		}
		value, err := read(name)
		if err != nil {
			return nil, fmt.Errorf("read directory xattr %q: %w", name, err)
		}
		total += len(value)
		if total > maxDirectoryXattrsBytes {
			return nil, errors.New("directory xattrs exceed seed metadata limit")
		}
		encoded, err := hostsXattrPAXValue(name, value)
		if err != nil {
			return nil, err
		}
		records["SCHILY.xattr."+name] = encoded
	}
	return records, nil
}

// Match the pinned gVisor tmpfs/tar.go writer, including its special POSIX
// ACL representation. Reject attributes that would otherwise be silently lost.
func hostsXattrPAXValue(name string, value []byte) (string, error) {
	if name == "" || strings.ContainsAny(name, "=\x00") {
		return "", fmt.Errorf("directory xattr %q cannot be represented in the hosts seed", name)
	}
	if name == "system.posix_acl_access" || name == "system.posix_acl_default" {
		return base64.RawStdEncoding.EncodeToString(value), nil
	}
	// archive/tar and runsc preserve SCHILY.xattr values as raw bytes, including
	// invalid UTF-8, NULs and empty values. Only the name needs PAX validation.
	return string(value), nil
}

func encodeHostsSeed(headers []*tar.Header, files []runtimecore.InitialFile) ([]byte, error) {
	if err := runtimecore.ValidateInitialFiles(files); err != nil {
		return nil, err
	}
	if len(files) != 1 || len(headers) != 2 || headers[0].Name != "./" || headers[1].Name != "./etc/" {
		return nil, errors.New("hosts seed requires root and /etc metadata and exactly one hosts file")
	}
	var data bytes.Buffer
	w := tar.NewWriter(&data)
	for _, header := range headers {
		if err := w.WriteHeader(header); err != nil {
			return nil, err
		}
	}
	file := files[0]
	if err := w.WriteHeader(&tar.Header{Name: "./etc/hosts", Typeflag: tar.TypeReg, Mode: int64(file.Mode), Size: int64(len(file.Content)), Format: tar.FormatPAX}); err != nil {
		return nil, err
	}
	if _, err := w.Write(file.Content); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if data.Len() > maxHostsSeedBytes {
		return nil, errors.New("hosts seed exceeds artifact limit")
	}
	return data.Bytes(), nil
}
