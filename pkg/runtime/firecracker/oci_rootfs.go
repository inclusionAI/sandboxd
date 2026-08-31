// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firecracker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// OCIRootfsConverter materializes an image-manager-mounted OCI or Nydus rootfs
// directory as an immutable EROFS image suitable for a Firecracker drive.
type OCIRootfsConverter struct {
	mkfsPath string
	group    singleflight.Group
}

// NewOCIRootfsConverter validates and prepares an OCI-to-EROFS converter.
func NewOCIRootfsConverter(mkfsPath string) (*OCIRootfsConverter, error) {
	mkfsPath = strings.TrimSpace(mkfsPath)
	if mkfsPath == "" {
		return nil, errors.New("Firecracker mkfs.erofs path is empty")
	}
	resolvedMkfs, err := exec.LookPath(mkfsPath)
	if err != nil {
		return nil, fmt.Errorf("find mkfs.erofs %q: %w", mkfsPath, err)
	}
	return &OCIRootfsConverter{
		mkfsPath: resolvedMkfs,
	}, nil
}

// Convert returns a content-addressed EROFS image for imageRef, building it
// atomically under storage owned by the source image's existing lifecycle.
func (converter *OCIRootfsConverter) Convert(
	ctx context.Context,
	imageRef,
	contentID,
	artifactDir,
	sourceDir string,
) (string, error) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return "", errors.New("Firecracker OCI image reference is empty")
	}
	contentID = strings.TrimSpace(contentID)
	if contentID == "" {
		return "", errors.New("Firecracker OCI rootfs content ID is empty")
	}
	artifactDir = strings.TrimSpace(artifactDir)
	if artifactDir == "" {
		return "", errors.New("Firecracker OCI rootfs artifact directory is empty")
	}
	artifactInfo, err := os.Stat(artifactDir)
	if err != nil {
		return "", fmt.Errorf("stat Firecracker OCI artifact directory %s: %w", artifactDir, err)
	}
	if !artifactInfo.IsDir() {
		return "", fmt.Errorf("Firecracker OCI artifact path %s is not a directory", artifactDir)
	}
	info, err := os.Stat(sourceDir)
	if err != nil {
		return "", fmt.Errorf("stat Firecracker OCI rootfs %s: %w", sourceDir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("Firecracker OCI rootfs %s is not a directory", sourceDir)
	}

	digest := sha256.Sum256([]byte(contentID))
	key := hex.EncodeToString(digest[:])
	groupKey := filepath.Clean(artifactDir) + "\x00" + key
	value, err, _ := converter.group.Do(groupKey, func() (interface{}, error) {
		return converter.convert(ctx, imageRef, key, artifactDir, sourceDir)
	})
	if err != nil {
		return "", err
	}
	return value.(string), nil
}

func (converter *OCIRootfsConverter) convert(
	ctx context.Context,
	imageRef,
	key,
	artifactDir,
	sourceDir string,
) (string, error) {
	destination := filepath.Join(artifactDir, "rootfs-"+key+".erofs")
	if validEROFSFile(destination) {
		logrus.Infof(
			"reusing Firecracker OCI EROFS image %s for %s",
			destination,
			imageRef,
		)
		return destination, nil
	}
	if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove invalid Firecracker OCI EROFS cache %s: %w", destination, err)
	}

	temporary, err := os.CreateTemp(artifactDir, ".rootfs-"+key+"-*.erofs")
	if err != nil {
		return "", fmt.Errorf("create Firecracker OCI EROFS temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return "", fmt.Errorf("close Firecracker OCI EROFS temporary file: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return "", fmt.Errorf("prepare Firecracker OCI EROFS output path: %w", err)
	}
	defer os.Remove(temporaryPath)

	started := time.Now()
	var stderr bytes.Buffer
	command := exec.CommandContext(
		ctx,
		converter.mkfsPath,
		"--quiet",
		"-Enoinline_data",
		temporaryPath,
		sourceDir,
	)
	command.Stdout = io.Discard
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf(
			"materialize Firecracker OCI rootfs %s: %w: %s",
			imageRef,
			err,
			strings.TrimSpace(stderr.String()),
		)
	}
	if !validEROFSFile(temporaryPath) {
		return "", fmt.Errorf(
			"materialized Firecracker OCI rootfs %s is not a valid EROFS image",
			imageRef,
		)
	}
	if err := os.Chmod(temporaryPath, 0644); err != nil {
		return "", fmt.Errorf("chmod Firecracker OCI EROFS image: %w", err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return "", fmt.Errorf("publish Firecracker OCI EROFS image: %w", err)
	}
	logrus.Infof(
		"materialized Firecracker OCI rootfs %s at %s in %s",
		imageRef,
		destination,
		time.Since(started),
	)
	return destination, nil
}

func validEROFSFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 1024); err != nil {
		return false
	}
	return binary.LittleEndian.Uint32(magic[:]) == firecrackerEROFSMagic
}
