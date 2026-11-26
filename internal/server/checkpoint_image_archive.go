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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/keyedlock"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	checkpointImageArchiveReceipt = "akernel-image-archive.json"
	checkpointReleasePrefix       = "release-"
	temporaryCheckpointRepository = "akernel-ephemeral"
)

var (
	temporaryCheckpointBuild = regexp.MustCompile(`^[0-9a-f]{32}/service-0([:@].*)?$`)
	checkpointArtifactID     = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
	checkpointRuntimeLease   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type checkpointImageArchive struct {
	origin    string
	authority string
	scheme    string
	artifacts string
	tokenFile string
	state     string
	client    *http.Client
	pending   chan struct{}

	locks keyedlock.Locks
}

func newCheckpointImageArchive(cfg config.CheckpointImageArchiveConfig, store string) (*checkpointImageArchive, error) {
	if cfg == (config.CheckpointImageArchiveConfig{}) {
		return nil, nil
	}
	origin, err := url.Parse(cfg.Origin)
	if err != nil || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" ||
		origin.ForceQuery || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, errors.New("checkpoint image archive requires an HTTP(S) origin")
	}
	if origin.Scheme != "https" && (origin.Scheme != "http" ||
		(origin.Hostname() != "127.0.0.1" && origin.Hostname() != "::1")) {
		return nil, errors.New("checkpoint image archive requires private HTTPS")
	}
	if !filepath.IsAbs(cfg.CheckpointArtifacts) || !filepath.IsAbs(cfg.WorkerTokenFile) {
		return nil, errors.New("checkpoint image archive requires absolute paths for artifacts and worker credentials")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	archive := &checkpointImageArchive{
		origin: strings.TrimSuffix(origin.String(), "/"), authority: origin.Host, scheme: origin.Scheme,
		artifacts: filepath.Clean(cfg.CheckpointArtifacts), tokenFile: cfg.WorkerTokenFile,
		state:   filepath.Join(filepath.Dir(store), "checkpoint-image-leases"),
		pending: make(chan struct{}, 1),
		client: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if _, err := archive.credential(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(archive.state, 0700); err != nil {
		return nil, err
	}
	if err := syncArchiveDirectory(filepath.Dir(archive.state)); err != nil {
		return nil, err
	}
	return archive, nil
}

func (a *checkpointImageArchive) credential() (string, error) {
	body, err := os.ReadFile(a.tokenFile)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(body))
	if token == "" || strings.ContainsAny(token, " \r\n\t") {
		return "", errors.New("checkpoint image archive worker credential is invalid")
	}
	return token, nil
}

func (a *checkpointImageArchive) call(ctx context.Context, operation string, fields map[string]string) (string, error) {
	token, err := a.credential()
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.origin+"/v1/archive/"+operation, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var result struct {
		Reference string `json:"reference"`
		Error     string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&result); err != nil {
		return "", fmt.Errorf("checkpoint image archive %s returned HTTP %d: %w", operation, response.StatusCode, err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checkpoint image archive %s returned HTTP %d: %s", operation, response.StatusCode, result.Error)
	}
	return result.Reference, nil
}

func normalizeCheckpointImage(image string) string {
	return strings.TrimPrefix(strings.TrimPrefix(image, "https://"), "http://")
}

// A temporary image belongs to the reserved build namespace of a configured
// managed Registry. The worker's profiles supply the trusted source.
func (h *sandboxService) isTemporaryCheckpointImage(image string) bool {
	authority, repository, _ := strings.Cut(image, "/")
	prefix, build, _ := strings.Cut(repository, "/")
	if authority == "" || prefix != temporaryCheckpointRepository || !temporaryCheckpointBuild.MatchString(build) {
		return false
	}
	for _, profile := range h.config.ManagedRuntimeProfiles {
		if profile.Registry == authority && profile.RepositoryPrefix == prefix {
			return true
		}
	}
	return false
}

func (a *checkpointImageArchive) validateUserImages(request *runtime.StartRequest) error {
	if a == nil {
		return nil
	}
	isArchive := func(ref string) bool {
		host, _, _ := strings.Cut(normalizeCheckpointImage(ref), "/")
		return strings.EqualFold(host, a.authority)
	}
	if isArchive(request.GetRootfs().GetImageUrl()) {
		return fmt.Errorf("checkpoint archive rootfs references are internal to restore: %w", errord.ErrInvalidArgument)
	}
	for _, mount := range request.GetMounts() {
		if isArchive(mount.GetImageUrl()) {
			return fmt.Errorf("checkpoint archive images cannot be mounted by callers: %w", errord.ErrInvalidArgument)
		}
	}
	return nil
}

func (a *checkpointImageArchive) artifact(dir string) (string, error) {
	id := filepath.Base(dir)
	if filepath.Dir(dir) != a.artifacts || !checkpointArtifactID.MatchString(id) {
		return "", fmt.Errorf("temporary checkpoint images require the distributed checkpoint store: %w", errord.ErrFailedPrecondition)
	}
	return id, nil
}

func (a *checkpointImageArchive) leaseFile(id string) string {
	return filepath.Join(a.state, uuid.NewSHA1(uuid.NameSpaceOID, []byte(id)).String())
}

func readArchiveLease(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !checkpointRuntimeLease.Match(value) {
		return "", errors.New("checkpoint image runtime lease state is invalid")
	}
	return string(value), nil
}

func (a *checkpointImageArchive) reserve(id string) (string, error) {
	value, err := readArchiveLease(a.leaseFile(id))
	if !errors.Is(err, os.ErrNotExist) {
		return value, err
	}
	randomLease, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	value = strings.ReplaceAll(randomLease.String(), "-", "")
	file, err := os.CreateTemp(a.state, ".lease-")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.WriteString(value)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return "", err
	}
	if err := os.Rename(file.Name(), a.leaseFile(id)); err != nil {
		return "", err
	}
	return value, syncArchiveDirectory(a.state)
}

// queueRelease persists the worker's proof that the runtime is gone. An archive
// outage can delay reference cleanup while local sandbox deletion completes.
func (a *checkpointImageArchive) queueRelease(id string) error {
	return a.queueReleaseFile(a.leaseFile(id))
}

func (a *checkpointImageArchive) queueReleaseFile(path string) error {
	lease, err := readArchiveLease(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.Rename(path, filepath.Join(a.state, checkpointReleasePrefix+lease)); err != nil {
		return err
	}
	if err := syncArchiveDirectory(a.state); err != nil {
		return err
	}
	select {
	case a.pending <- struct{}{}:
	default:
	}
	return nil
}

func (a *checkpointImageArchive) runPendingReleases(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		drain, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err := a.drainPendingReleases(drain); err != nil && ctx.Err() == nil {
			logrus.WithError(err).Warn("checkpoint image lease release deferred")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.pending:
		}
	}
}

func (a *checkpointImageArchive) drainPendingReleases(ctx context.Context) error {
	entries, err := os.ReadDir(a.state)
	if err != nil {
		return err
	}
	var releaseErrors []error
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(releaseErrors, err)...)
		}
		lease, ok := strings.CutPrefix(entry.Name(), checkpointReleasePrefix)
		if !ok || !checkpointRuntimeLease.MatchString(lease) || !entry.Type().IsRegular() {
			continue
		}
		request, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := a.releaseFile(request, filepath.Join(a.state, entry.Name()))
		cancel()
		if err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	return errors.Join(releaseErrors...)
}

func (a *checkpointImageArchive) releaseFile(ctx context.Context, path string) error {
	lease, err := readArchiveLease(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := a.call(ctx, "release", map[string]string{"lease": lease}); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncArchiveDirectory(a.state)
}

// During startup, verify runtime inventory before queuing release for leases
// whose sandbox metadata was lost on a process failure or pod replacement.
func (h *sandboxService) recoverCheckpointImageLeases(ctx context.Context) error {
	archive := h.checkpointImageArchive
	if archive == nil {
		return nil
	}
	entries, err := os.ReadDir(archive.state)
	if err != nil || len(entries) == 0 {
		return err
	}
	known := make(map[string]bool)
	for _, sandbox := range h.sandboxManager.List() {
		if sandbox.Metadata != nil {
			known[archive.leaseFile(sandbox.Metadata.ID)] = true
		}
	}
	for _, handler := range h.serviceHandler.Items() {
		runtimes, err := handler.List(ctx)
		if err != nil {
			return fmt.Errorf("confirm local runtimes before checkpoint image lease cleanup: %w", err)
		}
		for _, state := range runtimes {
			known[archive.leaseFile(state.ID)] = true
		}
	}
	var queueErrors []error
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(queueErrors, err)...)
		}
		path := filepath.Join(archive.state, entry.Name())
		if _, err := uuid.Parse(entry.Name()); entry.Type().IsRegular() && err == nil && !known[path] {
			if err := archive.queueReleaseFile(path); err != nil {
				queueErrors = append(queueErrors, err)
			}
		}
	}
	return errors.Join(queueErrors...)
}

func syncArchiveDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (m *fsManager) checkpointRootImage(id string) (string, error) {
	if m == nil {
		return "", nil
	}
	m.mu.Lock()
	state := m.sandboxState[id]
	m.mu.Unlock()
	if len(state.Rootfs) == 0 {
		return "", nil
	}
	var rootfs runtime.RootfsConfig
	if err := proto.Unmarshal(state.Rootfs, &rootfs); err != nil {
		return "", err
	}
	return normalizeCheckpointImage(rootfs.GetImageUrl()), nil
}

func (h *sandboxService) captureCheckpointImage(ctx context.Context, id, dir string) error {
	archive := h.checkpointImageArchive
	image, err := h.fsMgr.checkpointRootImage(id)
	if err != nil {
		return err
	}
	if !h.isTemporaryCheckpointImage(image) &&
		(archive == nil || !strings.HasPrefix(image, archive.authority+"/akernel-checkpoint/")) {
		return nil
	}
	if archive == nil {
		return fmt.Errorf("temporary checkpoint image archive is unavailable: %w", errord.ErrFailedPrecondition)
	}
	unlock, err := archive.locks.Acquire(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	// The source may have been deleted while this checkpoint waited.
	currentImage, err := h.fsMgr.checkpointRootImage(id)
	if err != nil {
		return err
	}
	if currentImage != image {
		return fmt.Errorf("checkpoint source image changed: %w", errord.ErrFailedPrecondition)
	}
	artifact, err := archive.artifact(dir)
	if err != nil {
		return err
	}
	lease, err := archive.reserve(id)
	if err != nil {
		return err
	}
	_, err = archive.call(ctx, "capture", map[string]string{
		"artifact": artifact, "reference": image, "lease": lease,
	})
	return err
}

func (h *sandboxService) restoreCheckpointImage(ctx context.Context, id, dir string, rootfs *runtime.RootfsConfig) (bool, error) {
	image := normalizeCheckpointImage(rootfs.GetImageUrl())
	temporary := h.isTemporaryCheckpointImage(image)
	receipt, err := os.Lstat(filepath.Join(dir, checkpointImageArchiveReceipt))
	if errors.Is(err, os.ErrNotExist) && !temporary {
		return false, nil
	}
	if err != nil || !temporary || !receipt.Mode().IsRegular() || h.checkpointImageArchive == nil {
		return false, fmt.Errorf("checkpoint image archive receipt or service is unavailable: %w", errord.ErrFailedPrecondition)
	}
	archive := h.checkpointImageArchive
	artifact, err := archive.artifact(dir)
	if err != nil {
		return false, err
	}
	lease, err := archive.reserve(id)
	if err != nil {
		return false, err
	}
	archived, err := archive.call(ctx, "restore", map[string]string{
		"artifact": artifact, "reference": image, "lease": lease,
	})
	if err != nil {
		return true, err
	}
	_, digest, _ := strings.Cut(image, "@")
	if archived != archive.origin+"/akernel-checkpoint/"+lease+"@"+digest {
		return true, errors.New("checkpoint image archive returned an unexpected OCI reference")
	}
	rootfs.Source = &runtime.RootfsConfig_ImageUrl{ImageUrl: normalizeCheckpointImage(archived)}
	return true, nil
}
