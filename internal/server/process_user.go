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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const checkpointProcessUserFile = "sandboxd-process-user.json"

type checkpointProcessUser struct {
	Version int       `json:"version"`
	User    *svc.User `json:"user"`
}

// resolveProcessUser runs before allocating resources. An old checkpoint may
// still be restored without an override, but cannot verify a requested change.
func resolveProcessUser(requested *runtime.ProcessUser, checkpointDir string) (*svc.User, error) {
	var user *svc.User
	if requested != nil {
		if requested.Uid == ^uint32(0) || requested.Gid == ^uint32(0) {
			return nil, fmt.Errorf("process_user UID/GID 4294967295 is reserved by Linux: %w", errord.ErrInvalidArgument)
		}
		user = &svc.User{UID: requested.Uid, GID: requested.Gid}
	}
	if checkpointDir == "" {
		return user, nil
	}
	data, err := os.ReadFile(filepath.Join(checkpointDir, checkpointProcessUserFile))
	if errors.Is(err, os.ErrNotExist) {
		if requested != nil {
			return nil, fmt.Errorf("checkpoint has no saved process user; omit process_user for legacy restore: %w", errord.ErrFailedPrecondition)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read checkpoint process user: %w", err)
	}
	var saved checkpointProcessUser
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("invalid checkpoint process user: %v: %w", err, errord.ErrInvalidArgument)
	}
	if saved.Version != 1 || saved.User == nil || saved.User.UID == ^uint32(0) || saved.User.GID == ^uint32(0) {
		return nil, fmt.Errorf("invalid checkpoint process user metadata: %w", errord.ErrInvalidArgument)
	}
	if user != nil && (user.UID != saved.User.UID || user.GID != saved.User.GID) {
		return nil, fmt.Errorf("process_user %d:%d conflicts with checkpoint identity %d:%d: %w", user.UID, user.GID, saved.User.UID, saved.User.GID, errord.ErrFailedPrecondition)
	}
	return saved.User, nil
}

// Write before capture, since a successful non-live checkpoint can stop the
// source. Preserve supplementary groups and umask as well as numeric IDs.
func writeCheckpointProcessUser(directory string, spec *specs.Spec) error {
	if spec == nil || spec.Process == nil {
		return fmt.Errorf("sandbox has no process spec: %w", errord.ErrFailedPrecondition)
	}
	user := spec.Process.User
	data, err := json.Marshal(checkpointProcessUser{Version: 1, User: &svc.User{
		UID: user.UID, GID: user.GID, Umask: user.Umask, AdditionalGids: user.AdditionalGids, Username: user.Username,
	}})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, checkpointProcessUserFile), data, 0600)
}
