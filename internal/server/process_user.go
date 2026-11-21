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
	"fmt"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// resolveProcessUser validates the numeric target OCI user supplied by the caller.
// The runtime owns process credentials restored from a snapshot.
func resolveProcessUser(requested *runtime.ProcessUser) (*svc.User, error) {
	if requested == nil {
		return nil, nil
	}
	if requested.Uid == ^uint32(0) || requested.Gid == ^uint32(0) {
		return nil, fmt.Errorf("process_user UID/GID 4294967295 is reserved by Linux: %w", errord.ErrInvalidArgument)
	}
	return &svc.User{UID: requested.Uid, GID: requested.Gid}, nil
}
