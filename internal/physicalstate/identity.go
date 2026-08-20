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

// Package physicalstate defines durable identities for sandboxd-owned
// physical facts. Distributed winner selection remains outside sandboxd.
package physicalstate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"google.golang.org/protobuf/proto"
)

// NewRestoreIdentity binds one deterministic target sandbox to the normalized
// logical restore request and checkpoint. Caller-provided trace IDs and object
// store credentials are excluded because they are transport/authentication
// details rather than physical sandbox identity.
func NewRestoreIdentity(
	checkpointID string,
	normalized *runtime.StartRequest,
) (*RestoreIdentity, error) {
	if strings.TrimSpace(checkpointID) == "" || normalized == nil {
		return nil, fmt.Errorf("checkpoint ID and normalized restore config are required: %w",
			errord.ErrInvalidArgument)
	}
	config := proto.Clone(normalized).(*runtime.StartRequest)
	config.TraceID = ""
	if config.Rootfs != nil {
		if s3 := config.Rootfs.GetS3Config(); s3 != nil {
			s3.AccessKeyID = ""
			s3.AccessKeySecret = ""
		}
	}
	request := &runtime.RestoreRequest{Config: config, CheckpointID: checkpointID}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal restore physical identity: %w", err)
	}
	digest := sha256.Sum256(data)
	return &RestoreIdentity{
		CheckpointID:  checkpointID,
		RequestSha256: hex.EncodeToString(digest[:]),
	}, nil
}
