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

package runtime

import (
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const kataRuntimeOptionsTypeURL = "types.containerd.io/runtimeoptions.v1.Options"

func kataRuntimeOptions(configPath string) (*anypb.Any, error) {
	if configPath == "" {
		return nil, nil
	}
	value, err := proto.Marshal(&runtimeoptions.Options{ConfigPath: configPath})
	if err != nil {
		return nil, err
	}
	return &anypb.Any{
		TypeUrl: kataRuntimeOptionsTypeURL,
		Value:   value,
	}, nil
}
