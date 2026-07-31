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

package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
)

// TestV010WireContract pins the public protobuf descriptor while allowing
// comments and generated-code details to change.
func TestV010WireContract(t *testing.T) {
	descriptor := protodesc.ToFileDescriptorProto(File_api_runtime_v1_sandbox_api_proto)
	descriptor.SourceCodeInfo = nil
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	const want = "a23d5cfd9854e85f890f9c8d3084920d2b2f54475984c69c844695e75d2d433e"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sandbox API descriptor hash = %s, want %s", got, want)
	}
}
