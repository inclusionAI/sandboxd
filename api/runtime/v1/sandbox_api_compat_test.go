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
	const want = "d44984feff1c971fe689985571c1ff1a93b0e86fc073ddc6ad4cce6c5a0be3d4"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sandbox API descriptor hash = %s, want %s", got, want)
	}
}
