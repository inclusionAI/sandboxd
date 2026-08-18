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
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCheckpointPublicContractContainsOnlyArtifactFacts(t *testing.T) {
	request := (&CheckpointRequest{}).ProtoReflect().Descriptor()
	assertFieldNumbers(t, request, 1, 2, 6, 7)
	assertReservedNumbers(t, request, 3, 4, 5)
	assertReservedNames(t, request, "timeout", "compress", "trace_id")

	response := (&CheckpointResponse{}).ProtoReflect().Descriptor()
	assertFieldNumbers(t, response, 3, 4, 5)
	assertReservedNumbers(t, response, 1, 2)
	assertReservedNames(t, response, "success", "message")
}

func TestRestoreReturnsAuthoritativeStartFacts(t *testing.T) {
	service := File_api_runtime_v1_sandbox_api_proto.Services().ByName("SandboxService")
	if service == nil {
		t.Fatal("SandboxService descriptor is missing")
	}
	restore := service.Methods().ByName("Restore")
	if restore == nil {
		t.Fatal("Restore method descriptor is missing")
	}
	if got, want := restore.Input().FullName(), protoreflect.FullName("runtime.v1.RestoreRequest"); got != want {
		t.Fatalf("Restore input = %s, want %s", got, want)
	}
	if got, want := restore.Output().FullName(), protoreflect.FullName("runtime.v1.StartResponse"); got != want {
		t.Fatalf("Restore output = %s, want %s", got, want)
	}

	start := (&StartResponse{}).ProtoReflect().Descriptor()
	ports := start.Fields().ByName("ports")
	if ports == nil || ports.Number() != 4 || !ports.IsList() {
		t.Fatalf("StartResponse.ports must remain repeated field 4")
	}
	status := (&SandboxStatus{}).ProtoReflect().Descriptor()
	statusPorts := status.Fields().ByName("ports")
	if statusPorts == nil || statusPorts.Number() != 16 || !statusPorts.IsList() {
		t.Fatalf("SandboxStatus.ports must remain repeated field 16")
	}
}

func assertFieldNumbers(t *testing.T, message protoreflect.MessageDescriptor, want ...protoreflect.FieldNumber) {
	t.Helper()
	fields := message.Fields()
	if fields.Len() != len(want) {
		t.Fatalf("%s has %d fields, want %d", message.FullName(), fields.Len(), len(want))
	}
	for i, number := range want {
		if got := fields.Get(i).Number(); got != number {
			t.Fatalf("%s field %d has number %d, want %d", message.FullName(), i, got, number)
		}
	}
}

func assertReservedNumbers(t *testing.T, message protoreflect.MessageDescriptor, want ...protoreflect.FieldNumber) {
	t.Helper()
	ranges := message.ReservedRanges()
	for _, number := range want {
		if !ranges.Has(number) {
			t.Errorf("%s does not reserve field %d", message.FullName(), number)
		}
	}
}

func assertReservedNames(t *testing.T, message protoreflect.MessageDescriptor, want ...protoreflect.Name) {
	t.Helper()
	names := message.ReservedNames()
	for _, name := range want {
		if !names.Has(name) {
			t.Errorf("%s does not reserve name %q", message.FullName(), name)
		}
	}
}
