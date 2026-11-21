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
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
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
	// Rolled for optional StartRequest.process_user (24), SandboxStatus.process_user
	// (16) and ProcessUser; existing field numbers and omitted defaults are unchanged.
	// Recompute after any proto change: run this test, copy the got hash.
	const want = "e3ef0922c4da76d247aa1ab385f5e83204a55dc2e5e6d6e270ccb3d235714f8c"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sandbox API descriptor hash = %s, want %s", got, want)
	}
}

// Older clients must continue to decode the original fields when the server
// supplies the sandbox network endpoint required by newer YuanRong releases.
func TestStartResponseLegacyWireCompatibility(t *testing.T) {
	response := &StartResponse{Code: 0, Message: "Succeed", ID: "sandbox-compat", SandboxIp: "10.88.0.2"}
	message := protodesc.ToDescriptorProto(response.ProtoReflect().Descriptor())
	if got := message.Field[3].GetNumber(); got != 4 {
		t.Fatalf("sandbox_ip field number = %d, want 4", got)
	}
	message.Field = message.Field[:3]
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:        proto.String("legacy-start-response.proto"),
		Package:     proto.String("legacy"),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{message},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	legacy := dynamicpb.NewMessage(file.Messages().Get(0))
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(wire, legacy); err != nil {
		t.Fatal(err)
	}
	fields := legacy.Descriptor().Fields()
	if legacy.Get(fields.ByNumber(1)).Int() != 0 || legacy.Get(fields.ByNumber(2)).String() != "Succeed" || legacy.Get(fields.ByNumber(3)).String() != response.ID {
		t.Fatalf("legacy response fields changed: %s", legacy)
	}
	legacyWire, err := proto.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var decoded StartResponse
	if err := proto.Unmarshal(legacyWire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != response.ID || decoded.Message != response.Message || decoded.SandboxIp != "" {
		t.Fatalf("legacy server response did not retain its original fields: %s", &decoded)
	}
}

func TestProcessUserWirePresenceAndLegacyRequests(t *testing.T) {
	for _, user := range []*ProcessUser{nil, {}, {Uid: 1000, Gid: 1001}} {
		original := &StartRequest{SandboxID: "sbox-wire-user", ProcessUser: user}
		wire, err := proto.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		var decoded StartRequest
		if err := proto.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(original, &decoded) {
			t.Fatalf("presence or identity changed: %v", &decoded)
		}
	}
	descriptor := protodesc.ToFileDescriptorProto(File_api_runtime_v1_sandbox_api_proto)
	var legacyMessages []*descriptorpb.DescriptorProto
	for _, message := range descriptor.MessageType {
		if message.GetName() == "ProcessUser" {
			continue
		}
		if message.GetName() == "StartRequest" || message.GetName() == "SandboxStatus" {
			var fields []*descriptorpb.FieldDescriptorProto
			for _, field := range message.Field {
				if field.GetName() != "process_user" {
					fields = append(fields, field)
				}
			}
			message.Field = fields
		}
		legacyMessages = append(legacyMessages, message)
	}
	descriptor.MessageType = legacyMessages
	legacyFile, err := protodesc.NewFile(descriptor, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := dynamicpb.NewMessage(legacyFile.Messages().ByName("StartRequest"))
	fields := legacy.Descriptor().Fields()
	legacy.Set(fields.ByName("sandbox_id"), protoreflect.ValueOfString("sbox-old-client"))
	wire, err := proto.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var current StartRequest
	if err := proto.Unmarshal(wire, &current); err != nil {
		t.Fatal(err)
	}
	if current.ProcessUser != nil || current.SandboxID != "sbox-old-client" {
		t.Fatalf("legacy request changed: %v", &current)
	}
	wire, err = proto.Marshal(&StartRequest{SandboxID: "sbox-new-client", ProcessUser: &ProcessUser{Uid: 1000, Gid: 1001}})
	if err != nil {
		t.Fatal(err)
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(wire, legacy); err != nil {
		t.Fatal(err)
	}
	if got := legacy.Get(fields.ByName("sandbox_id")).String(); got != "sbox-new-client" {
		t.Fatalf("legacy decoding changed: %s", got)
	}
}
