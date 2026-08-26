// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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

func TestStartResponseDataPlaneFieldNumbers(t *testing.T) {
	fields := (&StartResponse{}).ProtoReflect().Descriptor().Fields()
	want := map[protoreflect.Name]protoreflect.FieldNumber{
		"ports":               4,
		"bridge_ip":           5,
		"endpoint_generation": 6,
	}
	for name, number := range want {
		field := fields.ByName(name)
		if field == nil {
			t.Fatalf("StartResponse field %q is missing", name)
		}
		if field.Number() != number {
			t.Fatalf("StartResponse field %q number = %d, want %d", name, field.Number(), number)
		}
	}
}
