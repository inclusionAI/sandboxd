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

package config

import "testing"

func TestRuncRuntimeResources(t *testing.T) {
	resources := RuntimeResources[RuntimeNameRunc]
	if len(resources) != 2 || resources[0] != ResourceNameCgroup || resources[1] != ResourceNameInterface {
		t.Fatalf("unexpected runc resources: %v", resources)
	}
}

func TestIsValidSandboxID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{id: "sbox-custom", valid: true},
		{id: "sbox-12345678-1234-1234-1234-123456789abc", valid: true},
		{id: "", valid: false},
		{id: "sbox", valid: false},
		{id: "sbox-", valid: false},
		{id: "sboxcustom", valid: false},
		{id: "sandbox-custom", valid: false},
		{id: "sbox-../../outside", valid: false},
		{id: "sbox-nested/id", valid: false},
		{id: `sbox-nested\id`, valid: false},
		{id: "sbox-line\nbreak", valid: false},
		{id: "sbox-null\x00byte", valid: false},
		{id: "sbox-name_with.dots", valid: true},
	}

	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			if got := IsValidSandboxID(test.id); got != test.valid {
				t.Fatalf("IsValidSandboxID(%q) = %v, want %v", test.id, got, test.valid)
			}
		})
	}
}
