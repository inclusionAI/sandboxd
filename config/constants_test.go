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

func TestNormalizeCgroupVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "missing preserves v1", input: "", want: CgroupVersionV1},
		{name: "explicit v1", input: "v1", want: CgroupVersionV1},
		{name: "explicit v2", input: "v2", want: CgroupVersionV2},
		{name: "case and whitespace", input: " V2 ", want: CgroupVersionV2},
		{name: "invalid", input: "auto", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeCgroupVersion(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("NormalizeCgroupVersion(%q) unexpectedly succeeded", test.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeCgroupVersion(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("NormalizeCgroupVersion(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizeCgroupParent(t *testing.T) {
	tests := []struct {
		name    string
		version string
		parent  string
		want    string
		wantErr bool
	}{
		{name: "v1 ignores missing parent", version: CgroupVersionV1},
		{name: "v1 ignores configured parent", version: CgroupVersionV1, parent: "/ignored"},
		{name: "v2 root parent", version: CgroupVersionV2, parent: "/", want: "/"},
		{name: "v2 delegated parent", version: CgroupVersionV2, parent: "/system.slice/sandboxd.service", want: "/system.slice/sandboxd.service"},
		{name: "v2 requires parent", version: CgroupVersionV2, wantErr: true},
		{name: "v2 rejects relative parent", version: CgroupVersionV2, parent: "system.slice", wantErr: true},
		{name: "v2 rejects unclean parent", version: CgroupVersionV2, parent: "/system.slice/../other", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeCgroupParent(test.version, test.parent)
			if test.wantErr {
				if err == nil {
					t.Fatalf("NormalizeCgroupParent(%q, %q) unexpectedly succeeded", test.version, test.parent)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("NormalizeCgroupParent(%q, %q) = %q, want %q", test.version, test.parent, got, test.want)
			}
		})
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
