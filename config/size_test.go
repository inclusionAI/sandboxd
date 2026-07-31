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

package config

import "testing"

func TestParseMemorySize(t *testing.T) {
	tests := []struct {
		value string
		want  int64
	}{
		{"", 0},
		{"0", 0},
		{"1024", 1024},
		{"512MiB", 512 << 20},
		{"2GiB", 2 << 30},
		{"2GB", 2_000_000_000},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := ParseMemorySize(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("ParseMemorySize(%q) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}

func TestParseMemorySizeRejectsInvalidValue(t *testing.T) {
	if _, err := ParseMemorySize("2Gibibytes"); err == nil {
		t.Fatal("ParseMemorySize accepted an invalid value")
	}
}
