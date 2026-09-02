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

package firecracker

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseFirecrackerExtraConfig(t *testing.T) {
	config, err := parseFirecrackerExtraConfig(
		`{"networkStack":"sandbox","nativeWritableMounts":[` +
			`{"target":"/var/lib/docker"}]}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.NativeWritableMounts) != 1 ||
		config.NativeWritableMounts[0].Target != "/var/lib/docker" {
		t.Fatalf("native writable mounts = %+v", config.NativeWritableMounts)
	}
}

func TestValidateFirecrackerNativeWritableMounts(t *testing.T) {
	valid := []firecrackerNativeWritableMount{
		{Target: "/var/lib/docker"},
		{Target: "/home/cache"},
	}
	if err := validateFirecrackerNativeWritableMounts(valid, []string{"/mnt/data"}); err != nil {
		t.Fatalf("valid native writable mounts rejected: %v", err)
	}
}

func TestValidateFirecrackerNativeWritableMountsRejectsInvalidTargets(t *testing.T) {
	tests := []struct {
		name     string
		mounts   []firecrackerNativeWritableMount
		existing []string
		message  string
	}{
		{
			name:    "relative",
			mounts:  []firecrackerNativeWritableMount{{Target: "var/lib/docker"}},
			message: "invalid",
		},
		{
			name:    "root",
			mounts:  []firecrackerNativeWritableMount{{Target: "/"}},
			message: "invalid",
		},
		{
			name:    "not canonical",
			mounts:  []firecrackerNativeWritableMount{{Target: "/var/../data"}},
			message: "invalid",
		},
		{
			name:    "system mount",
			mounts:  []firecrackerNativeWritableMount{{Target: "/run/docker"}},
			message: "system mount",
		},
		{
			name: "native overlap",
			mounts: []firecrackerNativeWritableMount{
				{Target: "/var/lib"},
				{Target: "/var/lib/docker"},
			},
			message: "overlap",
		},
		{
			name:     "regular mount overlap",
			mounts:   []firecrackerNativeWritableMount{{Target: "/mnt/data/cache"}},
			existing: []string{"/mnt/data"},
			message:  "overlaps mount target",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateFirecrackerNativeWritableMounts(test.mounts, test.existing)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("validation error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestValidateFirecrackerNativeWritableMountsRejectsTooMany(t *testing.T) {
	mounts := make([]firecrackerNativeWritableMount, firecrackerMaxNativeWritableMounts+1)
	for index := range mounts {
		mounts[index].Target = fmt.Sprintf("/data/%d", index)
	}
	err := validateFirecrackerNativeWritableMounts(mounts, nil)
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("validation error = %v", err)
	}
}
