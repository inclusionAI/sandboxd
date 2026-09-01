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

package main

import (
	"reflect"
	"testing"
)

func TestParseMountFlags(t *testing.T) {
	mounts, err := parseMountFlags([]string{
		"/host/data:/mnt/data:bind:ro,nodev",
		"tmpfs:/run/cache:tmpfs:rw,size=1m",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 {
		t.Fatalf("mount count = %d", len(mounts))
	}
	if mounts[0].GetHostPath() != "/host/data" ||
		mounts[0].GetTarget() != "/mnt/data" ||
		mounts[0].GetType() != "bind" ||
		!reflect.DeepEqual(mounts[0].GetOptions(), []string{"ro", "nodev"}) {
		t.Fatalf("first mount = %+v", mounts[0])
	}
	if mounts[1].GetHostPath() != "tmpfs" ||
		mounts[1].GetType() != "tmpfs" ||
		!reflect.DeepEqual(mounts[1].GetOptions(), []string{"rw", "size=1m"}) {
		t.Fatalf("second mount = %+v", mounts[1])
	}
}

func TestParseMountFlagsRejectsMalformedValue(t *testing.T) {
	for _, value := range []string{"", "source", ":/target", "source:"} {
		if _, err := parseMountFlags([]string{value}); err == nil {
			t.Fatalf("accepted malformed mount %q", value)
		}
	}
}
