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

package util

import (
	"path/filepath"
	"testing"
)

func TestJoinWithinRoot(t *testing.T) {
	root := t.TempDir()
	got, err := JoinWithinRoot(root, "sbox-safe", "config.json")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "sbox-safe", "config.json")
	if got != want {
		t.Fatalf("JoinWithinRoot() = %q, want %q", got, want)
	}
}

func TestJoinWithinRootRejectsEscape(t *testing.T) {
	if _, err := JoinWithinRoot(t.TempDir(), "..", "outside"); err == nil {
		t.Fatal("JoinWithinRoot() accepted a path outside the root")
	}
}

func TestJoinWithinRootRejectsRoot(t *testing.T) {
	if _, err := JoinWithinRoot(t.TempDir(), "."); err == nil {
		t.Fatal("JoinWithinRoot() accepted the root itself")
	}
}
