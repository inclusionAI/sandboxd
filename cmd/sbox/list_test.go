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
	"testing"
	"time"
)

func TestSandboxListTimes(t *testing.T) {
	for _, timestamp := range []int64{0, -1} {
		age, created := sandboxListTimes(timestamp)
		if age != "-" || created != "-" {
			t.Fatalf("unknown timestamp %d displayed as %q / %q", timestamp, age, created)
		}
	}
	started := time.Now().Add(-2 * time.Hour).Unix()
	age, created := sandboxListTimes(started)
	if age != "2 hours" || created != time.Unix(started, 0).Format(time.RFC3339) {
		t.Fatalf("incorrect list times: %q / %q", age, created)
	}
	future := time.Now().Add(time.Hour).Unix()
	age, created = sandboxListTimes(future)
	if age != "-" || created != time.Unix(future, 0).Format(time.RFC3339) {
		t.Fatalf("future timestamp displayed as %q / %q", age, created)
	}
}
