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

package networkmanager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetLocalCPUCountV2(t *testing.T) {
	tests := []struct {
		name   string
		cpuMax string
		cpuset string
		want   int
	}{
		{name: "unlimited uses effective cpuset", cpuMax: "max 100000\n", cpuset: "0-3,6\n", want: 5},
		{name: "fractional quota rounds up", cpuMax: "50000 100000\n", cpuset: "0-7\n", want: 1},
		{name: "cpuset caps quota", cpuMax: "400000 100000\n", cpuset: "0-1\n", want: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			group := t.TempDir()
			if err := os.WriteFile(filepath.Join(group, "cpu.max"), []byte(test.cpuMax), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(group, "cpuset.cpus.effective"), []byte(test.cpuset), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := getLocalCPUCountV2(group)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("CPU count = %d, want %d", got, test.want)
			}
		})
	}
}
