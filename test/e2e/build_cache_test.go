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

package e2e

import (
	"os"
	"strings"
	"testing"
)

func TestRuntimeBuildCacheEnvironment(t *testing.T) {
	for _, filename := range []string{"build-binaries.sh", "runtime-suite.sh"} {
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		source := string(data)
		start := strings.Index(source, "\nGOCACHE=\"")
		if start < 0 {
			t.Fatalf("%s has no cache initialization", filename)
		}
		block := source[start+1:]
		marker := "export GOCACHE GOMODCACHE\n"
		end := strings.Index(block, marker)
		if end < 0 {
			t.Fatalf("%s does not export its cache environment", filename)
		}
		block = block[:end+len(marker)]
		for _, tc := range []struct {
			name, setup, want string
		}{
			{"defaults", "unset GOCACHE GOMODCACHE\n", "/tmp/go-build\n/tmp/go-mod-official\n"},
			{"persistent", "GOCACHE='/data/cache/go build'\nGOMODCACHE=/data/cache/go-mod\n", "/data/cache/go build\n/data/cache/go-mod\n"},
		} {
			t.Run(filename+"/"+tc.name, func(t *testing.T) {
				// Execute only the declaration block; never compile or run E2E.
				script := tc.setup + block + "bash -c 'printf \"%s\\n%s\\n\" \"$GOCACHE\" \"$GOMODCACHE\"'\n"
				output, err := runE2EHelper(t, script)
				if err != nil || output != tc.want {
					t.Fatalf("cache environment: err=%v, got=%q, want=%q", err, output, tc.want)
				}
			})
		}
	}
}
