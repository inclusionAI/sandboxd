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

package imagemanager

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseOCIZeroRefTTL(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    time.Duration
		wantErr bool
	}{
		{value: "", want: 30 * time.Minute},
		{value: "0s", want: 0},
		{value: "2h", want: 2 * time.Hour},
		{value: "2m30s", want: 150 * time.Second},
		{value: "-1s", wantErr: true},
		{value: "invalid", wantErr: true},
		{value: "999999999999h", wantErr: true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, err := parseOCIZeroRefTTL(tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid TTL was accepted")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("TTL = %s, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestNewModuleRejectsInvalidOCITTLBeforeStartingManagers(t *testing.T) {
	root := t.TempDir()
	_, err := NewModule(Config{Root: root, OCIZeroRefTTL: "-1s"})
	if err == nil || !strings.Contains(err.Error(), "oci_zero_ref_ttl") {
		t.Fatalf("expected OCI TTL validation error, got %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid config must fail before creating manager state: %v, %v", entries, err)
	}
}
