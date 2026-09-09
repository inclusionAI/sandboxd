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
	"testing"

	"github.com/inclusionAI/sandboxd/config"
)

func TestWritableIODefaultsAndOverrides(t *testing.T) {
	value := config.FirecrackerConfig{}
	applyFirecrackerDefaults(&value)
	if value.WritableIOEngine != "AsyncDirect" || value.WritableCacheType != "Writeback" {
		t.Fatalf("unexpected writable disk defaults: %+v", value)
	}
	for _, engine := range []string{"Sync", "Async", "SyncDirect", "AsyncDirect"} {
		for _, cache := range []string{"Unsafe", "Writeback"} {
			t.Run(engine+"/"+cache, func(t *testing.T) {
				value := config.FirecrackerConfig{WritableIOEngine: engine, WritableCacheType: cache}
				applyFirecrackerDefaults(&value)
				if value.WritableIOEngine != engine || value.WritableCacheType != cache {
					t.Fatalf("explicit writable policy overwritten: %+v", value)
				}
				if err := validateFirecrackerWritablePolicy(value); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestWritableIORejectsUnknownPolicy(t *testing.T) {
	for _, value := range []config.FirecrackerConfig{
		{WritableIOEngine: "Direct", WritableCacheType: "Writeback"},
		{WritableIOEngine: "async", WritableCacheType: "Writeback"},
		{WritableIOEngine: "AsyncDirect", WritableCacheType: "writeback"},
	} {
		applyFirecrackerDefaults(&value)
		if err := validateFirecrackerWritablePolicy(value); err == nil {
			t.Fatalf("accepted invalid writable policy: %+v", value)
		}
	}
}
