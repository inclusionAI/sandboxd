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

import (
	"testing"

	"github.com/pelletier/go-toml"
)

func TestOCIZeroRefTTLTOML(t *testing.T) {
	for _, value := range []string{"", "0s", "2h"} {
		t.Run(value, func(t *testing.T) {
			cfg := DefaultConfig()
			input := "[plugin.image]\n"
			if value != "" {
				input += "oci_zero_ref_ttl = \"" + value + "\"\n"
			}
			if err := toml.Unmarshal([]byte(input), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.OCIZeroRefTTL != value {
				t.Fatalf("OCI zero-reference TTL = %q, want %q", cfg.OCIZeroRefTTL, value)
			}
		})
	}
}
