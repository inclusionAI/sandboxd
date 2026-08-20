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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEphemeralNetNSPath(t *testing.T) {
	path := ephemeralNetNSPath("sbox-example")
	assert.Equal(t, "/var/run/netns/runc-sbox-example", path)
	require.NoError(t, ValidateEphemeralNetNSPath(path))
}

func TestValidateEphemeralNetNSPathRejectsUnownedPath(t *testing.T) {
	for _, path := range []string{
		"/tmp/runc-sbox-example",
		"/var/run/netns/sbox-example",
		"/var/run/netns/runc-invalid",
		"/var/run/netns/runc-sbox-../escape",
	} {
		t.Run(path, func(t *testing.T) {
			assert.Error(t, ValidateEphemeralNetNSPath(path))
		})
	}
}
