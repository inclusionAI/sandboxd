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

package cgroupv1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadCfsInfo(t *testing.T) {
	cfsInfo, err := ReadCfsInfo("", "testdata")
	assert.NoError(t, err)
	assert.Equal(t, int64(1024), cfsInfo.Shares)
	assert.Equal(t, int64(100000), cfsInfo.Period)
	assert.Equal(t, int64(100000), cfsInfo.Quota)

	_, err = ReadCfsInfo("", "xxx")
	assert.Error(t, err)

	_, err = ReadCfsInfo("testdata", "a")
	assert.Error(t, err)

	_, err = ReadCfsInfo("testdata", "b")
	assert.Error(t, err)
}
