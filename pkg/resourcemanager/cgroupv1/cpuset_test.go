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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadCpuset(t *testing.T) {
	os.WriteFile("testdata/cpuset.cpus", []byte(""), 0644)
	ci, err := ReadCpuset("", "testdata")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(ci.Cpus))

	os.WriteFile("testdata/cpuset.cpus", []byte("11"), 0644)
	ci, err = ReadCpuset("", "testdata")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(ci.Cpus))
	assert.True(t, ci.HasCpu(11))
	assert.False(t, ci.HasCpu(12))

	os.WriteFile("testdata/cpuset.cpus", []byte("0-7,12-13"), 0644)
	ci, err = ReadCpuset("", "testdata")
	assert.NoError(t, err)
	assert.Equal(t, 10, len(ci.Cpus))
	assert.True(t, ci.HasCpu(0))
	assert.True(t, ci.HasCpu(7))
	assert.True(t, ci.HasCpu(12))
	assert.True(t, ci.HasCpu(13))
	assert.True(t, ci.HasCpu(4))
	assert.False(t, ci.HasCpu(8))
	assert.False(t, ci.HasCpu(14))
	assert.False(t, ci.HasCpu(11))
}

func TestReadCpusetFailedCase(t *testing.T) {
	_, err := ReadCpuset("", "xxx")
	assert.Error(t, err)
	os.WriteFile("testdata/cpuset.cpus", []byte("1-"), 0644)
	_, err = ReadCpuset("", "testdata")
	assert.Error(t, err)

	os.WriteFile("testdata/cpuset.cpus", []byte("c-10"), 0644)
	_, err = ReadCpuset("", "testdata")
	assert.Error(t, err)

	os.WriteFile("testdata/cpuset.cpus", []byte("1-c"), 0644)
	_, err = ReadCpuset("", "testdata")
	assert.Error(t, err)

	os.WriteFile("testdata/cpuset.cpus", []byte("12-11"), 0644)
	_, err = ReadCpuset("", "testdata")
	assert.Error(t, err)

	os.WriteFile("testdata/cpuset.cpus", []byte("abc"), 0644)
	_, err = ReadCpuset("", "testdata")
	assert.Error(t, err)
}
