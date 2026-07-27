// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networkmanager

import (
	"fmt"
	"os"
	"testing"

	"github.com/containerd/cgroups/v3"
	"github.com/stretchr/testify/require"
)

func TestDetectLocalCpuNumV2Quota(t *testing.T) {
	count, err := detectLocalCpuNum(cgroups.Unified, mapReader(map[string]string{
		v2CPUMaxPath: "150000 100000\n",
	}))
	require.NoError(t, err)
	require.Equal(t, 2, count)
}

func TestDetectLocalCpuNumV2Unlimited(t *testing.T) {
	count, err := detectLocalCpuNum(cgroups.Unified, mapReader(map[string]string{
		v2CPUMaxPath:    "max 100000\n",
		v2CPUSetEffPath: "0-3,6,8-9\n",
	}))
	require.NoError(t, err)
	require.Equal(t, 7, count)
}

func TestDetectLocalCpuNumV2RootWithoutCPUMax(t *testing.T) {
	count, err := detectLocalCpuNum(cgroups.Unified, func(path string) ([]byte, error) {
		switch path {
		case v2CPUMaxPath:
			return nil, os.ErrNotExist
		case v2CPUSetEffPath:
			return []byte("0-3\n"), nil
		default:
			return nil, fmt.Errorf("%s not found", path)
		}
	})
	require.NoError(t, err)
	require.Equal(t, 4, count)
}

func TestDetectLocalCpuNumV1Unlimited(t *testing.T) {
	count, err := detectLocalCpuNum(cgroups.Legacy, mapReader(map[string]string{
		v1CPUQuotaPath:  "-1\n",
		v1CPUPeriodPath: "100000\n",
		v1CPUSetPath:    "0-7\n",
	}))
	require.NoError(t, err)
	require.Equal(t, 8, count)
}

func TestDetectLocalCpuNumRejectsMalformedV2Max(t *testing.T) {
	_, err := detectLocalCpuNum(cgroups.Unified, mapReader(map[string]string{
		v2CPUMaxPath: "broken\n",
	}))
	require.ErrorContains(t, err, "invalid")
}

func TestParseCPUSetRejectsInvalidRange(t *testing.T) {
	_, err := parseCPUSet("3-1")
	require.ErrorContains(t, err, "descending")
}

func mapReader(files map[string]string) readFileFunc {
	return func(path string) ([]byte, error) {
		value, ok := files[path]
		if !ok {
			return nil, fmt.Errorf("%s not found", path)
		}
		return []byte(value), nil
	}
}
