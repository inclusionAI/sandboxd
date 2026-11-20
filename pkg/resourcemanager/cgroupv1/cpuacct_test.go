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
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/uuid"
)

func TestReadCpuacctSimple(t *testing.T) {
	acct, err := ReadCPUAcctWithoutPercpu("testdata", time.Now())
	assert.NoError(t, err)
	assert.Equal(t, int64(123456), acct.Usage)

	_, err = ReadCPUAcctWithoutPercpu("xxxx", time.Now())
	assert.Error(t, err)
}

func TestSubUpperZero(t *testing.T) {
	testCases := []struct {
		oldUtilPercpu    *UtilPercpu
		newUtilPercpu    *UtilPercpu
		expectUtilPercpu *UtilPercpu
	}{
		{
			// case1: nil
			oldUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0, 4.0},
			},
			newUtilPercpu: nil,
			expectUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0, 4.0},
			},
		},
		{
			// case2: length not equal
			oldUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0, 4.0},
			},
			newUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0},
			},
			expectUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0, 4.0},
			},
		},
		{
			// case3: normal case
			oldUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0, 4.0},
			},
			newUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 1.0, 1.0, 1.0},
			},
			expectUtilPercpu: &UtilPercpu{
				Utils: []float64{0.0, 1.0, 2.0, 3.0},
			},
		},
		{
			// case4: normal case
			oldUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0, 4.0},
			},
			newUtilPercpu: &UtilPercpu{
				Utils: []float64{2.0, 3.0, 4.0, 5.0},
			},
			expectUtilPercpu: &UtilPercpu{
				Utils: []float64{0.0, 0.0, 0.0, 0.0},
			},
		},
	}

	for _, testCase := range testCases {
		testCase.oldUtilPercpu.SubUppperZero(testCase.newUtilPercpu)
		assert.Equal(t, testCase.expectUtilPercpu, testCase.oldUtilPercpu)
	}
}

func TestDeepCopy(t *testing.T) {
	testCases := []struct {
		oldUtilPercpu    *UtilPercpu
		expectUtilPercpu *UtilPercpu
	}{
		{
			oldUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0, 4.0},
			},
			expectUtilPercpu: &UtilPercpu{
				Utils: []float64{1.0, 2.0, 3.0, 4.0},
			},
		},
		{
			oldUtilPercpu: &UtilPercpu{
				Utils: []float64{},
			},
			expectUtilPercpu: &UtilPercpu{
				Utils: []float64{},
			},
		},
	}

	for _, testCase := range testCases {
		res := testCase.oldUtilPercpu.DeepCopy()
		assert.Equal(t, testCase.expectUtilPercpu, res)
	}
}

func TestReadCPUAcct(t *testing.T) {
	// prepare test file
	// case1: normal case
	basePath := "/tmp"
	id := string(uuid.NewUUID())
	testNormalDirName := fmt.Sprintf("huselet_test_readcpuacct_dir_%v", id)
	testNormalCgroupPath := path.Join(basePath, testNormalDirName)
	err := os.Mkdir(testNormalCgroupPath, os.ModePerm)
	assert.Nil(t, err)
	testNormalFileContent := "10 10 10 10 \n"
	err = writeFile(path.Join(basePath, testNormalDirName, UsagePercpuFile), testNormalFileContent)
	assert.Nil(t, err)
	testNormalFileContent = "10\n"
	err = writeFile(path.Join(basePath, testNormalDirName, UsageFile), testNormalFileContent)
	assert.Nil(t, err)

	// case2: file not exist
	id = string(uuid.NewUUID())
	testNotExistDirName := fmt.Sprintf("huselet_test_readcpuacct_dir_%v", id)
	testNotExistCgroupPath := path.Join(basePath, testNotExistDirName)
	err = os.Mkdir(path.Join(basePath, testNotExistDirName), os.ModePerm)
	assert.Nil(t, err)
	// case3: strconv error
	id = string(uuid.NewUUID())
	testErrorDirName := fmt.Sprintf("huselet_test_readcpuacct_dir_%v", id)
	testErrorCgroupPath := path.Join(basePath, testErrorDirName)
	err = os.Mkdir(path.Join(basePath, testErrorDirName), os.ModePerm)
	assert.Nil(t, err)
	testErrorFileContent := "10 10 10 error"
	err = writeFile(path.Join(basePath, testErrorDirName, UsagePercpuFile), testErrorFileContent)
	assert.Nil(t, err)

	testCases := []struct {
		cgroupPath string
		expectRes  *CPUAcct
		expectErr  bool
	}{
		{
			// case1: normal case
			cgroupPath: testNormalCgroupPath,
			expectRes: &CPUAcct{
				UsagePercpu: &UsagePercpu{
					Usages: []int64{10, 10, 10, 10},
				},
				Usage: 10,
			},
			expectErr: false,
		},
		{
			// case2: file not exist
			cgroupPath: testNotExistCgroupPath,
			expectRes:  &CPUAcct{},
			expectErr:  true,
		},
		{
			// case3: strconv error
			cgroupPath: testErrorCgroupPath,
			expectRes:  &CPUAcct{},
			expectErr:  true,
		},
	}

	for _, testCase := range testCases {
		// TODO: update timestamp
		cpuAcct, err := ReadCPUAcct(testCase.cgroupPath, time.Now())
		assert.Equal(t, testCase.expectRes.UsagePercpu, cpuAcct.UsagePercpu)
		if testCase.expectErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestReadUsagePercpu(t *testing.T) {
	// prepare test file
	cgroupPath := "/tmp"
	// case1: normal case
	id := string(uuid.NewUUID())
	testNormalFileName := fmt.Sprintf("huselet_test_readusagepercpu_file_%v", id)
	testNormalFileContent := "10 10 10 10 \n"
	err := writeFile(path.Join(cgroupPath, testNormalFileName), testNormalFileContent)
	assert.Nil(t, err)
	// case2: file not exist
	id = string(uuid.NewUUID())
	testNotExistFileName := fmt.Sprintf("huselet_test_readusagepercpu_file_%v", id)
	// case3: strconv error
	id = string(uuid.NewUUID())
	testErrorFileName := fmt.Sprintf("huselet_test_readusagepercpu_file_%v", id)
	testErrorFileContent := "10 10 10 error"
	err = writeFile(path.Join(cgroupPath, testErrorFileName), testErrorFileContent)
	assert.Nil(t, err)

	testCases := []struct {
		cgroupPath string
		fileName   string
		expectRes  *UsagePercpu
		expectErr  bool
	}{
		{
			// case1: normal case
			cgroupPath: cgroupPath,
			fileName:   testNormalFileName,
			expectRes: &UsagePercpu{
				Usages: []int64{
					10, 10, 10, 10,
				},
			},
			expectErr: false,
		},
		{
			// case2: file not exist
			cgroupPath: cgroupPath,
			fileName:   testNotExistFileName,
			expectRes: &UsagePercpu{
				Usages: []int64{},
			},
			expectErr: true,
		},
		{
			// case3: strconv error
			cgroupPath: cgroupPath,
			fileName:   testErrorFileName,
			expectRes: &UsagePercpu{
				Usages: []int64{
					10, 10, 10,
				},
			},
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		usagePercpu, err := ReadUsagePercpu(testCase.cgroupPath, testCase.fileName)
		assert.Equal(t, testCase.expectRes, usagePercpu)
		if testCase.expectErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestReadUsage(t *testing.T) {
	// prepare test file
	cgroupPath := "/tmp"
	// case1: normal case
	id := string(uuid.NewUUID())
	testNormalFileName := fmt.Sprintf("huselet_test_readusage_file_%v", id)
	testNormalFileContent := "10\n"
	err := writeFile(path.Join(cgroupPath, testNormalFileName), testNormalFileContent)
	assert.Nil(t, err)
	// case2: file not exist
	id = string(uuid.NewUUID())
	testNotExistFileName := fmt.Sprintf("huselet_test_readusage_file_%v", id)
	// case3: strconv error
	id = string(uuid.NewUUID())
	testErrorFileName := fmt.Sprintf("huselet_test_readusage_file_%v", id)
	testErrorFileContent := "error\n"
	err = writeFile(path.Join(cgroupPath, testErrorFileName), testErrorFileContent)
	assert.Nil(t, err)

	testCases := []struct {
		cgroupPath string
		fileName   string
		expectRes  int64
		expectErr  bool
	}{
		{
			// case1 normal case
			cgroupPath: cgroupPath,
			fileName:   testNormalFileName,
			expectRes:  int64(10),
			expectErr:  false,
		},
		{
			// case2
			cgroupPath: cgroupPath,
			fileName:   testNotExistFileName,
			expectRes:  0,
			expectErr:  true,
		},
		{
			// case3
			cgroupPath: cgroupPath,
			fileName:   testErrorFileName,
			expectRes:  0,
			expectErr:  true,
		},
	}

	for _, testCase := range testCases {
		usage, err := ReadUsage(testCase.cgroupPath, testCase.fileName)
		assert.Equal(t, testCase.expectRes, usage)
		if testCase.expectErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestCalUsagePercpuNano(t *testing.T) {
	testCases := []struct {
		oldCPUAcct *CPUAcct
		newCPUAcct *CPUAcct
		expectRes  *UsagePercpu
		expectErr  bool
	}{
		{
			// case1 normal case
			oldCPUAcct: &CPUAcct{
				UsagePercpu: &UsagePercpu{
					Usages: []int64{10, 10, 10, 10},
				},
			},
			newCPUAcct: &CPUAcct{
				UsagePercpu: &UsagePercpu{
					Usages: []int64{20, 20, 20, 20},
				},
			},
			expectRes: &UsagePercpu{
				Usages: []int64{10, 10, 10, 10},
			},
			expectErr: false,
		},
		{
			// case2 total CPU cores different
			oldCPUAcct: &CPUAcct{
				UsagePercpu: &UsagePercpu{
					Usages: []int64{10, 10, 10, 10},
				},
			},
			newCPUAcct: &CPUAcct{
				UsagePercpu: &UsagePercpu{
					Usages: []int64{20, 20, 20},
				},
			},
			expectRes: &UsagePercpu{
				Usages: []int64{},
			},
			expectErr: true,
		},
		{
			// case3 newAcct small than oldAcct
			oldCPUAcct: &CPUAcct{
				UsagePercpu: &UsagePercpu{
					Usages: []int64{10, 10, 10, 10},
				},
			},
			newCPUAcct: &CPUAcct{
				UsagePercpu: &UsagePercpu{
					Usages: []int64{0, 0, 0, 0},
				},
			},
			expectRes: &UsagePercpu{
				Usages: []int64{0, 0, 0, 0},
			},
			expectErr: false,
		},
	}

	for _, testCase := range testCases {
		usagePercpuNano, err := testCase.oldCPUAcct.CalUsagePercpuNano(testCase.newCPUAcct)
		assert.Equal(t, testCase.expectRes, usagePercpuNano)
		if testCase.expectErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestCalUtilPercpu(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(time.Second * time.Duration(1))

	testCases := []struct {
		oldCPUAcct *CPUAcct
		newCPUAcct *CPUAcct
		expectRes  *UtilPercpu
		expectErr  bool
	}{
		{
			// case1 normal case
			oldCPUAcct: &CPUAcct{
				RecordTime: startTime,
				UsagePercpu: &UsagePercpu{
					Usages: []int64{1000000000, 1000000000, 1000000000, 1000000000},
				},
			},
			newCPUAcct: &CPUAcct{
				RecordTime: endTime,
				UsagePercpu: &UsagePercpu{
					Usages: []int64{2000000000, 2000000000, 2000000000, 2000000000},
				},
			},
			expectRes: &UtilPercpu{
				Utils: []float64{1, 1, 1, 1},
			},
			expectErr: false,
		},
		{
			// case2 total CPU cores different
			oldCPUAcct: &CPUAcct{
				RecordTime: startTime,
				UsagePercpu: &UsagePercpu{
					Usages: []int64{1000000000, 1000000000, 1000000000, 1000000000},
				},
			},
			newCPUAcct: &CPUAcct{
				RecordTime: endTime,
				UsagePercpu: &UsagePercpu{
					Usages: []int64{2000000000, 2000000000, 2000000000},
				},
			},
			expectRes: &UtilPercpu{
				Utils: []float64{},
			},
			expectErr: true,
		},
		{
			// case3 newAcct small than oldAcct
			oldCPUAcct: &CPUAcct{
				RecordTime: startTime,
				UsagePercpu: &UsagePercpu{
					Usages: []int64{1000000000, 1000000000, 1000000000, 1000000000},
				},
			},
			newCPUAcct: &CPUAcct{
				RecordTime: endTime,
				UsagePercpu: &UsagePercpu{
					Usages: []int64{0, 0, 0, 0},
				},
			},
			expectRes: &UtilPercpu{
				Utils: []float64{0, 0, 0, 0},
			},
			expectErr: false,
		},
		{
			// case4 new timestamp befor old timestamp
			oldCPUAcct: &CPUAcct{
				RecordTime: endTime,
				UsagePercpu: &UsagePercpu{
					Usages: []int64{1000000000, 1000000000, 1000000000, 1000000000},
				},
			},
			newCPUAcct: &CPUAcct{
				RecordTime: startTime,
				UsagePercpu: &UsagePercpu{
					Usages: []int64{2000000000, 2000000000, 2000000000, 2000000000},
				},
			},
			expectRes: &UtilPercpu{
				Utils: []float64{},
			},
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		res, err := testCase.oldCPUAcct.CalUtilPercpu(testCase.newCPUAcct)
		assert.Equal(t, testCase.expectRes, res)
		if testCase.expectErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestCalUsageNano(t *testing.T) {
	testCases := []struct {
		oldCPUAcct *CPUAcct
		newCPUAcct *CPUAcct
		expectRes  int64
		expectErr  bool
	}{
		{
			// case1 normal case
			oldCPUAcct: &CPUAcct{
				Usage: 10,
			},
			newCPUAcct: &CPUAcct{
				Usage: 20,
			},
			expectRes: 10,
			expectErr: false,
		},
		{
			// case2 newAcct is nil
			oldCPUAcct: &CPUAcct{
				Usage: 10,
			},
			newCPUAcct: nil,
			expectRes:  0,
			expectErr:  true,
		},
		{
			// case3 newAcct small than oldAcct
			oldCPUAcct: &CPUAcct{
				Usage: 20,
			},
			newCPUAcct: &CPUAcct{
				Usage: 10,
			},
			expectRes: 0,
			expectErr: false,
		},
	}

	for _, testCase := range testCases {
		usagePercpuNano, err := testCase.oldCPUAcct.CalUsageNano(testCase.newCPUAcct)
		assert.Equal(t, testCase.expectRes, usagePercpuNano)
		if testCase.expectErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestCalUsage(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(time.Second * time.Duration(1))

	testCases := []struct {
		oldCPUAcct *CPUAcct
		newCPUAcct *CPUAcct
		expectRes  float64
		expectErr  bool
	}{
		{
			// case1 normal case
			oldCPUAcct: &CPUAcct{
				RecordTime: startTime,
				Usage:      1000000000,
			},
			newCPUAcct: &CPUAcct{
				RecordTime: endTime,
				Usage:      2000000000,
			},
			expectRes: 1.0,
			expectErr: false,
		},
		{
			// case2 new timestamp befor old timestamp
			oldCPUAcct: &CPUAcct{
				RecordTime: endTime,
				Usage:      1000000000,
			},
			newCPUAcct: &CPUAcct{
				RecordTime: startTime,
				Usage:      2000000000,
			},
			expectRes: 0.0,
			expectErr: true,
		},
		{
			// case3 nil cpu acct
			oldCPUAcct: &CPUAcct{
				RecordTime: endTime,
				Usage:      1000000000,
			},
			newCPUAcct: nil,
			expectRes:  0.0,
			expectErr:  true,
		},
	}

	for _, testCase := range testCases {
		res, err := testCase.oldCPUAcct.CalUsage(testCase.newCPUAcct)
		assert.Equal(t, testCase.expectRes, res)
		if testCase.expectErr {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}
