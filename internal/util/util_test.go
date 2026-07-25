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

package util

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	gomonkey "github.com/agiledragon/gomonkey/v2"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/cgroupops"
	cg "github.com/containerd/cgroups/v3/cgroup1"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
)

func TestMustInt64(t *testing.T) {
	type args struct {
		timestamp string
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{
			name: "RFC3339 format",
			args: args{
				timestamp: "2023-03-30T15:53:15.73829398+08:00",
			},
			want: 1680162795,
		},
		{
			name: "unix format",
			args: args{
				timestamp: "1680162795",
			},
			want: 1680162795,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MustInt64(tt.args.timestamp); got != tt.want {
				t.Errorf("MustInt64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnvValue(t *testing.T) {
	type args struct {
		envs []*runtime.KeyValue
		key  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty envs",
			args: args{
				envs: nil,
			},
			want: "",
		},
		{
			name: "empty key",
			args: args{
				envs: []*runtime.KeyValue{
					{
						Key:   "foo",
						Value: "bar",
					},
				},
				key: "",
			},
			want: "",
		},
		{
			name: "key found",
			args: args{
				envs: []*runtime.KeyValue{
					{
						Key:   "foo",
						Value: "bar",
					},
				},
				key: "foo",
			},
			want: "bar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, EnvValue(tt.args.envs, tt.args.key), "EnvValue(%v, %v)", tt.args.envs, tt.args.key)
		})
	}
}

func subystemsExecptMemory() ([]cg.Subsystem, error) {
	var enabled = []cg.Subsystem{
		cg.NewCpuset("/sys/fs/cgroup"),
	}

	return enabled, nil
}

func TestKillCgroupProcesses(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Requires root to create cgroups")
	}
	// OK case
	const cgroupPath = "test-kill-sandbox"
	cgroupHandler := &cgroupops.CgroupHandlerImpl{}
	cgroup, err := cgroupHandler.Create(cg.StaticPath(cgroupPath), &specs.LinuxResources{}, cg.WithHiearchy(cg.Default))
	assert.NoError(t, err)

	cmd := exec.Command("sleep", "666")
	err = cmd.Start()
	assert.NoError(t, err)

	err = cgroup.AddProc(uint64(cmd.Process.Pid))
	assert.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	err = KillCgroupProcesses(cgroupPath)
	assert.NoError(t, err)

	select {
	case <-time.After(1 * time.Second):
		assert.Fail(t, "timeout")
	case err := <-done:
		assert.ErrorContains(t, err, "signal: killed")
	}

	// Fail case 1
	// Use non-exist cgroup-path
	err = KillCgroupProcesses("/non-exist-test-cgroup-path")
	assert.ErrorContains(t, err, "getting cgroup failed")

	// Fail case 2
	// Use no memory subsystem cgroup
	const cgroupPathEmpty = "test-kill-sandbox-no-memory"
	_, err = cgroupHandler.Create(cg.StaticPath(cgroupPathEmpty), &specs.LinuxResources{}, cg.WithHiearchy(subystemsExecptMemory))
	assert.NoError(t, err)

	err = KillCgroupProcesses(cgroupPathEmpty)
	assert.ErrorContains(t, err, "getting processes failed")

}

// type fakeFileStat interface {
// 	Name() string       // base name of the file
// 	Size() int64        // length in bytes for regular files; system-dependent for others
// 	Mode() FileMode     // file mode bits
// 	ModTime() time.Time // modification time
// 	IsDir() bool        // abbreviation for Mode().IsDir()
// 	Sys() any           // underlying data source (can return nil)
// }

type fakeFileStat struct{}

func (fs *fakeFileStat) Name() string       { return "" }
func (fs *fakeFileStat) Size() int64        { return 0 }
func (fs *fakeFileStat) Mode() os.FileMode  { return 0 }
func (fs *fakeFileStat) IsDir() bool        { return false }
func (fs *fakeFileStat) ModTime() time.Time { return time.Now() }
func (fs *fakeFileStat) Sys() any           { return "wrong type" }

func TestIsMountpoint(t *testing.T) {
	// Mock error of "can't get info of target"
	m, err := IsMountpoint("/tmp/xxxx/never-exist-abcdddff")
	assert.ErrorContains(t, err, "can't get info of target dir")
	assert.False(t, m)

	// Mock error of "Get dev NO. of target"
	osStatPatches := gomonkey.ApplyFunc(os.Stat, func(string) (os.FileInfo, error) {
		return &fakeFileStat{}, nil
	})
	m, err = IsMountpoint("/tmp")
	osStatPatches.Reset()
	assert.ErrorContains(t, err, "can't get dev NO. of target dir")
	assert.False(t, m)

	// Mock error of "can't get info of parent dir"
	realStatResult, _ := os.Stat("/tmp")
	times := 0
	osStatPatches = gomonkey.ApplyFunc(os.Stat, func(name string) (os.FileInfo, error) {
		times++
		if times == 1 {
			return realStatResult, nil
		}
		return &fakeFileStat{}, errors.New("mock error")
	})
	m, err = IsMountpoint("/tmp")
	osStatPatches.Reset()
	assert.ErrorContains(t, err, "can't get info of parent dir")
	assert.False(t, m)

	// Mock error of "can't get dev NO. of parent dir"
	times = 0
	osStatPatches = gomonkey.ApplyFunc(os.Stat, func(name string) (os.FileInfo, error) {
		times++
		if times == 1 {
			return realStatResult, nil
		}
		return &fakeFileStat{}, nil
	})
	m, err = IsMountpoint("/tmp")
	osStatPatches.Reset()
	assert.ErrorContains(t, err, "can't get dev NO. of parent dir")
	assert.False(t, m)

	// Test mountpoint false
	m, err = IsMountpoint("/tmp")
	assert.NoError(t, err)
	assert.False(t, m)

	// Test mountpoint true
	realStatResult2, _ := os.Stat("/tmp")
	stat, ok := realStatResult2.Sys().(*syscall.Stat_t)
	if !ok {
		assert.Fail(t, "can't get stat for mock data")
	}
	stat.Dev = 996

	times = 0
	osStatPatches = gomonkey.ApplyFunc(os.Stat, func(name string) (os.FileInfo, error) {
		times++
		if times == 1 {
			return realStatResult, nil
		}
		return realStatResult2, nil
	})
	m, err = IsMountpoint("/tmp")
	osStatPatches.Reset()

	assert.NoError(t, err)
	assert.True(t, m)

}
