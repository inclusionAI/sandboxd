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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/cgroupops"
	cg "github.com/containerd/cgroups/v3/cgroup1"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	Second = time.Second
	Minute = Second * 60
	Hour   = Minute * 60
	Day    = Hour * 24
	Week   = Day * 7
	Month  = Day * 30
	Year   = Day * 365

	TimeLayout = time.RFC3339Nano

	// RFC3339NanoFixed is our own version of RFC339Nano because we want one
	// that pads the nanoseconds part with zeros to ensure
	// the timestamps are aligned in the logs.
	RFC3339NanoFixed = "2006-01-02T15:04:05.000000000Z07:00"
)

var errInvalid = errors.New("invalid time")

// MustInt64 convert unix timestamp string to int64, if failed return 0
func MustInt64(timestamp string) int64 {
	// try parse time
	if rt, err := time.Parse(time.RFC3339, timestamp); err == nil {
		return rt.Unix()
	}

	t, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return 0
	}
	return int64(t)
}

func FormatUnixTimestamp(timestamp int64) string {
	return time.Unix(timestamp, 0).Format(time.RFC3339)
}

// FormatTimeInterval is used to show the time interval from input time to now.
func FormatTimeInterval(sec, nano int64) (formattedTime string, err error) {
	start := time.Unix(sec, nano)
	diff := time.Since(start)

	// That should not happen.
	if diff < 0 {
		return "", errInvalid
	}

	timeThresholds := []time.Duration{Year, Month, Week, Day, Hour, Minute, Second}
	timeNames := []string{"year", "month", "week", "day", "hour", "minute", "second"}

	for i, threshold := range timeThresholds {
		if diff >= threshold {
			count := int(diff / threshold)
			formattedTime += strconv.Itoa(count) + " " + timeNames[i]
			if count > 1 {
				formattedTime += "s"
			}
			break
		}
	}

	if diff < Second {
		formattedTime += "0 second"
	}

	return formattedTime, nil
}

func MountToApi(m []spec.Mount) []*runtime.Mount {
	var mounts []*runtime.Mount
	for _, mount := range m {
		mounts = append(mounts, &runtime.Mount{
			Source:  &runtime.Mount_HostPath{HostPath: mount.Source},
			Target:  mount.Destination,
			Type:    mount.Type,
			Options: mount.Options,
		})
	}
	return mounts
}

func EnvValue(envs []*runtime.KeyValue, key string) string {
	for _, env := range envs {
		if env.Key == key {
			return env.Value
		}
	}
	return ""
}

func KillCgroupProcesses(cgroupPath string) error {
	// Kill all processes still attached to the sandbox cgroup.
	cgroupHandler := &cgroupops.CgroupHandlerImpl{}
	cgroup, err := cgroupHandler.Load(cg.StaticPath(cgroupPath), cg.WithHiearchy(cg.Default))
	if err != nil {
		return fmt.Errorf("getting cgroup failed: %v", err)
	}

	processes, err := cgroup.Processes(cg.Memory, true)
	if err != nil {
		return fmt.Errorf("getting processes failed: %v", err)
	}

	for _, process := range processes {
		// Kill process with SIGKILL never failed
		_ = syscall.Kill(process.Pid, syscall.SIGKILL)
	}

	return nil
}

func IsMountpoint(target string) (bool, error) {
	// Get info of target dir
	fileInfo, err := os.Stat(target)
	if err != nil {
		return false, fmt.Errorf("can't get info of target dir: %v", err)
	}

	// Get dev NO. of target
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("can't get dev NO. of target dir")
	}
	targetDev := stat.Dev

	// Get info of parent dir
	parentPath := filepath.Dir(target)
	parentInfo, err := os.Stat(parentPath)
	if err != nil {
		return false, errors.New("can't get info of parent dir")
	}

	// Get dev No. of parent dir
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("can't get dev NO. of parent dir")
	}
	parentDev := parentStat.Dev

	// Compare dev Numbers of target dir and it's parent dir
	if targetDev != parentDev {
		return true, nil
	} else {
		return false, nil
	}
}
