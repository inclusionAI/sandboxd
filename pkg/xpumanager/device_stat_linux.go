//go:build linux

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

package xpumanager

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func statCharacterDevice(path string) (string, int64, int64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return "", 0, 0, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR {
		return "", 0, 0, fmt.Errorf("%s is not a character device", path)
	}
	return "c", int64(unix.Major(uint64(stat.Rdev))), int64(unix.Minor(uint64(stat.Rdev))), nil
}
