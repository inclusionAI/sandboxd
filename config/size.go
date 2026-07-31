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

package config

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var memorySizePattern = regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?)\s*(B|KiB|MiB|GiB|TiB|KB|MB|GB|TB)$`)

// ParseMemorySize parses a byte count or a human-readable binary or decimal
// memory size. Empty and zero values disable the corresponding limit.
func ParseMemorySize(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return 0, nil
	}
	if size, err := strconv.ParseInt(value, 10, 64); err == nil {
		if size < 0 {
			return 0, fmt.Errorf("memory size must not be negative")
		}
		return size, nil
	}

	match := memorySizePattern.FindStringSubmatch(value)
	if match == nil {
		return 0, fmt.Errorf("unsupported format, use e.g. 512MiB, 2GiB, or plain bytes")
	}
	number, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, err
	}

	var multiplier float64
	switch strings.ToUpper(match[2]) {
	case "B":
		multiplier = 1
	case "KIB":
		multiplier = 1024
	case "MIB":
		multiplier = 1024 * 1024
	case "GIB":
		multiplier = 1024 * 1024 * 1024
	case "TIB":
		multiplier = 1024 * 1024 * 1024 * 1024
	case "KB":
		multiplier = 1000
	case "MB":
		multiplier = 1000 * 1000
	case "GB":
		multiplier = 1000 * 1000 * 1000
	case "TB":
		multiplier = 1000 * 1000 * 1000 * 1000
	}
	size := number * multiplier
	if math.IsInf(size, 0) || size > math.MaxInt64 {
		return 0, fmt.Errorf("memory size overflows int64")
	}
	return int64(size), nil
}
