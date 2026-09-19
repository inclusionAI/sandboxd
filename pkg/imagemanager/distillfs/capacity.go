// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
)

var chunkDBSizePattern = regexp.MustCompile(`^([0-9]+)(B|KiB|MiB|GiB|TiB)?$`)

func normalizeChunkDBSize(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	match := chunkDBSizePattern.FindStringSubmatch(value)
	if match == nil {
		return "", fmt.Errorf("invalid chunk_db_size %q: use whole bytes or integer B/KiB/MiB/GiB/TiB", value)
	}
	n, err := strconv.ParseUint(match[1], 10, 64)
	multiplier := map[string]uint64{"": 1, "B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}[match[2]]
	maxSize := uint64(^uint(0) >> 1)
	if err != nil || n > maxSize/multiplier {
		return "", fmt.Errorf("chunk_db_size %q overflows addressable range", value)
	}
	n *= multiplier
	if n < 1<<20 || n%uint64(os.Getpagesize()) != 0 {
		return "", fmt.Errorf("chunk_db_size must be at least 1MiB and a multiple of %d bytes", os.Getpagesize())
	}
	return strconv.FormatUint(n, 10), nil
}

func chunkDBArgs(command, dir, size string) []string {
	args := []string{command, "--chunk-db-dir", dir}
	if size != "" {
		args = append(args, "--chunk-db-size", size)
	}
	return args
}
