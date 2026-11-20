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

package sysutils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var kmemUnReclaimableFields = map[string]struct{}{
	"nr_slab_unreclaimable": {},
	"nr_kernel_stack":       {},
	"nr_page_table_pages":   {},
}

type MemInfo struct {
	Total               uint64
	UnReclaimableKernel uint64
}

func GetMemInfoFromZoneInfo(zoneInfoPath string) (*MemInfo, error) {
	f, err := os.Open(zoneInfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zoneinfo %s: %w", zoneInfoPath, err)
	}
	defer f.Close()

	pageSize := os.Getpagesize()
	mi := &MemInfo{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		valStr := fields[1]
		val, errParse := strconv.ParseUint(valStr, 10, 64)
		if errParse != nil {
			continue
		}
		if name == "managed" {
			mi.Total += val * uint64(pageSize)
		}
		_, ok := kmemUnReclaimableFields[name]
		if ok {
			mi.UnReclaimableKernel += val * uint64(pageSize)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read line err: %w", err)
	}
	return mi, nil
}
