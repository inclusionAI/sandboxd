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

package main

import (
	"runtime"
	"runtime/debug"
	"time"
)

func main() {
	// Give sandboxd time to install the memory.events watcher after runsc start.
	time.Sleep(2 * time.Second)
	debug.SetGCPercent(-1)

	allocations := make([][]byte, 0, 256)
	for {
		chunk := make([]byte, 4*1024*1024)
		for offset := 0; offset < len(chunk); offset += 4096 {
			chunk[offset] = 1
		}
		allocations = append(allocations, chunk)
		runtime.KeepAlive(allocations)
	}
}
