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

package main

import (
	"flag"
	"os"
	"runtime"
	"time"
)

func main() {
	waitFile := flag.String("wait-file", "", "wait for this file before allocating")
	flag.Parse()

	for *waitFile != "" {
		if _, err := os.Stat(*waitFile); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	const chunkSize = 1 << 20
	chunks := make([][]byte, 0, 1024)
	for {
		chunk := make([]byte, chunkSize)
		for page := 0; page < len(chunk); page += os.Getpagesize() {
			chunk[page] = 1
		}
		chunks = append(chunks, chunk)
		runtime.KeepAlive(chunks)
	}
}
