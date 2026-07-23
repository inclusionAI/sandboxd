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
	"fmt"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/urfave/cli"
)

var StatsCmd = cli.Command{
	Name:  "stats",
	Usage: "display resource usage statistics of a sandbox",
	Action: func(context *cli.Context) error {
		if context.NArg() != 1 {
			return fmt.Errorf("exactly one sandbox id must be specified")
		}

		id := context.Args()[0]
		client, err := NewSandboxClient(context)
		if err != nil {
			return err
		}

		resp, err := client.Stats(&runtime.StatsRequest{ID: id})
		if err != nil {
			return fmt.Errorf("stats failed: %v", err)
		}

		fmt.Printf("Sandbox: %s\n", id)
		fmt.Printf("CPU Usage:     %d ns (%.2f s)\n", resp.CpuUsageNs, float64(resp.CpuUsageNs)/1e9)
		fmt.Printf("  Kernel:      %d ns\n", resp.CpuKernelNs)
		fmt.Printf("  User:        %d ns\n", resp.CpuUserNs)
		fmt.Printf("Memory Usage:  %d bytes (%.1f MB)\n", resp.MemoryUsageBytes, float64(resp.MemoryUsageBytes)/1024/1024)
		fmt.Printf("Memory Limit:  %d bytes (%.1f MB)\n", resp.MemoryLimitBytes, float64(resp.MemoryLimitBytes)/1024/1024)
		fmt.Printf("Memory Max:    %d bytes (%.1f MB)\n", resp.MemoryMaxUsageBytes, float64(resp.MemoryMaxUsageBytes)/1024/1024)

		return nil
	},
}
