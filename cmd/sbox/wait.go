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
	"github.com/inclusionAI/sandboxd/config"
	"github.com/urfave/cli"
)

var WaitCmd = cli.Command{
	Name:  "wait",
	Usage: "wait for a sandbox to exit",
	Action: func(context *cli.Context) error {
		if context.NArg() != 1 {
			return fmt.Errorf("exactly one sandbox id must be specified")
		}
		id := context.Args().First()
		if !config.IsValidSandboxID(id) {
			return fmt.Errorf("invalid sandbox id %q", id)
		}
		client, err := NewSandboxClient(context)
		if err != nil {
			return err
		}
		defer client.Close()
		request := &runtime.WaitRequest{ID: id}
		var resp *runtime.WaitResponse
		if context.GlobalIsSet("timeout") {
			resp, err = client.WaitSandboxWithTimeout(request)
		} else {
			resp, err = client.WaitSandbox(request)
		}
		if err != nil {
			return err
		}
		fmt.Printf("Exit Code: %d\n", resp.ExitCode)
		if resp.Message != "" {
			fmt.Printf("Message: %s\n", resp.Message)
		}
		return nil
	},
}
