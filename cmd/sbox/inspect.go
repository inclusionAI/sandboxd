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
	"encoding/json"
	"fmt"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var InspectCmd = cli.Command{
	Name:  "inspect",
	Usage: "check sandbox status and detail",
	Action: func(context *cli.Context) error {
		if context.NArg() != 1 {
			return fmt.Errorf("only one sandbox id should be specified")
		}

		id := context.Args()[0]
		if !config.IsValidSandboxID(id) {
			logrus.Warnf("sandbox id %s is not valid, should start with %s and include a suffix, skip it", id, config.SandboxIDPrefix)
			return nil
		}

		client, err := NewSandboxClient(context)
		if err != nil {
			return err
		}

		resp, err := client.ListSandbox(nil, id)
		if err != nil {
			return err
		}

		if len(resp.Sandboxes) == 0 {
			logrus.Warnf("sandbox %s not found", id)
			return nil
		}

		sb := resp.Sandboxes[0]

		formattedData, err := json.MarshalIndent(sb, "", " ")
		if err != nil {
			return fmt.Errorf("marshal sandbox info %+v failed: %v", sb, err)
		}
		// print sandbox info in json
		fmt.Println(string(formattedData))

		return nil
	},
}
