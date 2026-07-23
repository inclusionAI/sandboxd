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
	"errors"
	"fmt"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var DeleteCmd = cli.Command{
	Name:  "delete",
	Usage: "force-delete a sandbox from the host",
	Action: func(context *cli.Context) error {
		if context.NArg() == 0 {
			return fmt.Errorf("no sandbox id specified")
		}

		client, err := NewSandboxClient(context)
		if err != nil {
			return err
		}

		for _, id := range context.Args() {
			if !config.IsValidSandboxID(id) {
				logrus.Warnf("sandbox id %q must use %s<suffix> as one path component; skipping", id, config.SandboxIDPrefix)
				continue
			}
			start := time.Now()
			if _, err := client.DeleteSandbox(&runtime.DeleteRequest{ID: id}); err != nil && !errors.Is(err, errord.ErrNotFound) {
				logrus.Warnf("delete sandbox %s failed: %v", id, err)
				continue
			}
			logrus.Infof("delete sandbox %s success, client cost: %v ms", id, time.Since(start).Milliseconds())
		}
		return nil
	},
}
