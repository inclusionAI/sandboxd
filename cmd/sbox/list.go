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
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var ListCmd = cli.Command{
	Name:      "list",
	ShortName: "ls",
	Usage:     "list sandboxes",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "label",
			Usage: "labels to list sandboxes, provide it by k=v or k= format, labels selector follow AND logic",
		},
	},
	Action: func(context *cli.Context) error {
		if context.NArg() != 0 {
			return fmt.Errorf("extra arguments: %v", context.Args())
		}

		// parse labels
		labels := make(map[string]string)
		if context.StringSlice("label") != nil {
			for _, label := range context.StringSlice("label") {
				if k, v, err := parseLabelStr(label); err != nil {
					logrus.Debugf("parse label string %s failed: %v", label, err)
					continue
				} else {
					labels[k] = v
				}
			}
		}

		client, err := NewSandboxClient(context)
		if err != nil {
			return err
		}

		resp, err := client.ListSandbox(labels, "")
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 12, 1, 3, ' ', 0)
		fmt.Fprint(w, "ID\tSTATUS\tRUNTIME\tAGE\tCREATED\n")
		type item struct {
			ID        string               `json:"id"`
			State     runtime.SandboxState `json:"state"`
			Runtime   string               `json:"runtime"`
			Age       string               `json:"age"`
			StartedAt string               `json:"started_at"`

			rawAge int64
		}
		items := make([]item, 0, len(resp.Sandboxes))
		for _, sb := range resp.Sandboxes {
			age, _ := util.FormatTimeInterval(sb.StartedAt, 0)
			items = append(items, item{
				ID:        sb.ID,
				State:     sb.State,
				Runtime:   sb.Runtime,
				Age:       age,
				StartedAt: util.FormatUnixTimestamp(sb.StartedAt),

				rawAge: sb.StartedAt,
			})
		}

		// sort by age
		sort.Slice(items, func(i, j int) bool {
			return items[i].rawAge > items[j].rawAge
		})

		for _, item := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t\n",
				item.ID,
				item.State,
				item.Runtime,
				item.Age,
				item.StartedAt)
		}
		if err := w.Flush(); err != nil {
			return err
		}
		return nil
	},
}

// parseLabelStr convert label string to key and value, for example:
// 1. k=v -> k, v
// 2. k= -> k, ""
// 3. other -> "", "", error
func parseLabelStr(kv string) (string, string, error) {
	kvs := strings.Split(kv, "=")
	if len(kvs) != 2 {
		return "", "", fmt.Errorf("invalid label string: %s", kv)
	}
	return kvs[0], kvs[1], nil
}
