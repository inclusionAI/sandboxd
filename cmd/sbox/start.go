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
	"strings"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/urfave/cli"
)

var StartCmd = cli.Command{
	Name:      "start",
	Usage:     "start a sandbox",
	ArgsUsage: "[command] [args...]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "runtime",
			Usage: "sandbox runtime handler name",
			Value: config.RuntimeNameRunsc,
		},
		cli.StringFlag{
			Name:  "sandbox-id",
			Usage: "optional sandbox id; sandboxd generates one when empty",
		},
		cli.StringFlag{
			Name:  "rootfs",
			Usage: "local rootfs path",
		},
		cli.BoolFlag{
			Name:  "rootfs-readonly",
			Usage: "mark rootfs readonly in the Start request",
		},
		cli.StringFlag{
			Name:  "cwd",
			Usage: "working directory inside the sandbox",
			Value: "/",
		},
		cli.StringSliceFlag{
			Name:  "env,e",
			Usage: "environment variable, formatted as key=value",
		},
		cli.StringSliceFlag{
			Name:  "mount",
			Usage: "bind mount, formatted as host_path:target[:type[:opt1,opt2]]",
		},
		cli.StringFlag{
			Name:  "stdout",
			Usage: "stdout log path",
		},
		cli.StringFlag{
			Name:  "stderr",
			Usage: "stderr log path",
		},
		cli.Float64Flag{
			Name:  "cpu-millicores",
			Usage: "CPU request in millicores",
		},
		cli.Float64Flag{
			Name:  "memory-mb",
			Usage: "memory limit in MB",
		},
		cli.StringSliceFlag{
			Name:  "port",
			Usage: "DNAT rule, formatted as protocol:dstPort:targetPort",
		},
		cli.BoolFlag{
			Name:  "quiet,q",
			Usage: "print only the sandbox id",
		},
	},
	Action: func(context *cli.Context) error {
		if context.String("rootfs") == "" {
			return fmt.Errorf("--rootfs is required")
		}
		requestedID := context.String("sandbox-id")
		if requestedID != "" && !config.IsValidSandboxID(requestedID) {
			return fmt.Errorf(
				"sandbox id %q must use %s<suffix> as one path component",
				requestedID, config.SandboxIDPrefix,
			)
		}

		command := context.Args()
		if len(command) == 0 {
			command = []string{"/bin/sleep", "3600"}
		}

		envs, err := parseEnvFlags(context.StringSlice("env"))
		if err != nil {
			return err
		}
		mounts, err := parseMountFlags(context.StringSlice("mount"))
		if err != nil {
			return err
		}

		resources := make(map[string]float64)
		if cpu := context.Float64("cpu-millicores"); cpu > 0 {
			resources["CPU"] = cpu
		}
		if memory := context.Float64("memory-mb"); memory > 0 {
			resources["Memory"] = memory
		}

		client, err := NewSandboxClient(context)
		if err != nil {
			return err
		}
		defer client.Close()

		resp, err := client.StartSandbox(&runtime.StartRequest{
			SandboxID: requestedID,
			Runtime:   context.String("runtime"),
			Rootfs: &runtime.RootfsConfig{
				Readonly: context.Bool("rootfs-readonly"),
				Type:     runtime.RootfsSrcType_LOCAL,
				Source: &runtime.RootfsConfig_Path{
					Path: context.String("rootfs"),
				},
			},
			Command:   command,
			Cwd:       context.String("cwd"),
			Envs:      envs,
			Mounts:    mounts,
			Resources: resources,
			Stdout:    context.String("stdout"),
			Stderr:    context.String("stderr"),
			Network:   "sandbox",
			Ports:     context.StringSlice("port"),
		})
		if err != nil {
			return err
		}
		if resp.Code != 0 {
			return fmt.Errorf("start failed: code=%d message=%s", resp.Code, resp.Message)
		}

		if context.Bool("quiet") {
			fmt.Println(resp.ID)
			return nil
		}
		fmt.Printf("Started sandbox %s\n", resp.ID)
		return nil
	},
}

func parseEnvFlags(flags []string) (map[string]string, error) {
	envs := make(map[string]string, len(flags))
	for _, flag := range flags {
		key, value, ok := strings.Cut(flag, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid env %q, expected key=value", flag)
		}
		envs[key] = value
	}
	return envs, nil
}

func parseMountFlags(flags []string) ([]*runtime.Mount, error) {
	mounts := make([]*runtime.Mount, 0, len(flags))
	for _, flag := range flags {
		parts := strings.SplitN(flag, ":", 4)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid mount %q, expected host_path:target[:type[:opt1,opt2]]", flag)
		}
		mountType := "bind"
		if len(parts) >= 3 && parts[2] != "" {
			mountType = parts[2]
		}
		options := []string{"rbind", "rw"}
		if len(parts) == 4 && parts[3] != "" {
			options = strings.Split(parts[3], ",")
		}
		mounts = append(mounts, &runtime.Mount{
			Type:    mountType,
			Target:  parts[1],
			Options: options,
			Source: &runtime.Mount_HostPath{
				HostPath: parts[0],
			},
		})
	}
	return mounts, nil
}
