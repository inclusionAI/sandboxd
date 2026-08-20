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
	"path/filepath"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type execRequest struct {
	sandboxID string
	command   string
	args      []string
	user      string
	env       []string
	cwd       string
	tty       bool
}

type execRunner interface {
	Run(execRequest) error
}

var defaultRunscRootDir = filepath.Join(
	config.DefaultSandboxRootDir,
	config.RuntimeNameRunsc,
)

var defaultRuncRootDir = config.DefaultRuncStateRoot

var defaultContainersRoot = filepath.Join(
	config.DefaultSandboxRootDir,
	"containers",
)

var ExecCmd = cli.Command{
	Name:  "exec",
	Usage: "execute a command in a running sandbox",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "user, u",
			Usage: "Username or UID (format: <name|uid>[:<group|gid>])",
		},
		cli.StringSliceFlag{
			Name:  "env, e",
			Usage: "Set environment variables",
		},
		cli.StringFlag{
			Name:  "cwd",
			Usage: "Set working directory",
		},
		cli.BoolFlag{
			Name:  "t, tty",
			Usage: "Allocate a pseudo-TTY",
		},
		cli.StringFlag{
			Name:   "runtime-binary",
			Usage:  "Path to runsc binary",
			Value:  config.DefaultRunscBinary,
			EnvVar: "RUNSC_BINARY",
		},
		cli.StringFlag{
			Name:   "runtime-root",
			Usage:  "Root directory for runsc state",
			Value:  defaultRunscRootDir,
			EnvVar: "RUNSC_ROOT",
		},
		cli.StringFlag{
			Name:   "runc-binary",
			Usage:  "Path to runc binary",
			Value:  config.DefaultRuncBinary,
			EnvVar: "RUNC_BINARY",
		},
		cli.StringFlag{
			Name:   "runc-root",
			Usage:  "Root directory for runc state",
			Value:  defaultRuncRootDir,
			EnvVar: "RUNC_ROOT",
		},
		cli.StringFlag{
			Name:   "containers-root",
			Usage:  "Root directory for sandboxd runtime state",
			Value:  defaultContainersRoot,
			EnvVar: "SANDBOXD_CONTAINERS_ROOT",
		},
		cli.BoolFlag{
			Name:   "ignore-cgroups",
			Usage:  "tell runsc exec not to create or join cgroups",
			EnvVar: "RUNSC_IGNORE_CGROUPS",
		},
	},
	Action: func(context *cli.Context) error {
		if context.NArg() < 2 {
			return fmt.Errorf("usage: sbox exec <sandbox_id> <cmd> [args...]")
		}

		sandboxID := context.Args().Get(0)
		if !config.IsValidSandboxID(sandboxID) {
			return fmt.Errorf("sandbox id %q must use %s<suffix> as one path component", sandboxID, config.SandboxIDPrefix)
		}

		if !context.GlobalBool("debug") {
			logrus.SetLevel(logrus.WarnLevel)
		}

		runtimeName, err := resolveExecRuntime(context, sandboxID)
		if err != nil {
			return err
		}
		runner, err := newExecRunner(runtimeName, context)
		if err != nil {
			return err
		}

		command := context.Args().Get(1)
		args := []string{}
		if context.NArg() > 2 {
			args = context.Args().Tail()[1:]
		}
		return runner.Run(execRequest{
			sandboxID: sandboxID,
			command:   command,
			args:      args,
			user:      context.String("user"),
			env:       context.StringSlice("env"),
			cwd:       context.String("cwd"),
			tty:       context.Bool("tty"),
		})
	},
}

func resolveExecRuntime(context *cli.Context, sandboxID string) (string, error) {
	client, err := NewSandboxClient(context)
	if err != nil {
		return "", err
	}
	defer client.Close()

	response, err := client.ListSandbox(nil, sandboxID)
	if err != nil {
		return "", fmt.Errorf("inspect sandbox %s: %w", sandboxID, err)
	}
	if len(response.Sandboxes) != 1 || response.Sandboxes[0].Runtime == "" {
		return "", fmt.Errorf("sandbox %s has no runtime metadata", sandboxID)
	}
	return response.Sandboxes[0].Runtime, nil
}

func newExecRunner(runtimeName string, context *cli.Context) (execRunner, error) {
	switch runtimeName {
	case config.RuntimeNameRunsc:
		return &runscExecRunner{
			binary:        context.String("runtime-binary"),
			root:          context.String("runtime-root"),
			ignoreCgroups: context.Bool("ignore-cgroups"),
		}, nil
	case config.RuntimeNameKata:
		return &kataExecRunner{
			containersRoot: context.String("containers-root"),
		}, nil
	case config.RuntimeNameRunc:
		return &runcExecRunner{
			binary: context.String("runc-binary"),
			root:   context.String("runc-root"),
		}, nil
	default:
		return nil, fmt.Errorf("runtime %q does not support sbox exec", runtimeName)
	}
}
