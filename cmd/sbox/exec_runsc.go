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
	"os/exec"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type runscExecRunner struct {
	binary        string
	root          string
	ignoreCgroups bool
}

func (r *runscExecRunner) Run(request execRequest) error {
	if request.tty {
		return r.execWithTTY(request)
	}
	return r.execWithoutTTY(request)
}

func (r *runscExecRunner) command(
	request execRequest,
	runtimeArgs ...string,
) *exec.Cmd {
	args := []string{"--root", r.root}
	if r.ignoreCgroups {
		args = append(args, "--ignore-cgroups")
	}
	args = append(args, "exec")
	args = append(args, runtimeArgs...)
	if request.user != "" {
		args = append(args, "--user", request.user)
	}
	if request.cwd != "" {
		args = append(args, "--cwd", request.cwd)
	}
	for _, environment := range request.env {
		args = append(args, "--env", environment)
	}
	args = append(args, request.sandboxID, request.command)
	args = append(args, request.args...)
	return exec.Command(r.binary, args...)
}

func (r *runscExecRunner) execWithoutTTY(request execRequest) error {
	start := time.Now()
	command := r.command(request)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	logrus.Debugf("running runsc exec without TTY: %v", command.Args)

	if err := command.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
				return cli.NewExitError("", exitCodeFromWaitStatus(status))
			}
		}
		return fmt.Errorf("runsc exec: %w", err)
	}
	logrus.Debugf("runsc exec completed in %v", time.Since(start))
	return nil
}

func (r *runscExecRunner) execWithTTY(request execRequest) error {
	return execWithConsoleTTY("runsc", func(consoleSocket, pidFile string) *exec.Cmd {
		return r.command(
			request,
			"--console-socket",
			consoleSocket,
			"--detach",
			"--pid-file",
			pidFile,
		)
	})
}

func exitCodeFromWaitStatus(status syscall.WaitStatus) int {
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}
