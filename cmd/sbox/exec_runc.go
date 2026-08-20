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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type runcExecRunner struct {
	binary string
	root   string
}

type execUser struct {
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	AdditionalGids []uint32 `json:"additionalGids,omitempty"`
}

type runcExecProcess struct {
	Terminal bool     `json:"terminal"`
	User     execUser `json:"user"`
	Args     []string `json:"args"`
	Env      []string `json:"env,omitempty"`
	Cwd      string   `json:"cwd"`
}

func newRuncExecProcess(request execRequest) (runcExecProcess, error) {
	cwd := request.cwd
	if cwd == "" {
		cwd = "/"
	}
	process := runcExecProcess{
		Terminal: request.tty,
		Args:     append([]string{request.command}, request.args...),
		Env:      request.env,
		Cwd:      cwd,
	}
	user, err := parseRuncExecUser(request.user)
	if err != nil {
		return runcExecProcess{}, err
	}
	process.User = user
	return process, nil
}

func (r *runcExecRunner) Run(request execRequest) error {
	process, err := newRuncExecProcess(request)
	if err != nil {
		return err
	}
	data, err := json.Marshal(process)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp("", "sbox-runc-process-*.json")
	if err != nil {
		return err
	}
	processPath := temporary.Name()
	defer os.Remove(processPath)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}

	if request.tty {
		return execWithConsoleTTY("runc", func(consoleSocket, pidFile string) *exec.Cmd {
			return r.command(
				request.sandboxID,
				processPath,
				"--console-socket",
				consoleSocket,
				"--detach",
				"--pid-file",
				pidFile,
			)
		})
	}

	start := time.Now()
	cmd := r.command(request.sandboxID, processPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	logrus.Debugf("running runc exec without TTY: %v", cmd.Args)
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
				return cli.NewExitError("", exitCodeFromWaitStatus(status))
			}
		}
		return fmt.Errorf("runc exec: %w", err)
	}
	logrus.Debugf("runc exec completed in %v", time.Since(start))
	return nil
}

func (r *runcExecRunner) command(
	sandboxID string,
	processPath string,
	runtimeArgs ...string,
) *exec.Cmd {
	args := []string{"--root", r.root, "exec", "--process", processPath}
	args = append(args, runtimeArgs...)
	args = append(args, sandboxID)
	return exec.Command(r.binary, args...)
}

func parseRuncExecUser(value string) (execUser, error) {
	if value == "" {
		return execUser{}, nil
	}
	parts := strings.SplitN(value, ":", 2)
	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return execUser{}, fmt.Errorf("runc exec user must be a numeric UID: %w", err)
	}
	user := execUser{UID: uint32(uid)}
	if len(parts) == 2 {
		gid, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return execUser{}, fmt.Errorf("runc exec group must be a numeric GID: %w", err)
		}
		user.GID = uint32(gid)
	}
	return user, nil
}
