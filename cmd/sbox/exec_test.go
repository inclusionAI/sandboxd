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
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli"
)

func TestExitCodeFromWaitStatus(t *testing.T) {
	assert.Equal(t, 7, exitCodeFromWaitStatus(syscall.WaitStatus(7<<8)))
	assert.Equal(t, 128+int(syscall.SIGTERM), exitCodeFromWaitStatus(syscall.WaitStatus(syscall.SIGTERM)))
}

func TestCommandExitCode(t *testing.T) {
	assert.Equal(t, 7, commandExitCode(cli.NewExitError("", 7)))
	assert.Equal(t, 1, commandExitCode(assert.AnError))
}

func TestRunscExecCommand(t *testing.T) {
	runner := &runscExecRunner{
		binary: "/usr/local/bin/runsc",
		root:   "/run/runsc",
	}
	command := runner.command(
		execRequest{
			sandboxID: "sbox-test",
			command:   "/bin/sh",
			args:      []string{"-c", "echo ok"},
			user:      "1000:1000",
			env:       []string{"LANG=C"},
			cwd:       "/tmp",
		},
		"--console-socket",
		"/tmp/console.sock",
	)

	assert.Equal(t, []string{
		"/usr/local/bin/runsc",
		"--root",
		"/run/runsc",
		"exec",
		"--console-socket",
		"/tmp/console.sock",
		"--user",
		"1000:1000",
		"--cwd",
		"/tmp",
		"--env",
		"LANG=C",
		"sbox-test",
		"/bin/sh",
		"-c",
		"echo ok",
	}, command.Args)
}
