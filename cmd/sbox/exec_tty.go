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
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

const execConsoleTimeout = 10 * time.Second

type ttyProcessResult struct {
	exitCode int
	err      error
}

// execWithConsoleTTY connects sbox stdio to the OCI console socket shared by
// runsc and runc. Both runtimes create the terminal in detached mode and send
// its master file descriptor over this socket.
func execWithConsoleTTY(
	runtimeName string,
	commandFactory func(consoleSocket, pidFile string) *exec.Cmd,
) error {
	start := time.Now()
	tmpDir, err := os.MkdirTemp("", "sbox-exec-")
	if err != nil {
		return fmt.Errorf("create exec directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	consoleSocket := filepath.Join(tmpDir, "console.sock")
	pidFile := filepath.Join(tmpDir, "exec.pid")
	listener, err := net.Listen("unix", consoleSocket)
	if err != nil {
		return fmt.Errorf("create console socket: %w", err)
	}
	defer listener.Close()

	command := commandFactory(consoleSocket, pidFile)
	command.Stdin = nil
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr

	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("become child subreaper: %w", err)
	}

	consoleCh := make(chan net.Conn, 1)
	consoleErrCh := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			consoleErrCh <- acceptErr
			return
		}
		consoleCh <- connection
	}()

	if err := command.Start(); err != nil {
		return fmt.Errorf("start %s exec: %w", runtimeName, err)
	}

	var consoleConn net.Conn
	select {
	case consoleConn = <-consoleCh:
	case err := <-consoleErrCh:
		return fmt.Errorf("accept %s console connection: %w", runtimeName, err)
	case <-time.After(execConsoleTimeout):
		return fmt.Errorf("wait for %s console connection: timeout", runtimeName)
	}
	defer consoleConn.Close()

	processDone := make(chan ttyProcessResult, 1)
	go func() {
		processDone <- waitForTTYProcess(runtimeName, command, pidFile)
	}()

	unixConn, ok := consoleConn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%s console connection is not a Unix socket", runtimeName)
	}
	fd, err := receiveFD(unixConn)
	if err != nil {
		return fmt.Errorf("receive %s console FD: %w", runtimeName, err)
	}
	consoleFile := os.NewFile(uintptr(fd), "console")
	defer consoleFile.Close()

	oldState, err := setRawMode()
	if err != nil {
		logrus.Warnf("set raw terminal mode: %v", err)
	} else {
		defer restoreMode(oldState)
	}
	syncWindowSize(int(os.Stdin.Fd()), int(consoleFile.Fd()))

	go func() {
		_, _ = io.Copy(consoleFile, os.Stdin)
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, consoleFile)
	}()

	resizeCh := make(chan os.Signal, 1)
	signal.Notify(resizeCh, syscall.SIGWINCH)
	defer signal.Stop(resizeCh)
	go func() {
		for range resizeCh {
			syncWindowSize(int(os.Stdin.Fd()), int(consoleFile.Fd()))
		}
	}()

	signalCh := make(chan os.Signal, 32)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	var result ttyProcessResult
	processExited := false
	select {
	case <-signalCh:
	case result = <-processDone:
		processExited = true
	}

	_ = consoleConn.Close()
	_ = consoleFile.Close()
	if !processExited {
		result = <-processDone
	}
	if result.err != nil {
		return result.err
	}
	logrus.Debugf("%s TTY exec completed in %v", runtimeName, time.Since(start))
	if result.exitCode != 0 {
		return cli.NewExitError("", result.exitCode)
	}
	return nil
}

func waitForTTYProcess(
	runtimeName string,
	command *exec.Cmd,
	pidFile string,
) ttyProcessResult {
	if err := command.Wait(); err != nil {
		return ttyProcessResult{
			err: fmt.Errorf("detached %s exec: %w", runtimeName, err),
		}
	}
	pid, err := readPIDFile(runtimeName, pidFile, execConsoleTimeout)
	if err != nil {
		return ttyProcessResult{err: err}
	}

	var status syscall.WaitStatus
	for {
		_, err = syscall.Wait4(pid, &status, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return ttyProcessResult{
				err: fmt.Errorf("wait for %s exec process %d: %w", runtimeName, pid, err),
			}
		}
		break
	}
	return ttyProcessResult{exitCode: exitCodeFromWaitStatus(status)}
}

func readPIDFile(runtimeName, path string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var pid int
			if _, scanErr := fmt.Sscanf(string(data), "%d", &pid); scanErr == nil &&
				pid > 0 {
				return pid, nil
			}
		} else if !os.IsNotExist(err) {
			return 0, fmt.Errorf("read %s exec pidfile: %w", runtimeName, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, fmt.Errorf("wait for %s exec pidfile: timeout", runtimeName)
}
