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
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type ttyProcessResult struct {
	exitCode int
	err      error
}

var (
	defaultRunscRootDir = filepath.Join(config.DefaultSandboxRootDir, config.RuntimeNameRunsc)
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

		cmd := context.Args().Get(1)
		args := []string{}
		if context.NArg() > 2 {
			args = context.Args().Tail()[1:]
		}

		binary := context.String("runtime-binary")
		if context.Bool("tty") {
			return execWithTTY(binary, sandboxID, cmd, args, context)
		}
		return execWithoutTTY(binary, sandboxID, cmd, args, context)
	},
}

// execWithoutTTY executes command without TTY (regular mode)
func execWithoutTTY(binary, sandboxID, cmd string, args []string, ctx *cli.Context) error {
	start := time.Now()
	runscRoot := ctx.String("runtime-root")

	runscCmd := exec.Command(binary, "--root", runscRoot, "exec")

	// Add flags based on CLI options
	if user := ctx.String("user"); user != "" {
		runscCmd.Args = append(runscCmd.Args, "--user", user)
	}
	if cwd := ctx.String("cwd"); cwd != "" {
		runscCmd.Args = append(runscCmd.Args, "--cwd", cwd)
	}

	// Add environment variables
	for _, env := range ctx.StringSlice("env") {
		runscCmd.Args = append(runscCmd.Args, "--env", env)
	}

	// Add sandbox ID and command
	runscCmd.Args = append(runscCmd.Args, sandboxID)
	runscCmd.Args = append(runscCmd.Args, cmd)
	runscCmd.Args = append(runscCmd.Args, args...)

	// Set up IO
	runscCmd.Stdin = os.Stdin
	runscCmd.Stdout = os.Stdout
	runscCmd.Stderr = os.Stderr

	logrus.Debugf("Running command (no TTY): %v", runscCmd.Args)

	// Execute the command
	if err := runscCmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
				code := status.ExitStatus()
				logrus.Debugf("Command exited with code %d (took %v ms)", code, time.Since(start).Milliseconds())
				if code != 0 {
					return cli.NewExitError("", code)
				}
			}
		}
		return fmt.Errorf("failed to execute command: %v", err)
	}

	logrus.Debugf("Command executed successfully (took %v ms)", time.Since(start).Milliseconds())
	return nil
}

// execWithTTY executes command with TTY support
func execWithTTY(binary, sandboxID, cmd string, args []string, ctx *cli.Context) error {
	start := time.Now()
	runscRoot := ctx.String("runtime-root")

	tmpDir, err := os.MkdirTemp("", "sbox-exec-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	consoleSocket := filepath.Join(tmpDir, "console.sock")
	pidFile := filepath.Join(tmpDir, "exec.pid")

	listener, err := net.Listen("unix", consoleSocket)
	if err != nil {
		return fmt.Errorf("failed to create console socket: %v", err)
	}
	defer listener.Close()

	runscCmd := exec.Command(binary, "--root", runscRoot, "exec")

	// Add console socket for TTY
	runscCmd.Args = append(runscCmd.Args, "--console-socket", consoleSocket)

	// Add flags based on CLI options
	if user := ctx.String("user"); user != "" {
		runscCmd.Args = append(runscCmd.Args, "--user", user)
	}
	if cwd := ctx.String("cwd"); cwd != "" {
		runscCmd.Args = append(runscCmd.Args, "--cwd", cwd)
	}

	// Add environment variables
	for _, env := range ctx.StringSlice("env") {
		runscCmd.Args = append(runscCmd.Args, "--env", env)
	}

	// Add detach and pidfile (required for runsc exec with TTY)
	runscCmd.Args = append(runscCmd.Args, "--detach", "--pid-file", pidFile)

	// Add sandbox ID and command
	runscCmd.Args = append(runscCmd.Args, sandboxID)
	runscCmd.Args = append(runscCmd.Args, cmd)
	runscCmd.Args = append(runscCmd.Args, args...)

	// Set up stdio (stdout/stderr will be redirected via console)
	runscCmd.Stdin = nil
	runscCmd.Stdout = os.Stderr // Log to stderr since TTY output goes through console
	runscCmd.Stderr = os.Stderr

	logrus.Debugf("Running command (TTY): %v", runscCmd.Args)

	// In detach mode runsc starts a second runsc-exec process that waits for the
	// sandbox process, then the original runsc process exits successfully. Become
	// a child subreaper before starting runsc so the waiting process is reparented
	// to sbox and its real wait status remains available.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to become child subreaper: %v", err)
	}

	// Channel to receive console connection
	consoleCh := make(chan net.Conn, 1)
	consoleErrCh := make(chan error, 1)

	// Accept console connection in background
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			consoleErrCh <- err
			return
		}
		consoleCh <- conn
	}()

	// Execute the command
	if err := runscCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %v", err)
	}

	// Wait for console connection with timeout
	var consoleConn net.Conn
	select {
	case conn := <-consoleCh:
		consoleConn = conn
	case err := <-consoleErrCh:
		return fmt.Errorf("failed to accept console connection: %v", err)
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timeout waiting for console connection")
	}

	// The pidfile contains the host PID of runsc-exec. Once the detach parent
	// exits, wait for that reparented process and preserve its exit status.
	processDone := make(chan ttyProcessResult, 1)
	go func() {
		processDone <- waitForTTYProcess(runscCmd, pidFile)
	}()

	// Get the PTY file descriptor from the socket
	// The connection should be a Unix socket with file descriptor passing
	unixConn, ok := consoleConn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("console connection is not a Unix socket")
	}

	// Receive file descriptor
	fd, err := receiveFD(unixConn)
	if err != nil {
		return fmt.Errorf("failed to receive console FD: %v", err)
	}
	consoleFile := os.NewFile(uintptr(fd), "console")
	defer consoleFile.Close()

	// Set raw mode on local terminal
	oldState, err := setRawMode()
	if err != nil {
		logrus.Warnf("Failed to set raw mode: %v", err)
	} else {
		defer restoreMode(oldState)
	}

	// Copy data between local terminal and console
	consoleDone := make(chan struct{})

	// Sync initial window size
	syncWindowSize(int(os.Stdin.Fd()), int(consoleFile.Fd()))

	// Handle window resize
	resizeCh := make(chan os.Signal, 1)
	signal.Notify(resizeCh, syscall.SIGWINCH)
	defer signal.Stop(resizeCh)
	go func() {
		for range resizeCh {
			logrus.Debug("Window resize detected, syncing size")
			syncWindowSize(int(os.Stdin.Fd()), int(consoleFile.Fd()))
		}
	}()

	// Copy stdin -> console
	go func() {
		defer close(consoleDone)
		_, _ = io.Copy(consoleFile, os.Stdin)
	}()

	// Copy console -> stdout
	go func() {
		_, _ = io.Copy(os.Stdout, consoleFile)
	}()

	// Handle signals
	sigCh := make(chan os.Signal, 32)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Reset()

	// Wait for process exit, console close, or signal
	var processResult ttyProcessResult
	processExited := false
	select {
	case sig := <-sigCh:
		logrus.Debugf("Received signal: %v", sig)
	case <-consoleDone:
		logrus.Debug("Console closed, process exited")
	case processResult = <-processDone:
		processExited = true
		logrus.Debug("Process exited")
	}

	// Closing the PTY also ensures a disconnected client does not leave the
	// sandbox process running indefinitely. If the process has not exited yet,
	// wait for runsc-exec to report its final status.
	_ = consoleConn.Close()
	_ = consoleFile.Close()
	if !processExited {
		processResult = <-processDone
	}
	if processResult.err != nil {
		return processResult.err
	}

	logrus.Debugf("Command exited with code %d (took %v ms)", processResult.exitCode, time.Since(start).Milliseconds())
	if processResult.exitCode != 0 {
		return cli.NewExitError("", processResult.exitCode)
	}
	return nil
}

func waitForTTYProcess(runscCmd *exec.Cmd, pidFile string) ttyProcessResult {
	if err := runscCmd.Wait(); err != nil {
		return ttyProcessResult{err: fmt.Errorf("detached runsc exec failed: %v", err)}
	}

	pid, err := readPIDFile(pidFile, 10*time.Second)
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
			return ttyProcessResult{err: fmt.Errorf("failed to wait for runsc exec process %d: %v", pid, err)}
		}
		break
	}

	return ttyProcessResult{exitCode: exitCodeFromWaitStatus(status)}
}

func readPIDFile(path string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var pid int
			if _, scanErr := fmt.Sscanf(string(data), "%d", &pid); scanErr == nil && pid > 0 {
				return pid, nil
			}
		} else if !os.IsNotExist(err) {
			return 0, fmt.Errorf("failed to read runsc exec pidfile: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, fmt.Errorf("timed out waiting for runsc exec pidfile")
}

func exitCodeFromWaitStatus(status syscall.WaitStatus) int {
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}

// receiveFD receives a file descriptor over a Unix socket
func receiveFD(conn *net.UnixConn) (int, error) {
	// Get the underlying file descriptor
	f, err := conn.File()
	if err != nil {
		return -1, err
	}
	defer f.Close()

	fd := int(f.Fd())

	// Set a timeout on the connection
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read the file descriptor using syscall.Recvmsg
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4))

	n, oobn, _, _, err := syscall.Recvmsg(fd, buf, oob, 0)
	if err != nil {
		return -1, err
	}

	if oobn > 0 {
		cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return -1, err
		}

		for _, cmsg := range cmsgs {
			if cmsg.Header.Level == syscall.SOL_SOCKET && cmsg.Header.Type == syscall.SCM_RIGHTS {
				fds, err := syscall.ParseUnixRights(&cmsg)
				if err != nil {
					return -1, err
				}
				if len(fds) > 0 {
					return fds[0], nil
				}
			}
		}
	}

	_ = n // suppress unused warning
	return -1, fmt.Errorf("no file descriptor received")
}

// setRawMode sets the local terminal to raw mode
func setRawMode() (*syscall.Termios, error) {
	// Get current terminal settings
	oldState, err := tcgetattr(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}

	// Make a copy and set raw mode
	newState := *oldState
	newState.Iflag &^= syscall.BRKINT | syscall.ICRNL | syscall.INPCK | syscall.ISTRIP | syscall.IXON
	newState.Oflag &^= syscall.OPOST
	newState.Cflag |= syscall.CS8
	newState.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	newState.Cc[syscall.VMIN] = 1
	newState.Cc[syscall.VTIME] = 0

	err = tcsetattr(int(os.Stdin.Fd()), &newState)
	if err != nil {
		return nil, err
	}

	return oldState, nil
}

// restoreMode restores the terminal to its original state
func restoreMode(state *syscall.Termios) {
	if state != nil {
		tcsetattr(int(os.Stdin.Fd()), state)
	}
}

// tcgetattr gets terminal attributes
func tcgetattr(fd int) (*syscall.Termios, error) {
	var termios syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
	if err != 0 {
		return nil, err
	}
	return &termios, nil
}

// tcsetattr sets terminal attributes
func tcsetattr(fd int, termios *syscall.Termios) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS, uintptr(unsafe.Pointer(termios)))
	if err != 0 {
		return err
	}
	return nil
}

// syncWindowSize gets the window size from src fd and sets it to dst fd
func syncWindowSize(srcFd, dstFd int) {
	ws, err := unix.IoctlGetWinsize(srcFd, unix.TIOCGWINSZ)
	if err != nil {
		logrus.Warnf("Failed to get window size: %v", err)
		return
	}

	err = unix.IoctlSetWinsize(dstFd, unix.TIOCSWINSZ, ws)
	if err != nil {
		logrus.Warnf("Failed to set window size: %v", err)
		return
	}

	logrus.Debugf("Window size synced: %dx%d", ws.Col, ws.Row)
}
