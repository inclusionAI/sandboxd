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
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

type firecrackerExecRunner struct {
	containersRoot string
}

type firecrackerFrameWriter struct {
	mu         sync.Mutex
	connection io.Writer
}

func (writer *firecrackerFrameWriter) write(
	frameType firecrackerproto.FrameType,
	payload []byte,
) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return firecrackerproto.WriteFrame(writer.connection, frameType, payload)
}

func (runner *firecrackerExecRunner) Run(request execRequest) error {
	socket := firecrackerAgentSocket(runner.containersRoot, request.sandboxID)
	connection, err := firecrackerproto.DialAgent(socket, 5*time.Second)
	if err != nil {
		return fmt.Errorf("firecracker exec: %w", err)
	}
	defer connection.Close()

	agentRequest := firecrackerproto.ExecRequest{
		Command: request.command,
		Args:    append([]string(nil), request.args...),
		Env:     append([]string(nil), request.env...),
		Cwd:     request.cwd,
		User:    request.user,
	}
	if request.tty {
		agentRequest.Rows, agentRequest.Cols = firecrackerWindowSize()
	}
	messageType := firecrackerproto.MessageExec
	if request.tty {
		messageType = firecrackerproto.MessageExecTTY
	}
	if err := firecrackerproto.WriteMessage(
		connection,
		messageType,
		agentRequest,
	); err != nil {
		return fmt.Errorf("firecracker exec: send request: %w", err)
	}
	if err := firecrackerproto.ReadResponse(connection); err != nil {
		return fmt.Errorf("firecracker exec: %w", err)
	}

	if request.tty {
		oldState, err := setRawMode()
		if err != nil {
			return fmt.Errorf("firecracker exec: set terminal raw mode: %w", err)
		}
		defer restoreMode(oldState)
	}
	return runFirecrackerExecStream(
		connection,
		os.Stdin,
		os.Stdout,
		os.Stderr,
		request.tty,
	)
}

func firecrackerAgentSocket(_ string, sandboxID string) string {
	return firecrackerproto.HostAgentSocket(
		firecrackerproto.HostRuntimeRoot,
		sandboxID,
	)
}

func runFirecrackerExecStream(
	connection net.Conn,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	tty bool,
) error {
	writer := &firecrackerFrameWriter{connection: connection}
	done := make(chan struct{})
	defer close(done)

	go forwardFirecrackerInput(stdin, writer, done)
	go forwardFirecrackerSignals(writer, tty, done)

	for {
		frameType, payload, err := firecrackerproto.ReadFrame(connection)
		if err != nil {
			return fmt.Errorf("firecracker exec: read output: %w", err)
		}
		switch frameType {
		case firecrackerproto.FrameData:
			if _, err := stdout.Write(payload); err != nil {
				return fmt.Errorf("firecracker exec: write stdout: %w", err)
			}
		case firecrackerproto.FrameStderr:
			if _, err := stderr.Write(payload); err != nil {
				return fmt.Errorf("firecracker exec: write stderr: %w", err)
			}
		case firecrackerproto.FrameExit:
			exitCode, err := firecrackerproto.ExitCode(payload)
			if err != nil {
				return fmt.Errorf("firecracker exec: %w", err)
			}
			if exitCode != 0 {
				return cli.NewExitError("", exitCode)
			}
			return nil
		default:
			return fmt.Errorf(
				"firecracker exec: unexpected agent frame %d",
				frameType,
			)
		}
	}
}

func forwardFirecrackerInput(
	input io.Reader,
	writer *firecrackerFrameWriter,
	done <-chan struct{},
) {
	buffer := make([]byte, 32<<10)
	for {
		count, err := input.Read(buffer)
		if count > 0 {
			select {
			case <-done:
				return
			default:
			}
			if writer.write(
				firecrackerproto.FrameData,
				buffer[:count],
			) != nil {
				return
			}
		}
		if err != nil {
			_ = writer.write(firecrackerproto.FrameEOF, nil)
			return
		}
	}
}

func forwardFirecrackerSignals(
	writer *firecrackerFrameWriter,
	tty bool,
	done <-chan struct{},
) {
	signals := make(chan os.Signal, 4)
	signal.Notify(
		signals,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGWINCH,
	)
	defer signal.Stop(signals)
	for {
		select {
		case <-done:
			return
		case received := <-signals:
			if received == syscall.SIGWINCH {
				if tty {
					rows, cols := firecrackerWindowSize()
					_ = writer.write(
						firecrackerproto.FrameResize,
						firecrackerproto.ResizePayload(rows, cols),
					)
				}
				continue
			}
			signalNumber, ok := received.(syscall.Signal)
			if ok {
				_ = writer.write(
					firecrackerproto.FrameSignal,
					firecrackerproto.SignalPayload(int(signalNumber)),
				)
			}
		}
	}
}

func firecrackerWindowSize() (uint16, uint16) {
	window, err := unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
	if err != nil || window.Row == 0 || window.Col == 0 {
		return 24, 80
	}
	return window.Row, window.Col
}
