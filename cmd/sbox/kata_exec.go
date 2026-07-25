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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	taskv2 "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/fifo"
	"github.com/containerd/ttrpc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	kataExecTaskService = "containerd.task.v2.Task"
	kataProcessTypeURL  = "types.containerd.io/opencontainers/runtime-spec/1/Process"
)

type kataExecRunner struct {
	containersRoot string
}

func (r *kataExecRunner) Run(request execRequest) error {
	bundlePath := filepath.Join(r.containersRoot, request.sandboxID)
	address, err := readKataShimAddress(bundlePath)
	if err != nil {
		return err
	}
	connection, err := dialKataShim(address)
	if err != nil {
		return fmt.Errorf("kata exec: connect shim: %w", err)
	}
	client := ttrpc.NewClient(connection)
	defer client.Close()

	process, err := kataExecProcess(bundlePath, request)
	if err != nil {
		return err
	}
	processJSON, err := json.Marshal(process)
	if err != nil {
		return err
	}

	if request.tty {
		oldState, rawErr := setRawMode()
		if rawErr != nil {
			return fmt.Errorf("kata exec: set terminal raw mode: %w", rawErr)
		}
		defer restoreMode(oldState)
	}

	temporaryDir, err := os.MkdirTemp("", "sbox-kata-exec-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporaryDir)
	stdinPath := filepath.Join(temporaryDir, "stdin")
	stdoutPath := filepath.Join(temporaryDir, "stdout")
	stderrPath := filepath.Join(temporaryDir, "stderr")

	ioContext, cancelIO := context.WithCancel(context.Background())
	streams, err := openKataExecIO(
		ioContext,
		stdinPath,
		stdoutPath,
		stderrPath,
		request.tty,
	)
	if err != nil {
		cancelIO()
		return err
	}
	defer streams.Close()
	defer cancelIO()
	streams.Copy()

	execID := fmt.Sprintf("sbox-exec-%d-%d", os.Getpid(), time.Now().UnixNano())
	execRequest := &taskv2.ExecProcessRequest{
		ID:       request.sandboxID,
		ExecID:   execID,
		Terminal: request.tty,
		Stdin:    stdinPath,
		Stdout:   stdoutPath,
		Stderr:   stderrPath,
		Spec: &anypb.Any{
			TypeUrl: kataProcessTypeURL,
			Value:   processJSON,
		},
	}
	callContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := client.Call(callContext, kataExecTaskService, "Exec", execRequest, &emptypb.Empty{}); err != nil {
		cancel()
		return fmt.Errorf("kata exec: register process: %w", err)
	}
	cancel()

	callContext, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	startResponse := &taskv2.StartResponse{}
	err = client.Call(callContext, kataExecTaskService, "Start", &taskv2.StartRequest{
		ID: request.sandboxID, ExecID: execID,
	}, startResponse)
	cancel()
	if err != nil {
		deleteContext, deleteCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = client.Call(deleteContext, kataExecTaskService, "Delete", &taskv2.DeleteRequest{
			ID: request.sandboxID, ExecID: execID,
		}, &taskv2.DeleteResponse{})
		deleteCancel()
		return fmt.Errorf("kata exec: start process: %w", err)
	}

	resizeDone := make(chan struct{})
	processDone := make(chan struct{})
	if request.tty {
		go forwardKataWindowChanges(
			client,
			request.sandboxID,
			execID,
			processDone,
			resizeDone,
		)
		resizeKataPTY(client, request.sandboxID, execID)
	} else {
		close(resizeDone)
	}

	waitResult := make(chan struct {
		response *taskv2.WaitResponse
		err      error
	}, 1)
	go func() {
		response := &taskv2.WaitResponse{}
		err := client.Call(context.Background(), kataExecTaskService, "Wait", &taskv2.WaitRequest{
			ID: request.sandboxID, ExecID: execID,
		}, response)
		waitResult <- struct {
			response *taskv2.WaitResponse
			err      error
		}{response: response, err: err}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	var result struct {
		response *taskv2.WaitResponse
		err      error
	}
	select {
	case result = <-waitResult:
	case received := <-signals:
		callContext, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		_ = client.Call(callContext, kataExecTaskService, "Kill", &taskv2.KillRequest{
			ID:     request.sandboxID,
			ExecID: execID,
			Signal: uint32(received.(syscall.Signal)),
		}, &emptypb.Empty{})
		cancel()
		result = <-waitResult
	}
	close(processDone)
	<-resizeDone

	// Deleting the exec process closes the shim's FIFO endpoints and lets the
	// local copy goroutines terminate.
	deleteContext, deleteCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = client.Call(deleteContext, kataExecTaskService, "Delete", &taskv2.DeleteRequest{
		ID: request.sandboxID, ExecID: execID,
	}, &taskv2.DeleteResponse{})
	deleteCancel()
	streams.CloseStdin()
	ioDone := make(chan struct{})
	go func() {
		streams.Wait()
		close(ioDone)
	}()
	select {
	case <-ioDone:
	case <-time.After(5 * time.Second):
		logrus.Warn("kata exec: timed out draining process IO")
	}
	if result.err != nil {
		return fmt.Errorf("kata exec: wait: %w", result.err)
	}
	if result.response != nil && result.response.ExitStatus != 0 {
		return cli.NewExitError("", int(result.response.ExitStatus))
	}
	return nil
}

func kataExecProcess(bundlePath string, request execRequest) (*specs.Process, error) {
	data, err := os.ReadFile(filepath.Join(bundlePath, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("kata exec: read OCI spec: %w", err)
	}
	var ociSpec specs.Spec
	if err := json.Unmarshal(data, &ociSpec); err != nil {
		return nil, fmt.Errorf("kata exec: decode OCI spec: %w", err)
	}
	process := ociSpec.Process
	if process == nil {
		process = &specs.Process{Cwd: "/", User: specs.User{UID: 0, GID: 0}}
	}
	process.Terminal = request.tty
	process.Args = append([]string{request.command}, request.args...)
	if request.cwd != "" {
		process.Cwd = request.cwd
	}
	process.Env = mergeKataExecEnv(process.Env, request.env)
	if request.user != "" {
		uid, gid, parseErr := parseKataExecUser(request.user)
		if parseErr != nil {
			return nil, parseErr
		}
		process.User = specs.User{UID: uid, GID: gid}
	}
	return process, nil
}

func mergeKataExecEnv(base, overrides []string) []string {
	values := make(map[string]string, len(base)+len(overrides))
	order := make([]string, 0, len(base)+len(overrides))
	for _, environment := range append(append([]string{}, base...), overrides...) {
		parts := strings.SplitN(environment, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if _, exists := values[parts[0]]; !exists {
			order = append(order, parts[0])
		}
		values[parts[0]] = parts[1]
	}
	result := make([]string, 0, len(order))
	for _, key := range order {
		result = append(result, key+"="+values[key])
	}
	return result
}

func parseKataExecUser(value string) (uint32, uint32, error) {
	parts := strings.SplitN(value, ":", 2)
	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("kata exec: user must be a numeric UID[:GID]: %w", err)
	}
	var gid uint64
	if len(parts) == 2 {
		gid, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("kata exec: invalid GID: %w", err)
		}
	}
	return uint32(uid), uint32(gid), nil
}

func readKataShimAddress(bundlePath string) (string, error) {
	data, err := os.ReadFile(filepath.Join(bundlePath, "address"))
	if err != nil {
		return "", fmt.Errorf("kata exec: read shim address: %w", err)
	}
	address := strings.TrimPrefix(strings.TrimSpace(string(data)), "unix://")
	if address == "" {
		return "", fmt.Errorf("kata exec: shim address is empty")
	}
	return address, nil
}

func dialKataShim(socketPath string) (net.Conn, error) {
	connection, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err == nil {
		return connection, nil
	}
	var abstractErr error
	for _, name := range []string{"\x00" + socketPath, "\x00" + socketPath + "\x00"} {
		connection, abstractErr = net.DialTimeout("unix", name, 5*time.Second)
		if abstractErr == nil {
			return connection, nil
		}
	}
	return nil, fmt.Errorf("%w; abstract socket: %v", err, abstractErr)
}

type kataExecIO struct {
	stdin  io.ReadWriteCloser
	stdout io.ReadWriteCloser
	stderr io.ReadWriteCloser

	stdinOnce sync.Once
	outputs   sync.WaitGroup
}

func openKataExecIO(
	ctx context.Context,
	stdinPath string,
	stdoutPath string,
	stderrPath string,
	terminal bool,
) (_ *kataExecIO, retErr error) {
	streams := &kataExecIO{}
	defer func() {
		if retErr != nil {
			streams.Close()
		}
	}()

	var err error
	streams.stdin, err = fifo.OpenFifo(
		ctx,
		stdinPath,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_NONBLOCK,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("kata exec: open stdin FIFO: %w", err)
	}
	streams.stdout, err = fifo.OpenFifo(
		ctx,
		stdoutPath,
		syscall.O_RDONLY|syscall.O_CREAT|syscall.O_NONBLOCK,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("kata exec: open stdout FIFO: %w", err)
	}
	if !terminal {
		streams.stderr, err = fifo.OpenFifo(
			ctx,
			stderrPath,
			syscall.O_RDONLY|syscall.O_CREAT|syscall.O_NONBLOCK,
			0600,
		)
		if err != nil {
			return nil, fmt.Errorf("kata exec: open stderr FIFO: %w", err)
		}
	}
	return streams, nil
}

func (s *kataExecIO) Copy() {
	go func() {
		_, _ = io.Copy(s.stdin, os.Stdin)
		s.CloseStdin()
	}()

	s.outputs.Add(1)
	go func() {
		defer s.outputs.Done()
		_, _ = io.Copy(os.Stdout, s.stdout)
		_ = s.stdout.Close()
	}()
	if s.stderr != nil {
		s.outputs.Add(1)
		go func() {
			defer s.outputs.Done()
			_, _ = io.Copy(os.Stderr, s.stderr)
			_ = s.stderr.Close()
		}()
	}
}

func (s *kataExecIO) CloseStdin() {
	s.stdinOnce.Do(func() {
		if s.stdin != nil {
			_ = s.stdin.Close()
		}
	})
}

func (s *kataExecIO) Wait() {
	s.outputs.Wait()
}

func (s *kataExecIO) Close() {
	s.CloseStdin()
	for _, stream := range []io.Closer{s.stdout, s.stderr} {
		if stream != nil {
			_ = stream.Close()
		}
	}
}

func forwardKataWindowChanges(client *ttrpc.Client, sandboxID, execID string, done <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	windowChanges := make(chan os.Signal, 1)
	signal.Notify(windowChanges, syscall.SIGWINCH)
	defer signal.Stop(windowChanges)
	for {
		select {
		case <-done:
			return
		case <-windowChanges:
			resizeKataPTY(client, sandboxID, execID)
		}
	}
}

func resizeKataPTY(client *ttrpc.Client, sandboxID, execID string) {
	window, err := unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return
	}
	resizeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = client.Call(resizeContext, kataExecTaskService, "ResizePty", &taskv2.ResizePtyRequest{
		ID: sandboxID, ExecID: execID, Width: uint32(window.Col), Height: uint32(window.Row),
	}, &emptypb.Empty{})
}
