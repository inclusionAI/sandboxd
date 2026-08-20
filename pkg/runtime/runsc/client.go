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

package runsc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	contMgrCreateLinksAndRoutes = "containerManager.CreateLinksAndRoutes"
	contMgrRootContainerStart   = "containerManager.StartRoot"
	contMgrRestore              = "containerManager.Restore"
	contMgrWait                 = "containerManager.Wait"
)

type controlRPC interface {
	Call(method string, arg, result any) error
	Close() error
}

type interruptibleControlRPC interface {
	Interrupt() error
}

// Client is sandboxd's narrow adapter over upstream gVisor runsc. It avoids
// linking runsc/boot or runsc/container directly because those packages pull in
// the sentry/boot build graph and generated artifacts.
type Client struct {
	Binary  string
	RootDir string
	Options Options

	connectControl func(string) (controlRPC, error)
	openRawSocket  func(net.Interface) (*os.File, error)
}

type Options struct {
	FilestoreDir     string
	OverlayTmpfsSize string
	DebugLogPath     string
	IgnoreCgroups    bool
}

type StartArgs struct {
	ID          string
	BundleDir   string
	UserStdout  string
	UserStderr  string
	RootOverlay string
	Network     NetworkConfig
}

func NewClient(binary, rootDir string) *Client {
	return NewClientWithOptions(binary, rootDir, Options{})
}

func NewClientWithOptions(binary, rootDir string, options Options) *Client {
	return &Client{
		Binary:  binary,
		RootDir: rootDir,
		Options: options,
		connectControl: func(path string) (controlRPC, error) {
			return connectRPC(path)
		},
		openRawSocket: OpenRawSocket,
	}
}

// Create performs the single required runsc binary exec. It intentionally uses
// regular files for stdio so the boot/gofer processes do not inherit pipes held
// by exec.Cmd, which can otherwise make create appear to hang.
func (c *Client) Create(ctx context.Context, args StartArgs) error {
	if args.ID == "" {
		return fmt.Errorf("container id is empty")
	}
	if args.BundleDir == "" {
		return fmt.Errorf("bundle dir is empty for %s", args.ID)
	}
	if c.Options.FilestoreDir == "" {
		return fmt.Errorf("filestore directory is empty for %s", args.ID)
	}
	if err := os.MkdirAll(c.RootDir, 0711); err != nil {
		return fmt.Errorf("create runsc root %s: %w", c.RootDir, err)
	}

	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer stdin.Close()

	stdout, err := openOutputFile(args.UserStdout)
	if err != nil {
		return fmt.Errorf("open stdout file %q: %w", args.UserStdout, err)
	}
	defer stdout.Close()

	stderr, err := openOutputFile(args.UserStderr)
	if err != nil {
		return fmt.Errorf("open stderr file %q: %w", args.UserStderr, err)
	}
	defer stderr.Close()

	cmdArgs := append(c.globalArgs(),
		"-network=sandbox",
		"--net-raw",
	)
	if c.Options.DebugLogPath != "" {
		cmdArgs = append(cmdArgs, "-debug-log="+c.Options.DebugLogPath)
	}
	rootOverlay := args.RootOverlay
	if rootOverlay == "" {
		rootOverlay = RootFileOverlay(c.Options.FilestoreDir, c.Options.OverlayTmpfsSize)
	}
	cmdArgs = append(cmdArgs, "--overlay2="+rootOverlay)
	cmdArgs = append(cmdArgs, "create")
	cmdArgs = append(cmdArgs,
		"--bundle", args.BundleDir,
		args.ID,
	)
	cmd := exec.CommandContext(ctx, c.Binary, cmdArgs...)
	cmd.Env = os.Environ()
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	start := time.Now()
	logrus.Debugf("runsc create command started, id: %s, args: %v", args.ID, cmdArgs)
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if stderrOutput := readOutputSnippet(args.UserStderr); stderrOutput != "" {
			return fmt.Errorf("runsc create %s failed: %w: %s", args.ID, err, stderrOutput)
		}
		return fmt.Errorf("runsc create %s failed: %w", args.ID, err)
	}
	logrus.Debugf("runsc create command finished, id: %s, cost: %v", args.ID, time.Since(start))
	return nil
}

// RootFileOverlay returns a writable root overlay backed by dir.
func RootFileOverlay(dir, size string) string {
	overlay := "root:dir=" + dir
	if size == "" {
		return overlay
	}
	return overlay + ",size=" + size
}

func (c *Client) globalArgs() []string {
	args := []string{"--root", c.RootDir}
	if c.Options.IgnoreCgroups {
		args = append(args, "--ignore-cgroups")
	}
	return args
}

func openOutputFile(path string) (*os.File, error) {
	if path == "" {
		return os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
}

func readOutputSnippet(path string) string {
	if path == "" || path == os.DevNull {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	const maxSnippetLen = 4096
	if len(data) > maxSnippetLen {
		data = data[len(data)-maxSnippetLen:]
	}
	return strings.TrimSpace(string(data))
}

// Start configures external networking with a raw socket FD and starts the root
// container through gVisor's existing control RPCs.
func (c *Client) Start(ctx context.Context, args StartArgs) error {
	logrus.Debugf("runsc start rpc flow started, id: %s", args.ID)
	state, err := c.loadState(args.ID)
	if err != nil {
		return fmt.Errorf("load runsc state for %s: %w", args.ID, err)
	}
	logrus.Debugf("runsc start loaded state, id: %s, control_socket: %s", args.ID, state.Sandbox.ControlSocketPath)

	logrus.Debugf("runsc start opening raw socket, id: %s, interface: %+v", args.ID, args.Network.Interface)
	rawSocket, err := c.openRawSocket(*args.Network.Interface)
	if err != nil {
		return err
	}
	defer rawSocket.Close()
	logrus.Debugf("runsc start opened raw socket, id: %s", args.ID)

	networkArgs, err := BuildNetworkArgs(args.Network, rawSocket)
	if err != nil {
		return err
	}
	logrus.Debugf("runsc start built network args, id: %s", args.ID)

	logrus.Debugf("runsc start connecting control socket, id: %s, socket: %s", args.ID, state.Sandbox.ControlSocketPath)
	conn, err := c.connectControl(state.Sandbox.ControlSocketPath)
	if err != nil {
		return fmt.Errorf("connect runsc control socket for %s: %w", args.ID, err)
	}
	defer conn.Close()
	logrus.Debugf("runsc start connected control socket, id: %s", args.ID)

	if err := callContextWithTimeout(ctx, conn, contMgrCreateLinksAndRoutes, networkArgs, nil, 30*time.Second); err != nil {
		return fmt.Errorf("create links and routes for %s: %w", args.ID, err)
	}
	if err := callContextWithTimeout(ctx, conn, contMgrRootContainerStart, &args.ID, nil, 30*time.Second); err != nil {
		return fmt.Errorf("start root container %s: %w", args.ID, err)
	}
	if err := c.markStateRunning(args.ID); err != nil {
		return fmt.Errorf("mark runsc state running for %s: %w", args.ID, err)
	}
	return nil
}

// Checkpoint saves a sandbox to imageDir using the stable upstream runsc CLI.
// leaveRunning is used by pause/resume so source recovery before the PAUSED
// commit does not require a second physical sandbox restore.
func (c *Client) Checkpoint(ctx context.Context, id, imageDir string, leaveRunning bool) error {
	if id == "" {
		return fmt.Errorf("container id is empty")
	}
	if imageDir == "" {
		return fmt.Errorf("checkpoint image directory is empty for %s", id)
	}

	args := append(c.globalArgs(),
		"checkpoint",
		"--compression=flate-best-speed",
	)
	if leaveRunning {
		args = append(args, "--leave-running")
	}
	args = append(args, "--image-path", imageDir, id)
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("runsc checkpoint %s failed: %w: %s", id, err, strings.TrimSpace(string(output)))
	}
	return nil
}

type restoreOpts struct {
	payload filePayload `json:"-"`

	HavePagesFile      bool
	HaveDeviceFile     bool
	Background         bool
	UseCheckpointGofer bool `json:"use_checkpoint_gofer"`
}

func (o *restoreOpts) filePayload() []*os.File {
	return o.payload.Files
}

func (o *restoreOpts) setFilePayload(files []*os.File) {
	o.payload.Files = files
}

// Restore connects a runsc sandbox previously created with Create, installs
// its target networking, and restores the single compressed checkpoint file.
// The Restore RPC has no fixed timeout because loading a large image may take
// arbitrarily long; it remains cancellable through ctx.
func (c *Client) Restore(ctx context.Context, args StartArgs, imagePath string) error {
	if args.ID == "" {
		return fmt.Errorf("container id is empty")
	}
	if imagePath == "" {
		return fmt.Errorf("checkpoint image path is empty for %s", args.ID)
	}
	if args.Network.Interface == nil {
		return fmt.Errorf("network interface is nil for %s", args.ID)
	}

	state, err := c.loadState(args.ID)
	if err != nil {
		return fmt.Errorf("load runsc state for %s: %w", args.ID, err)
	}
	rawSocket, err := c.openRawSocket(*args.Network.Interface)
	if err != nil {
		return err
	}
	defer rawSocket.Close()

	networkArgs, err := BuildNetworkArgs(args.Network, rawSocket)
	if err != nil {
		return err
	}
	conn, err := c.connectControl(state.Sandbox.ControlSocketPath)
	if err != nil {
		return fmt.Errorf("connect runsc control socket for %s: %w", args.ID, err)
	}
	defer conn.Close()

	if err := callContextWithTimeout(ctx, conn, contMgrCreateLinksAndRoutes, networkArgs, nil, 30*time.Second); err != nil {
		return fmt.Errorf("create links and routes for %s: %w", args.ID, err)
	}
	image, err := os.Open(imagePath)
	if err != nil {
		return fmt.Errorf("open checkpoint image for %s: %w", args.ID, err)
	}
	defer image.Close()

	opts := &restoreOpts{payload: filePayload{Files: []*os.File{image}}}
	if err := callContext(ctx, conn, contMgrRestore, opts, nil); err != nil {
		return fmt.Errorf("restore root container %s: %w", args.ID, err)
	}
	if err := c.markStateRunning(args.ID); err != nil {
		return fmt.Errorf("mark runsc state running for %s: %w", args.ID, err)
	}
	return nil
}

func callContext(ctx context.Context, conn controlRPC, method string, arg, result any) error {
	done := make(chan error, 1)
	go func() {
		done <- conn.Call(method, arg, result)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if interruptible, ok := conn.(interruptibleControlRPC); ok {
			_ = interruptible.Interrupt()
		} else {
			_ = conn.Close()
		}
		return ctx.Err()
	}
}

func callContextWithTimeout(ctx context.Context, conn controlRPC, method string, arg, result any, timeout time.Duration) error {
	start := time.Now()
	logrus.Debugf("runsc urpc call %s started", method)
	if timeout <= 0 {
		err := callContext(ctx, conn, method, arg, result)
		logrus.Debugf("runsc urpc call %s finished, cost: %v, err: %v", method, time.Since(start), err)
		return err
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := callContext(callCtx, conn, method, arg, result)
	logrus.Debugf("runsc urpc call %s finished, cost: %v, err: %v", method, time.Since(start), err)
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("urpc method %q timed out after %s", method, timeout)
	}
	return err
}

func (c *Client) Wait(ctx context.Context, id string) (int, error) {
	state, err := c.loadState(id)
	if err != nil {
		return 0, fmt.Errorf("load runsc state for %s: %w", id, err)
	}
	conn, err := c.connectControl(state.Sandbox.ControlSocketPath)
	if err != nil {
		return 0, fmt.Errorf("connect runsc control socket for %s: %w", id, err)
	}
	defer conn.Close()

	var status uint32
	if err := callContext(ctx, conn, contMgrWait, &id, &status); err != nil {
		return 0, err
	}
	return waitStatusExitCode(unix.WaitStatus(status)), nil
}

func waitStatusExitCode(status unix.WaitStatus) int {
	if status.Exited() {
		return status.ExitStatus()
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return int(status)
}

// Delete delegates to runsc delete because that path is upstream's host-side
// cleanup boundary and calls Container.Destroy() internally.
func (c *Client) Delete(ctx context.Context, id string, force bool) error {
	args := append(c.globalArgs(), "delete")
	if force {
		args = append(args, "--force")
	}
	args = append(args, id)

	cmd := exec.CommandContext(ctx, c.Binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if force && isRunscNotFound(output) {
			return nil
		}
		return fmt.Errorf("runsc delete %s failed: %w: %s", id, err, string(output))
	}
	return nil
}

func isRunscNotFound(output []byte) bool {
	return bytes.Contains(output, []byte("does not exist")) || bytes.Contains(output, []byte("not found"))
}

func (c *Client) ListJSON(ctx context.Context) ([]byte, error) {
	args := append(c.globalArgs(), "list", "--format", "json")
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	out, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("runsc list failed: %w", err)
	}
	return out, nil
}

type containerState struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Sandbox struct {
		ID                string `json:"id"`
		ControlSocketPath string `json:"controlSocketPath"`
		Pid               int    `json:"pid"`
	} `json:"sandbox"`
}

func (c *Client) loadState(id string) (*containerState, error) {
	path := c.stateFilePath(id)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var state containerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse runsc state %s: %w", path, err)
	}
	if state.Sandbox.ControlSocketPath == "" {
		return nil, fmt.Errorf("state file %s does not contain sandbox.controlSocketPath", path)
	}
	return &state, nil
}

func (c *Client) stateFilePath(id string) string {
	return filepath.Join(c.RootDir, fmt.Sprintf("%s_sandbox:%s.state", id, id))
}

func (c *Client) markStateRunning(id string) error {
	path := c.stateFilePath(id)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse runsc state %s: %w", path, err)
	}
	raw["status"] = "running"

	out, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("encode runsc state %s: %w", path, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0640
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
