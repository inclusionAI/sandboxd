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
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

type options struct {
	action                   string
	socket                   string
	runtime                  string
	rootfs                   string
	sandboxID                string
	targetID                 string
	requestFile              string
	checkpointDir            string
	timeout                  time.Duration
	checkpointTimeoutSeconds uint
	memoryMB                 float64
	cpu                      int
	storageMB                uint64
	extraConfig              string
	compress                 bool
	leaveRunning             bool
	snapshotType             string
	workloadCmd              string
}

func main() {
	var value options
	flag.StringVar(&value.action, "action", "", "start, checkpoint, restore, or delete")
	flag.StringVar(&value.socket, "socket", "", "sandboxd Unix socket")
	flag.StringVar(&value.runtime, "runtime", "runsc", "runtime handler")
	flag.StringVar(&value.rootfs, "rootfs", "", "local rootfs path")
	flag.StringVar(&value.sandboxID, "sandbox-id", "", "source sandbox ID")
	flag.StringVar(&value.targetID, "target-id", "", "restored sandbox ID")
	flag.StringVar(&value.requestFile, "request-file", "", "persisted StartRequest JSON")
	flag.StringVar(&value.checkpointDir, "checkpoint-dir", "", "caller-owned checkpoint directory")
	flag.DurationVar(&value.timeout, "timeout", 5*time.Minute, "client operation timeout")
	flag.UintVar(
		&value.checkpointTimeoutSeconds,
		"checkpoint-timeout-seconds",
		180,
		"sandboxd checkpoint timeout in seconds",
	)
	flag.Float64Var(&value.memoryMB, "memory-mb", 128, "sandbox memory in MiB")
	flag.IntVar(&value.cpu, "cpu", 500, "CPU quota (milli-CPU)")
	flag.Uint64Var(&value.storageMB, "storage-mb", 64, "writable layer in MiB")
	flag.StringVar(&value.extraConfig, "extra-config", "",
		"runtime-specific configuration as a JSON object")
	flag.BoolVar(&value.compress, "compress", true, "compress checkpoint artifacts")
	flag.BoolVar(&value.leaveRunning, "leave-running", true, "leave source running")
	flag.StringVar(&value.snapshotType, "snapshot-type", "",
		"checkpoint flavor: empty (auto), Full, Incremental, or SoftDirty")
	flag.StringVar(&value.workloadCmd, "workload-cmd", "",
		"override the built-in start workload command (template warmup hooks)")
	flag.Parse()

	if err := run(value); err != nil {
		fmt.Fprintf(os.Stderr, "checkpoint-restore: %v\n", err)
		os.Exit(1)
	}
}

func run(value options) error {
	if value.socket == "" {
		return errors.New("--socket is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), value.timeout)
	defer cancel()
	connection, err := grpc.DialContext(
		ctx,
		"passthrough:///sandboxd",
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", value.socket)
		}),
	)
	if err != nil {
		return err
	}
	defer connection.Close()
	client := runtime.NewSandboxServiceClient(connection)

	switch value.action {
	case "start":
		return start(ctx, client, value)
	case "checkpoint":
		return checkpoint(ctx, client, value)
	case "restore":
		return restore(ctx, client, value)
	case "delete":
		return deleteSandbox(ctx, client, value)
	default:
		return errors.New("--action must be start, checkpoint, restore, or delete")
	}
}

func start(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.rootfs == "" || value.sandboxID == "" {
		return errors.New("--rootfs and --sandbox-id are required for start")
	}
	if value.requestFile == "" {
		return errors.New("--request-file is required for start")
	}
	if value.storageMB > ^uint64(0)/(1024*1024) {
		return errors.New("--storage-mb overflows bytes")
	}
	request := &runtime.StartRequest{
		SandboxID: value.sandboxID,
		Runtime:   value.runtime,
		Rootfs: &runtime.RootfsConfig{
			Type: runtime.RootfsSrcType_LOCAL,
			Source: &runtime.RootfsConfig_Path{
				Path: value.rootfs,
			},
		},
		Command: []string{
			"/bin/sh",
			"-c",
			workloadCommand(value.workloadCmd),
		},
		Cwd:     "/",
		Network: "sandbox",
		Stdout:  "/var/log/sandboxd/checkpoint-workload.stdout",
		Stderr:  "/var/log/sandboxd/checkpoint-runtime.stderr",
		Resources: map[string]float64{
			"CPU":    float64(value.cpu),
			"Memory": value.memoryMB,
		},
		WritableLayerLimitBytes: value.storageMB * 1024 * 1024,
		ExtraConfig:             value.extraConfig,
	}
	data, err := protojson.MarshalOptions{
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(request)
	if err != nil {
		return err
	}
	if err := os.WriteFile(value.requestFile, append(data, '\n'), 0600); err != nil {
		return err
	}
	response, err := client.Start(ctx, request)
	if err != nil {
		return err
	}
	if response.Code != 0 || response.ID != value.sandboxID {
		return fmt.Errorf("start response = %+v", response)
	}
	fmt.Println(response.ID)
	return nil
}

// workloadCommand returns the guest workload for a start: an explicit hook
// overrides the built-in regression workload. Hook authors keep full control
// but must keep the sandbox alive — end with an idle loop.
func workloadCommand(hook string) string {
	if hook != "" {
		return hook
	}
	return "if [ -e /var/checkpoint-started ]; then " +
		"echo restarted > /var/checkpoint-restarted; fi; " +
		"echo started > /var/checkpoint-started; " +
		// The anonymous 100MiB blob gives the dirty-page ledgers a
		// substantial first window; the fsyncs land the marker files
		// on the writable layer, where a sealed artifact can read
		// them back with debugfs (the guest page cache is otherwise
		// still unflushed at snapshot pause time).
		"dd if=/dev/zero of=/tmp/blob bs=1M count=100 conv=fsync 2>/dev/null; sync; " +
		"counter=0; while :; do counter=$((counter + 1)); " +
		"echo \"$counter\" > /var/checkpoint-counter; sync; sleep 0.1; done"
}

func checkpoint(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.sandboxID == "" || value.checkpointDir == "" {
		return errors.New("--sandbox-id and --checkpoint-dir are required for checkpoint")
	}
	if value.checkpointTimeoutSeconds == 0 || value.checkpointTimeoutSeconds > uint(^uint32(0)) {
		return errors.New("--checkpoint-timeout-seconds must fit in a non-zero uint32")
	}
	_, err := client.Checkpoint(ctx, &runtime.CheckpointRequest{
		ID:             value.sandboxID,
		CheckpointDir:  value.checkpointDir,
		TimeoutSeconds: uint32(value.checkpointTimeoutSeconds),
		Compress:       value.compress,
		LeaveRunning:   value.leaveRunning,
		SnapshotType:   value.snapshotType,
	})
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	return nil
}

func restore(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.targetID == "" || value.checkpointDir == "" {
		return errors.New("--target-id and --checkpoint-dir are required for restore")
	}
	if value.requestFile == "" {
		return errors.New("--request-file is required for restore")
	}
	data, err := os.ReadFile(value.requestFile)
	if err != nil {
		return err
	}
	request := new(runtime.StartRequest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, request); err != nil {
		return err
	}
	request.SandboxID = value.targetID
	request.CheckpointInfo = &runtime.CheckpointInfo{
		CheckpointDir: value.checkpointDir,
	}
	response, err := client.Start(ctx, request)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if response.Code != 0 || response.ID != value.targetID {
		return fmt.Errorf("restore response = %+v", response)
	}
	fmt.Println(response.ID)
	return nil
}

// deleteSandbox releases a sandbox through the normal Delete RPC, cleaning
// its runtime state and writable layer — the acceptance counterpart to
// checkpoint/restore (previously only reachable through the sbox CLI).
func deleteSandbox(
	ctx context.Context,
	client runtime.SandboxServiceClient,
	value options,
) error {
	if value.sandboxID == "" {
		return errors.New("--sandbox-id is required for delete")
	}
	if _, err := client.Delete(ctx, &runtime.DeleteRequest{
		ID: value.sandboxID,
	}); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}
