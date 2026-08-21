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
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"github.com/urfave/cli"
)

func TestFirecrackerAgentSocket(t *testing.T) {
	got := firecrackerAgentSocket("/run/sandboxd/containers", "sbox-test")
	want := firecrackerproto.HostAgentSocket(
		firecrackerproto.HostRuntimeRoot,
		"sbox-test",
	)
	if got != want {
		t.Fatalf("agent socket = %q, want %q", got, want)
	}
}

func TestRunFirecrackerExecStream(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverResult := make(chan error, 1)
	go func() {
		frameType, payload, err := firecrackerproto.ReadFrame(server)
		if err == nil &&
			(frameType != firecrackerproto.FrameData ||
				string(payload) != "guest input") {
			err = errors.New("unexpected input frame")
		}
		if err == nil {
			frameType, _, err = firecrackerproto.ReadFrame(server)
			if err == nil && frameType != firecrackerproto.FrameEOF {
				err = errors.New("missing input EOF")
			}
		}
		if err == nil {
			err = firecrackerproto.WriteFrame(
				server,
				firecrackerproto.FrameData,
				[]byte("stdout"),
			)
		}
		if err == nil {
			err = firecrackerproto.WriteFrame(
				server,
				firecrackerproto.FrameStderr,
				[]byte("stderr"),
			)
		}
		if err == nil {
			err = firecrackerproto.WriteFrame(
				server,
				firecrackerproto.FrameExit,
				firecrackerproto.ExitPayload(23),
			)
		}
		serverResult <- err
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := runFirecrackerExecStream(
		client,
		bytes.NewBufferString("guest input"),
		&stdout,
		&stderr,
		false,
	)
	var exitCoder cli.ExitCoder
	if !errors.As(err, &exitCoder) || exitCoder.ExitCode() != 23 {
		t.Fatalf("exec error = %v, want exit code 23", err)
	}
	if stdout.String() != "stdout" || stderr.String() != "stderr" {
		t.Fatalf("output = %q, %q", stdout.String(), stderr.String())
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
