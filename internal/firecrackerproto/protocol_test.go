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

package firecrackerproto

import (
	"bufio"
	"bytes"
	"net"
	"path/filepath"
	"testing"
	"time"
)

type shortWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (writer *shortWriter) Write(data []byte) (int, error) {
	if len(data) > writer.limit {
		data = data[:writer.limit]
	}
	return writer.buffer.Write(data)
}

func TestMessageRoundTripWithShortWrites(t *testing.T) {
	writer := &shortWriter{limit: 2}
	request := ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
		Cwd:     "/tmp",
	}
	if err := WriteMessage(writer, MessageExec, request); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := ReadMessage(&writer.buffer)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != MessageExec {
		t.Fatalf("message type = %d, want %d", messageType, MessageExec)
	}
	var decoded ExecRequest
	if err := Decode(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Command != request.Command ||
		decoded.Cwd != request.Cwd ||
		len(decoded.Args) != 1 ||
		decoded.Args[0] != "hello" {
		t.Fatalf("decoded request = %+v", decoded)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	var request ExecRequest
	if err := Decode([]byte(`{"command":"true","unexpected":1}`), &request); err == nil {
		t.Fatal("Decode accepted an unknown field")
	}
}

func TestFramePayloads(t *testing.T) {
	for _, exitCode := range []int{0, 23, -1} {
		decoded, err := ExitCode(ExitPayload(exitCode))
		if err != nil || decoded != exitCode {
			t.Fatalf("exit code round trip = %d, %v", decoded, err)
		}
	}
	rows, cols, err := Resize(ResizePayload(41, 132))
	if err != nil || rows != 41 || cols != 132 {
		t.Fatalf("resize round trip = %d x %d, %v", rows, cols, err)
	}
	signal, err := Signal(SignalPayload(15))
	if err != nil || signal != 15 {
		t.Fatalf("signal round trip = %d, %v", signal, err)
	}
	if _, err := Signal(SignalPayload(65)); err == nil {
		t.Fatal("accepted an out-of-range signal")
	}
}

func TestWaitResponseRequiresExitCode(t *testing.T) {
	var encoded bytes.Buffer
	if err := WriteMessage(
		&encoded,
		MessageResponse,
		Response{OK: true},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWaitResponse(&encoded); err == nil {
		t.Fatal("accepted a wait response without an exit code")
	}
}

func TestDialAgentHandshake(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		handshake, err := reader.ReadString('\n')
		if err != nil {
			serverResult <- err
			return
		}
		if handshake != "CONNECT 52\n" {
			serverResult <- &testError{value: handshake}
			return
		}
		if _, err := connection.Write([]byte("OK 123\n")); err != nil {
			serverResult <- err
			return
		}
		messageType, _, err := ReadMessage(reader)
		if err == nil && messageType != MessageHealth {
			err = &testError{value: "unexpected message"}
		}
		if err == nil {
			err = WriteMessage(
				connection,
				MessageResponse,
				Response{OK: true},
			)
		}
		serverResult <- err
	}()

	connection, err := DialAgent(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := WriteMessage(connection, MessageHealth, nil); err != nil {
		t.Fatal(err)
	}
	if err := ReadResponse(connection); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

type testError struct {
	value string
}

func (err *testError) Error() string {
	return err.value
}
