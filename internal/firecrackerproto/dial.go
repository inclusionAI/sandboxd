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
	"fmt"
	"net"
	"strings"
	"time"
)

// DialAgent connects through Firecracker's host-side vsock UDS and selects the
// well-known agent port. The handshake is read byte-by-byte so no protocol
// bytes can be stranded in a temporary buffered reader.
func DialAgent(path string, timeout time.Duration) (net.Conn, error) {
	connection, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial Firecracker vsock %s: %w", path, err)
	}
	if timeout > 0 {
		_ = connection.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := fmt.Fprintf(connection, "CONNECT %d\n", AgentPort); err != nil {
		connection.Close()
		return nil, fmt.Errorf("write Firecracker vsock handshake: %w", err)
	}
	var response []byte
	var next [1]byte
	terminated := false
	for len(response) < 64 {
		if _, err := connection.Read(next[:]); err != nil {
			connection.Close()
			return nil, fmt.Errorf("read Firecracker vsock handshake: %w", err)
		}
		if next[0] == '\n' {
			terminated = true
			break
		}
		response = append(response, next[0])
	}
	if !terminated || !strings.HasPrefix(string(response), "OK ") {
		connection.Close()
		return nil, fmt.Errorf("Firecracker vsock handshake failed: %q", response)
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, nil
}

func ReadResponse(connection net.Conn) error {
	messageType, payload, err := ReadMessage(connection)
	if err != nil {
		return err
	}
	if messageType != MessageResponse {
		return fmt.Errorf("unexpected Firecracker agent response type %d", messageType)
	}
	var response Response
	if err := Decode(payload, &response); err != nil {
		return err
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "guest agent rejected the request"
		}
		return fmt.Errorf("%s", response.Error)
	}
	return nil
}
