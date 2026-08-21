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

// Package firecrackerproto defines the versioned host-to-guest protocol used
// by the Firecracker runtime. It deliberately depends only on the standard
// library so the same types can be linked into the static guest PID 1.
package firecrackerproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version   = uint16(1)
	AgentPort = uint32(52)

	maxMessageSize = 16 << 20
	maxFrameSize   = 16 << 20
)

var messageMagic = [4]byte{'A', 'K', 'F', 'C'}

type MessageType uint16

const (
	MessageHealth    MessageType = 1
	MessageConfigure MessageType = 2
	MessageShutdown  MessageType = 3
	MessageExec      MessageType = 4
	MessageExecTTY   MessageType = 5
	MessageWait      MessageType = 6
	MessageResponse  MessageType = 100
)

type Response struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

type ProcessSpec struct {
	Args           []string `json:"args"`
	Env            []string `json:"env,omitempty"`
	Cwd            string   `json:"cwd,omitempty"`
	UID            uint32   `json:"uid,omitempty"`
	GID            uint32   `json:"gid,omitempty"`
	AdditionalGIDs []uint32 `json:"additional_gids,omitempty"`
}

type NetworkSpec struct {
	Interface string `json:"interface"`
	MAC       string `json:"mac"`
	Address   string `json:"address"`
	Netmask   string `json:"netmask"`
	Gateway   string `json:"gateway"`
}

type MountSpec struct {
	Device  string   `json:"device"`
	Target  string   `json:"target"`
	FSType  string   `json:"fs_type"`
	Options []string `json:"options,omitempty"`
}

type FileSpec struct {
	Target   string `json:"target"`
	Content  []byte `json:"content"`
	Mode     uint32 `json:"mode"`
	Readonly bool   `json:"readonly,omitempty"`
}

type ConfigureRequest struct {
	Hostname      string      `json:"hostname"`
	RootDevice    string      `json:"root_device"`
	OverlayDevice string      `json:"overlay_device"`
	RootReadonly  bool        `json:"root_readonly,omitempty"`
	Process       ProcessSpec `json:"process"`
	Network       NetworkSpec `json:"network"`
	Mounts        []MountSpec `json:"mounts,omitempty"`
	Files         []FileSpec  `json:"files,omitempty"`
}

type ExecRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env,omitempty"`
	Cwd     string   `json:"cwd,omitempty"`
	User    string   `json:"user,omitempty"`
	Rows    uint16   `json:"rows,omitempty"`
	Cols    uint16   `json:"cols,omitempty"`
}

func WriteMessage(w io.Writer, messageType MessageType, value any) error {
	var payload []byte
	var err error
	if value != nil {
		payload, err = json.Marshal(value)
		if err != nil {
			return fmt.Errorf("marshal Firecracker message: %w", err)
		}
	}
	if len(payload) > maxMessageSize {
		return fmt.Errorf("Firecracker message is too large: %d", len(payload))
	}
	var header [12]byte
	copy(header[:4], messageMagic[:])
	binary.BigEndian.PutUint16(header[4:6], Version)
	binary.BigEndian.PutUint16(header[6:8], uint16(messageType))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func ReadMessage(r io.Reader) (MessageType, []byte, error) {
	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(header[:4], messageMagic[:]) {
		return 0, nil, errors.New("invalid Firecracker protocol magic")
	}
	version := binary.BigEndian.Uint16(header[4:6])
	if version != Version {
		return 0, nil, fmt.Errorf(
			"unsupported Firecracker protocol version %d (want %d)",
			version,
			Version,
		)
	}
	size := binary.BigEndian.Uint32(header[8:12])
	if size > maxMessageSize {
		return 0, nil, fmt.Errorf("Firecracker message is too large: %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return MessageType(binary.BigEndian.Uint16(header[6:8])), payload, nil
}

func Decode(payload []byte, value any) error {
	if len(payload) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode Firecracker message: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode Firecracker message: trailing JSON value")
		}
		return fmt.Errorf("decode Firecracker message trailer: %w", err)
	}
	return nil
}

func ReadWaitResponse(connection io.Reader) (int, error) {
	messageType, payload, err := ReadMessage(connection)
	if err != nil {
		return 0, err
	}
	if messageType != MessageResponse {
		return 0, fmt.Errorf(
			"unexpected Firecracker agent response type %d",
			messageType,
		)
	}
	var response Response
	if err := Decode(payload, &response); err != nil {
		return 0, err
	}
	if !response.OK {
		return 0, errors.New(response.Error)
	}
	if response.ExitCode == nil {
		return 0, errors.New("Firecracker wait response has no exit code")
	}
	return *response.ExitCode, nil
}

type FrameType byte

const (
	FrameData   FrameType = 0
	FrameResize FrameType = 1
	FrameExit   FrameType = 2
	FrameStderr FrameType = 3
	FrameEOF    FrameType = 4
	FrameSignal FrameType = 5
)

func WriteFrame(w io.Writer, frameType FrameType, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("Firecracker stream frame is too large: %d", len(payload))
	}
	var header [5]byte
	header[0] = byte(frameType)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func ReadFrame(r io.Reader) (FrameType, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	frameType := FrameType(header[0])
	switch frameType {
	case FrameData, FrameResize, FrameExit, FrameStderr, FrameEOF, FrameSignal:
	default:
		return 0, nil, fmt.Errorf("unknown Firecracker stream frame %d", frameType)
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size > maxFrameSize {
		return 0, nil, fmt.Errorf("Firecracker stream frame is too large: %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return frameType, payload, nil
}

func ExitPayload(exitCode int) []byte {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], uint32(int32(exitCode)))
	return payload[:]
}

func ExitCode(payload []byte) (int, error) {
	if len(payload) != 4 {
		return 0, fmt.Errorf("invalid exit frame payload length %d", len(payload))
	}
	return int(int32(binary.BigEndian.Uint32(payload))), nil
}

func ResizePayload(rows, cols uint16) []byte {
	var payload [4]byte
	binary.BigEndian.PutUint16(payload[:2], rows)
	binary.BigEndian.PutUint16(payload[2:], cols)
	return payload[:]
}

func Resize(payload []byte) (uint16, uint16, error) {
	if len(payload) != 4 {
		return 0, 0, fmt.Errorf("invalid resize frame payload length %d", len(payload))
	}
	return binary.BigEndian.Uint16(payload[:2]), binary.BigEndian.Uint16(payload[2:]), nil
}

func SignalPayload(signal int) []byte {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], uint32(signal))
	return payload[:]
}

func Signal(payload []byte) (int, error) {
	if len(payload) != 4 {
		return 0, fmt.Errorf("invalid signal frame payload length %d", len(payload))
	}
	signal := int(binary.BigEndian.Uint32(payload))
	if signal <= 0 || signal > 64 {
		return 0, fmt.Errorf("invalid signal number %d", signal)
	}
	return signal, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := w.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
