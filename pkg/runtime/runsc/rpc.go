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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

const maxFiles = 128

type remoteError struct {
	Message string
}

func (r remoteError) Error() string {
	return r.Message
}

type filePayload struct {
	Files []*os.File `json:"-"`
}

func (f *filePayload) filePayload() []*os.File {
	return f.Files
}

func (f *filePayload) setFilePayload(fs []*os.File) {
	f.Files = fs
}

type filePayloader interface {
	filePayload() []*os.File
	setFilePayload([]*os.File)
}

type clientCall struct {
	Method string `json:"method"`
	Arg    any    `json:"arg"`
}

type callResult struct {
	Success bool   `json:"success"`
	Err     string `json:"err"`
	Result  any    `json:"result"`
}

type rpcClient struct {
	mu sync.Mutex
	fd int
}

func connectRPC(path string) (*rpcClient, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &rpcClient{fd: fd}, nil
}

func (c *rpcClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

// Interrupt unblocks an in-flight Call without waiting for Call's serialization
// mutex. The caller still owns Close, which releases the descriptor after the
// blocked syscall has returned.
func (c *rpcClient) Interrupt() error {
	if c.fd < 0 {
		return nil
	}
	err := unix.Shutdown(c.fd, unix.SHUT_RDWR)
	if err == unix.ENOTCONN || err == unix.EINVAL {
		return nil
	}
	return err
}

func (c *rpcClient) Call(method string, arg any, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var files []*os.File
	if fp, ok := arg.(filePayloader); ok {
		files = fp.filePayload()
		if len(files) > maxFiles {
			return fmt.Errorf("too many file descriptors: %d > %d", len(files), maxFiles)
		}
	}

	if err := c.marshal(&clientCall{Method: method, Arg: arg}, files); err != nil {
		return err
	}

	callR := callResult{Result: result}
	newFiles, err := c.unmarshal(&callR)
	if err != nil {
		return fmt.Errorf("urpc method %q failed: %w", method, err)
	}
	if fp, ok := result.(filePayloader); ok {
		fp.setFilePayload(newFiles)
	} else {
		closeAll(newFiles)
	}
	if !callR.Success {
		return remoteError{Message: callR.Err}
	}
	return nil
}

func (c *rpcClient) marshal(v any, files []*os.File) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	var oob []byte
	if len(files) > 0 {
		fds := make([]int, 0, len(files))
		for _, f := range files {
			fds = append(fds, int(f.Fd()))
		}
		oob = unix.UnixRights(fds...)
	}

	n, err := unix.SendmsgN(c.fd, data, oob, nil, 0)
	runtime.KeepAlive(files)
	if err != nil {
		return err
	}
	for n < len(data) {
		written, err := unix.SendmsgN(c.fd, data[n:], nil, nil, 0)
		if err != nil {
			return err
		}
		if written == 0 {
			return fmt.Errorf("short urpc write: wrote %d of %d bytes", n, len(data))
		}
		n += written
	}
	return nil
}

func (c *rpcClient) unmarshal(v any) ([]*os.File, error) {
	firstByte := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(maxFiles*4))
	n, oobn, _, _, err := unix.Recvmsg(c.fd, firstByte, oob, 0)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, io.EOF
	}

	files, err := parseFiles(oob[:oobn])
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(io.MultiReader(bytes.NewReader(firstByte[:n]), fdReader{fd: c.fd}))
	decoder.UseNumber()
	if err := decoder.Decode(v); err != nil {
		closeAll(files)
		return nil, err
	}
	return files, nil
}

type fdReader struct {
	fd int
}

func (r fdReader) Read(p []byte) (int, error) {
	n, err := unix.Read(r.fd, p)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}

func parseFiles(oob []byte) ([]*os.File, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var files []*os.File
	for _, msg := range msgs {
		fds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			closeAll(files)
			return nil, err
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "runsc-urpc-fd"))
		}
	}
	return files, nil
}

func closeAll(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
