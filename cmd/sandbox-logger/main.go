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

// sandbox-logger drains sandbox output through the containerd binary logger ABI.
package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

const (
	defaultLogLimit = int64(64 * 1024 * 1024)
	copyBufferSize  = 32 * 1024
)

type options struct {
	stdout  string
	stderr  string
	maxSize int64
}

func main() {
	stdout := os.NewFile(3, "CONTAINER_STDOUT")
	stderr := os.NewFile(4, "CONTAINER_STDERR")
	ready := os.NewFile(5, "CONTAINER_WAIT")
	if err := run(os.Args[1:], stdout, stderr, ready); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr, ready *os.File) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	stdoutSink, err := openSink(opts.stdout, opts.maxSize)
	if err != nil {
		return fmt.Errorf("open stdout destination: %w", err)
	}
	defer stdoutSink.Close()
	stderrSink, err := openSink(opts.stderr, opts.maxSize)
	if err != nil {
		return fmt.Errorf("open stderr destination: %w", err)
	}
	defer stderrSink.Close()

	if _, err := ready.Write([]byte{1}); err != nil {
		return fmt.Errorf("signal readiness: %w", err)
	}
	if err := ready.Close(); err != nil {
		return fmt.Errorf("close readiness descriptor: %w", err)
	}

	var wait sync.WaitGroup
	wait.Add(2)
	go copyStream(&wait, stdoutSink, stdout)
	go copyStream(&wait, stderrSink, stderr)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-signals:
		_ = stdout.Close()
		_ = stderr.Close()
		<-done
	}
	return nil
}

func parseOptions(args []string) (options, error) {
	opts := options{
		stdout:  os.DevNull,
		stderr:  os.DevNull,
		maxSize: defaultLogLimit,
	}
	if len(args)%2 != 0 {
		return options{}, fmt.Errorf("logger arguments must be key-value pairs")
	}
	for index := 0; index < len(args); index += 2 {
		key, value := args[index], args[index+1]
		switch key {
		case "stdout":
			opts.stdout = value
		case "stderr":
			opts.stderr = value
		case "max-bytes":
			maxSize, err := strconv.ParseInt(value, 10, 64)
			if err != nil || maxSize <= 0 {
				return options{}, fmt.Errorf("invalid max-bytes %q", value)
			}
			opts.maxSize = maxSize
		default:
			return options{}, fmt.Errorf("unknown logger argument %q", key)
		}
	}
	return opts, nil
}

type cappedSink struct {
	file      *os.File
	remaining int64
}

func openSink(path string, maxSize int64) (*cappedSink, error) {
	if path == "" {
		path = os.DevNull
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("log path %q is not absolute", path)
	}
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	remaining := maxSize - info.Size()
	if remaining < 0 {
		remaining = 0
	}
	return &cappedSink{file: file, remaining: remaining}, nil
}

func (s *cappedSink) Write(data []byte) (int, error) {
	if s.remaining <= 0 {
		return len(data), nil
	}
	toWrite := int64(len(data))
	if toWrite > s.remaining {
		toWrite = s.remaining
	}
	written, err := s.file.Write(data[:toWrite])
	s.remaining -= int64(written)
	if err != nil {
		s.remaining = 0
	}
	// Always report the input as consumed. Once the bounded destination is
	// full or unavailable, draining continues without applying backpressure
	// to the sandbox.
	return len(data), nil
}

func (s *cappedSink) Close() error {
	return s.file.Close()
}

func copyStream(wait *sync.WaitGroup, destination io.Writer, source *os.File) {
	defer wait.Done()
	defer source.Close()
	buffer := make([]byte, copyBufferSize)
	_, _ = io.CopyBuffer(destination, source, buffer)
}
