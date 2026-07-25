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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseOptions(t *testing.T) {
	opts, err := parseOptions([]string{
		"stderr", "/tmp/stderr.log",
		"stdout", "/tmp/stdout.log",
		"max-bytes", "1024",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.stdout != "/tmp/stdout.log" ||
		opts.stderr != "/tmp/stderr.log" ||
		opts.maxSize != 1024 {
		t.Fatalf("options = %+v", opts)
	}
}

func TestCappedSinkDrainsAfterLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout.log")
	sink, err := openSink(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	if written, err := sink.Write([]byte("abcdefgh")); err != nil || written != 8 {
		t.Fatalf("first write = %d, %v", written, err)
	}
	if written, err := sink.Write([]byte("ijk")); err != nil || written != 3 {
		t.Fatalf("second write = %d, %v", written, err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "abcde" {
		t.Fatalf("log = %q, want %q", data, "abcde")
	}
}

func TestRunImplementsBinaryLoggerABI(t *testing.T) {
	stdoutPath := filepath.Join(t.TempDir(), "stdout.log")
	stderrPath := filepath.Join(t.TempDir(), "stderr.log")
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		result <- run([]string{
			"stderr", stderrPath,
			"stdout", stdoutPath,
			"max-bytes", "1024",
		}, stdoutReader, stderrReader, readyWriter)
	}()

	ready := make([]byte, 1)
	if _, err := readyReader.Read(ready); err != nil {
		t.Fatalf("read readiness: %v", err)
	}
	if ready[0] != 1 {
		t.Fatalf("readiness = %d, want 1", ready[0])
	}
	_ = readyReader.Close()
	if _, err := stdoutWriter.Write([]byte("stdout data\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := stderrWriter.Write([]byte("stderr data\n")); err != nil {
		t.Fatal(err)
	}
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()

	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("logger did not stop after both streams reached EOF")
	}
	if data, err := os.ReadFile(stdoutPath); err != nil || string(data) != "stdout data\n" {
		t.Fatalf("stdout = %q, %v", data, err)
	}
	if data, err := os.ReadFile(stderrPath); err != nil || string(data) != "stderr data\n" {
		t.Fatalf("stderr = %q, %v", data, err)
	}
}
