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

package runcshim

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	Binary string
	Root   string
	Bundle string
	ID     string
	Stdout string
	Stderr string
}

func (o Options) Validate() error {
	for name, value := range map[string]string{
		"binary": o.Binary,
		"root":   o.Root,
		"bundle": o.Bundle,
		"id":     o.ID,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	return nil
}

// Run owns the blocking runc process and always attempts to persist its exit.
func Run(options Options) int {
	if err := options.Validate(); err != nil {
		return 125
	}
	exitPath := filepath.Join(options.Bundle, ExitFile)
	initPIDPath := filepath.Join(options.Bundle, InitPIDFile)
	_ = os.Remove(exitPath)
	_ = os.Remove(initPIDPath)

	record := ExitRecord{Version: ExitVersion, ExitCode: 125}
	stdout, err := openLog(options.Stdout)
	if err != nil {
		record.RuntimeError = err.Error()
		return persist(exitPath, record)
	}
	defer stdout.Close()
	stderr, err := openLog(options.Stderr)
	if err != nil {
		record.RuntimeError = err.Error()
		return persist(exitPath, record)
	}
	defer stderr.Close()

	runtimeLog := filepath.Join(options.Bundle, "runc.log")
	cmd := exec.Command(
		options.Binary,
		"--root", options.Root,
		"--log", runtimeLog,
		"run", "--keep",
		"--bundle", options.Bundle,
		"--pid-file", initPIDPath,
		options.ID,
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	record.Started = fileExists(initPIDPath)
	record.ExitedAt = time.Now().UTC()
	if err == nil {
		record.ExitCode = 0
	} else {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			record.ExitCode = exitError.ExitCode()
			record.RuntimeError = failureDetail(options.Stderr, runtimeLog)
		} else {
			record.RuntimeError = err.Error()
		}
	}
	return persist(exitPath, record)
}

func persist(path string, record ExitRecord) int {
	if err := WriteExit(path, record); err != nil {
		return 125
	}
	return record.ExitCode
}

func openLog(path string) (*os.File, error) {
	if path == "" || path == os.DevNull {
		return os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}

func failureDetail(paths ...string) string {
	const maxBytes = 4096
	var details []string
	for _, path := range paths {
		if path == "" || path == os.DevNull {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(data) > maxBytes {
			data = data[len(data)-maxBytes:]
		}
		if detail := strings.TrimSpace(string(data)); detail != "" {
			details = append(details, detail)
		}
	}
	return strings.Join(details, "; ")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
