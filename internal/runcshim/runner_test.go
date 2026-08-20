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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunPersistsStartedFailure(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "fake-runc")
	script := `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--pid-file" ]; then
    shift
    echo $$ > "$1"
  fi
  shift
done
echo fake-runc-failure >&2
exit 17
`
	require.NoError(t, os.WriteFile(binary, []byte(script), 0755))
	bundle := filepath.Join(dir, "bundle")
	require.NoError(t, os.MkdirAll(bundle, 0755))
	stderr := filepath.Join(dir, "stderr.log")

	code := Run(Options{
		Binary: binary,
		Root:   filepath.Join(dir, "state"),
		Bundle: bundle,
		ID:     "sbox-shim-test",
		Stdout: os.DevNull,
		Stderr: stderr,
	})
	assert.Equal(t, 17, code)
	record, err := ReadExit(filepath.Join(bundle, ExitFile))
	require.NoError(t, err)
	assert.True(t, record.Started)
	assert.Equal(t, 17, record.ExitCode)
	assert.Contains(t, record.RuntimeError, "fake-runc-failure")
}

func TestRunRejectsIncompleteOptions(t *testing.T) {
	assert.Equal(t, 125, Run(Options{}))
}
