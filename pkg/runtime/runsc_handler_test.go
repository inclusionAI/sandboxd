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

package runtime

import (
	"path/filepath"
	"testing"

	"github.com/akernel-dev/sandboxd/config"
	runscapi "github.com/akernel-dev/sandboxd/pkg/runtime/runsc"
	"github.com/stretchr/testify/assert"
)

func TestNewRunscServiceHandlerUsesSharedLogFile(t *testing.T) {
	baseDir := t.TempDir()
	rootDir := filepath.Join(baseDir, "sandboxd", "root")
	handler, err := NewRunscServiceHandler(config.Config{RootDir: rootDir}, "/usr/local/bin/runsc", nil, nil)
	assert.NoError(t, err)

	client, ok := handler.runsc.(*runscapi.Client)
	if !ok {
		t.Fatalf("runsc client has unexpected type %T", handler.runsc)
	}
	assert.Equal(t, filepath.Join(baseDir, "logs", config.RuntimeNameRunsc, "runsc.log"), client.Options.DebugLogPath)
}
