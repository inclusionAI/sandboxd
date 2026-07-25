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

package sandbox

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
)

func TestGenerateStatusFromState(t *testing.T) {
	type args struct {
		state *svc.UnionSandboxState
		path  string
	}
	tests := []struct {
		name string
		args args
		want Status
	}{
		{
			name: "test",
			args: args{
				state: &svc.UnionSandboxState{
					ID:             "",
					InitProcessPid: 100,
					Status:         "running",
					Bundle:         "",
					Created:        "2023-08-28 16:34:07.878055688 +0800 CST m=+0.008551102",
				},
				path: "/tmp",
			},
			want: Status{
				Pid:        100,
				StartedAt:  "2023-08-28 16:34:07.878055688 +0800 CST m=+0.008551102",
				FinishedAt: "",
				ExitCode:   0,
				Unknown:    false,
				Resources:  nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenerateStatusFromState(tt.args.state, tt.args.path).Get(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateStatusFromState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateSync(t *testing.T) {
	const NewPid = 456
	const SuccessKey = "success"

	sandboxRoot := t.TempDir()
	ss := statusStorage{
		path: filepath.Join(sandboxRoot, config.SandboxStatusFile),
		status: Status{
			Pid:       123,
			StartedAt: "202308201132",
		},
	}

	// No change no update
	err := ss.UpdateSync(func(s Status) (Status, error) {
		return s, nil
	})
	assert.NoError(t, err)

	// Has changes, got status file
	err = ss.UpdateSync(func(s Status) (Status, error) {
		s.Pid = NewPid
		// Mocked WriteFile needs this key so we can get the success result
		s.FinishedAt = SuccessKey
		return s, nil
	})

	assert.NoError(t, err)
	assert.Equal(t, ss.status.Pid, NewPid)
	assert.Equal(t, ss.status.FinishedAt, SuccessKey)
}

func TestStatusEncodeDecodeOOMKilled(t *testing.T) {
	original := Status{
		Pid:        7,
		StartedAt:  "2026-05-08T00:00:00Z",
		FinishedAt: "2026-05-08T00:00:42Z",
		ExitCode:   137,
		OOMKilled:  true,
	}
	data, err := original.encode()
	assert.NoError(t, err)

	var decoded Status
	assert.NoError(t, decoded.decode(data))
	assert.True(t, decoded.OOMKilled, "OOMKilled should round-trip")
	assert.Equal(t, original.ExitCode, decoded.ExitCode)
	assert.Equal(t, original.FinishedAt, decoded.FinishedAt)

	// Backwards compatibility: a status file written without oom_killed
	// must decode with OOMKilled defaulting to false (omitempty).
	legacy := []byte(`{"Version":"v1","Pid":1,"StartedAt":"x","FinishedAt":"y","ExitCode":0}`)
	var fromLegacy Status
	assert.NoError(t, fromLegacy.decode(legacy))
	assert.False(t, fromLegacy.OOMKilled)

	// And a Status that was not OOM-killed must omit the field on the
	// wire so we don't bloat existing checkpoints.
	noOOM := Status{Pid: 1, StartedAt: "x", FinishedAt: "y"}
	noOOMData, err := noOOM.encode()
	assert.NoError(t, err)
	assert.NotContains(t, string(noOOMData), "oom_killed")
}

func TestStatusEqualConsidersOOMKilled(t *testing.T) {
	a := Status{Pid: 1, StartedAt: "s", FinishedAt: "f", OOMKilled: true}
	b := a
	assert.True(t, a.Equal(b))
	b.OOMKilled = false
	assert.False(t, a.Equal(b), "Equal must distinguish OOMKilled to avoid skipping disk writes")
}
