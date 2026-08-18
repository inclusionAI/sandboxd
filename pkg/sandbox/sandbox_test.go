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
	"encoding/json"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/internal/physicalstate"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"testing"
)

func TestSandbox_EnvValue(t *testing.T) {
	type fields struct {
		Metadata *physicalstate.SandboxMetadata
		Status   StatusStorage
		Spec     *spec.Spec
		PATH     string
	}
	type args struct {
		key string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "test",
			fields: fields{
				Spec: &spec.Spec{
					Process: &spec.Process{
						Env: []string{"a=1", "b=2"},
					},
				},
			},
			args: args{
				key: "a",
			},
			want: "1",
		},
		{
			name: "empty sandbox",
			fields: fields{
				Spec: &spec.Spec{},
			},
			args: args{
				key: "a",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Sandbox{
				Metadata: tt.fields.Metadata,
				Status:   tt.fields.Status,
				Spec:     tt.fields.Spec,
				PATH:     tt.fields.PATH,
			}
			if got := c.EnvValue(tt.args.key); got != tt.want {
				t.Errorf("EnvValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSandbox_ApiStatus(t *testing.T) {
	type fields struct {
		Metadata *physicalstate.SandboxMetadata
		Status   StatusStorage
		Spec     *spec.Spec
		PATH     string
	}
	tests := []struct {
		name   string
		fields fields
		want   *runtime.SandboxStatus
	}{
		{
			name: "test",
			fields: fields{
				Metadata: &physicalstate.SandboxMetadata{
					ID:             "123",
					RuntimeHandler: "runsc",
					Labels: map[string]string{
						"test": "test",
					},
					Stdout: "/root/stdout",
					Stderr: "/root/stderr",
				},
				Status: &statusStorage{
					status: Status{
						Pid:       123,
						StartedAt: "202308201132",
					},
				},
				Spec: &spec.Spec{
					Process: &spec.Process{
						Args: []string{"a", "b"},
						Env:  []string{"a=1", "b=2"},
					},
				},
				PATH: "/root",
			},
			want: &runtime.SandboxStatus{
				ID:        "123",
				Command:   []string{"a", "b"},
				Runtime:   "runsc",
				Stdout:    "/root/stdout",
				Stderr:    "/root/stderr",
				ExitCode:  0,
				StartedAt: 202308201132,
				Labels: map[string]string{
					"test": "test",
				},
				Mounts: []*runtime.Mount{},
				State:  runtime.SandboxState_SANDBOX_STATE_RUNNING,
				Envs: []*runtime.KeyValue{
					{
						Key:   "a",
						Value: "1",
					},
					{
						Key:   "b",
						Value: "2",
					},
				},
			},
		},
		{
			name: "test for empty status",
			fields: fields{
				Metadata: &physicalstate.SandboxMetadata{
					ID:             "123",
					RuntimeHandler: "runsc",
					Labels: map[string]string{
						"test": "test",
					},
					Stdout: "/root/stdout",
					Stderr: "/root/stderr",
				},
				Status: nil,
				Spec: &spec.Spec{
					Process: &spec.Process{
						Args: []string{"a", "b"},
						Env:  []string{"a=1", "b=2"},
					},
				},
				PATH: "/root",
			},
			want: &runtime.SandboxStatus{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Sandbox{
				Metadata: tt.fields.Metadata,
				Status:   tt.fields.Status,
				Spec:     tt.fields.Spec,
				PATH:     tt.fields.PATH,
			}
			// compare the fields of the struct by json.Marshal
			got := c.ApiStatus()
			b1, e1 := json.Marshal(got)
			b2, e2 := json.Marshal(tt.want)
			if e1 != nil || e2 != nil {
				t.Errorf("ApiStatus() error = %v, wantErr %v", e1, e2)
			}
			if string(b1) != string(b2) {
				t.Errorf("ApiStatus() = %v\nwant %v", string(b1), string(b2))
			}
		})
	}
}
