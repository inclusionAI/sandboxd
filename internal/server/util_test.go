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

package server

import (
	"github.com/inclusionAI/sandboxd/config"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
	"testing"
)

func Test_sandboxService_checkRuntime(t *testing.T) {
	type args struct {
		requestRuntime string
	}
	tests := []struct {
		name    string
		options []ServiceOptions
		args    args
		wantErr bool
	}{
		{
			name: "runtime not configured",
			args: args{
				requestRuntime: "nonexistent",
			},
			options: []ServiceOptions{
				SetPluginConfig(config.RuntimeConfig{
					RuntimeBinary: map[string]string{
						"runsc": "/usr/local/bin/runsc",
					},
					BasicSpec:   nil,
					ImageLibDir: "",
				}),
			},
			wantErr: true,
		},
		{
			name: "runtime not build handler",
			args: args{
				requestRuntime: "runsc",
			},
			options: []ServiceOptions{
				SetPluginConfig(config.RuntimeConfig{
					RuntimeBinary: map[string]string{
						"runsc": "/usr/local/bin/runsc",
					},
					BasicSpec:   nil,
					ImageLibDir: "",
				}),
			},
			wantErr: true,
		},
		{
			name: "runtime not configured",
			args: args{
				requestRuntime: "runsc",
			},
			options: []ServiceOptions{
				SetPluginConfig(config.RuntimeConfig{
					RuntimeBinary: map[string]string{
						"runsc": "/usr/local/bin/runsc",
					},
					BasicSpec:   nil,
					ImageLibDir: "",
				}),
				AddHandler("runsc", svc.NewFakeRuntimeHandler()),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := buildServiceWithOptions(tt.options...)
			if err := h.checkRuntime(tt.args.requestRuntime); (err != nil) != tt.wantErr {
				t.Errorf("checkRuntime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type ServiceOptions func(*sandboxService)

func buildServiceWithOptions(opts ...ServiceOptions) *sandboxService {
	svc := &sandboxService{
		config:         config.Config{},
		serviceHandler: cmap.New[svc.RealRuntimeHandler](),
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func SetPluginConfig(runtimeConfig config.RuntimeConfig) ServiceOptions {
	return func(service *sandboxService) {
		service.config.PluginConfig.RuntimeConfig = runtimeConfig
	}
}

func AddHandler(runtime string, handler svc.RealRuntimeHandler) ServiceOptions {
	return func(service *sandboxService) {
		service.serviceHandler.Set(runtime, handler)
	}
}
