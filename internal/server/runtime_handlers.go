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
	"os"
	"path/filepath"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/runtime/firecracker"
	"github.com/inclusionAI/sandboxd/pkg/runtime/kata"
	"github.com/inclusionAI/sandboxd/pkg/runtime/runc"
	"github.com/inclusionAI/sandboxd/pkg/runtime/runsc"
)

func newRuntimeHandler(
	cfg config.Config,
	binary,
	runtimeName string,
) (runtimecore.Handler, error) {
	if _, err := os.Stat(binary); err != nil {
		return nil, err
	}

	sandboxRoot := filepath.Join(cfg.RootDir, "containers")
	switch runtimeName {
	case config.RuntimeNameRunsc:
		loader, err := newRuntimeBundleLoader(cfg, runtimeName, sandboxRoot)
		if err != nil {
			return nil, err
		}
		return runsc.NewHandler(cfg, binary, loader)
	case config.RuntimeNameKata:
		loader, err := runtimecore.NewBundleLoader("", sandboxRoot)
		if err != nil {
			return nil, err
		}
		return kata.NewHandler(cfg, binary, loader)
	case config.RuntimeNameRunc:
		loader, err := newRuntimeBundleLoader(cfg, runtimeName, sandboxRoot)
		if err != nil {
			return nil, err
		}
		return runc.NewHandler(cfg, binary, loader)
	case config.RuntimeNameFirecracker, config.RuntimeNameFirecrackerPVM:
		loader, err := newRuntimeBundleLoader(cfg, runtimeName, sandboxRoot)
		if err != nil {
			return nil, err
		}
		return firecracker.NewHandlerForRuntime(cfg, binary, loader, runtimeName)
	default:
		return nil, errord.ErrNotImplemented
	}
}

func newRuntimeBundleLoader(
	cfg config.Config,
	runtimeName,
	sandboxRoot string,
) (*runtimecore.BundleLoader, error) {
	baseSpec := ""
	if cfg.RuntimeConfig.BasicSpec != nil {
		baseSpec = cfg.RuntimeConfig.BasicSpec[runtimeName]
	}
	return runtimecore.NewBundleLoader(baseSpec, sandboxRoot)
}
