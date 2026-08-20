// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package server

import (
	"context"

	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// managedCheckpointHandler is a server-private optional runtime capability.
// General runtime consumers only depend on runtime.Handler.
type managedCheckpointHandler interface {
	Checkpoint(context.Context, string, string, bool) error
	Restore(context.Context, svc.StartConfig, string) error
}
