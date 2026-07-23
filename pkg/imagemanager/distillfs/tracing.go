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

package distillfs

import (
	"context"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/timedtrace"

	"go.opentelemetry.io/otel/attribute"
)

// TimedOperation wraps an operation with tracing and logs timing on completion
type TimedOperation struct {
	op *timedtrace.Operation
}

// StartTimedOperation creates a new timed operation with tracing from context
func StartTimedOperation(ctx context.Context, operation string, daemonID string) (*TimedOperation, context.Context) {
	op, nextCtx := timedtrace.Start(ctx, timedtrace.Config{
		TracerName:      "distillfs",
		Operation:       operation,
		IdentifierKey:   "daemon",
		IdentifierValue: daemonID,
		LogPrefix:       "distillfs trace",
		Attributes: []attribute.KeyValue{
			attribute.String("daemon.id", daemonID),
			attribute.String("operation", operation),
		},
	})
	return &TimedOperation{op: op}, nextCtx
}

// Stage records a stage timing and creates a span event
func (t *TimedOperation) Stage(stageName string, duration time.Duration) {
	t.op.Stage(stageName, duration)
}

// End completes the operation and logs all timing information
func (t *TimedOperation) End() {
	t.op.End()
}

// Fail marks the operation as failed with an error
func (t *TimedOperation) Fail(err error) {
	t.op.Fail(err)
}
