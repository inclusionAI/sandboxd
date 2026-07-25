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

package api

import (
	"context"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/timedtrace"

	"go.opentelemetry.io/otel/attribute"
)

// APITimedOperation wraps an API operation with tracing
type APITimedOperation struct {
	op *timedtrace.Operation
}

// StartAPITimedOperation creates a new timed API operation with tracing
func StartAPITimedOperation(ctx context.Context, operation string, identifier string) (*APITimedOperation, context.Context) {
	op, nextCtx := timedtrace.Start(ctx, timedtrace.Config{
		TracerName:      "api",
		Operation:       operation,
		IdentifierKey:   "identifier",
		IdentifierValue: identifier,
		LogPrefix:       "API trace",
		Attributes: []attribute.KeyValue{
			attribute.String("api.operation", operation),
			attribute.String("api.identifier", identifier),
		},
	})
	return &APITimedOperation{op: op}, nextCtx
}

// Stage records a stage timing and creates a span event
func (t *APITimedOperation) Stage(stageName string, duration time.Duration) {
	t.op.Stage(stageName, duration)
}

// End completes the operation and logs all timing information
func (t *APITimedOperation) End() {
	t.op.End()
}

// Fail marks the operation as failed with an error
func (t *APITimedOperation) Fail(err error) {
	t.op.Fail(err)
}
