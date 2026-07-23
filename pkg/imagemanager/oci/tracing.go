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

package oci

import (
	"context"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/timedtrace"

	"go.opentelemetry.io/otel/attribute"
)

// OCITimedOperation wraps an OCI operation with tracing metadata.
type OCITimedOperation struct {
	op *timedtrace.Operation
}

// StartOCITimedOperation creates a timed OCI operation span.
func StartOCITimedOperation(ctx context.Context, operation, identifier string) (*OCITimedOperation, context.Context) {
	op, nextCtx := timedtrace.Start(ctx, timedtrace.Config{
		TracerName:      "oci",
		Operation:       operation,
		IdentifierKey:   "identifier",
		IdentifierValue: identifier,
		LogPrefix:       "OCI trace",
		Attributes: []attribute.KeyValue{
			attribute.String("oci.operation", operation),
			attribute.String("oci.identifier", identifier),
		},
	})
	return &OCITimedOperation{op: op}, nextCtx
}

// Stage records a stage duration and emits an event.
func (t *OCITimedOperation) Stage(stageName string, duration time.Duration) {
	t.op.Stage(stageName, duration)
}

// RecordError attaches an error to the span without ending it.
func (t *OCITimedOperation) RecordError(err error) {
	t.op.RecordError(err)
}

// End completes tracing and logs timing summary.
func (t *OCITimedOperation) End() {
	t.op.End()
}
