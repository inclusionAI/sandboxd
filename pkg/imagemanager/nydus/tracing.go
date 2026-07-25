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

package nydus

import (
	"context"
	"time"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/timedtrace"

	"go.opentelemetry.io/otel/attribute"
)

// NydusTimedOperation wraps a Nydus operation with tracing
type NydusTimedOperation struct {
	op *timedtrace.Operation
}

// StartNydusTimedOperation creates a new timed Nydus operation with tracing
func StartNydusTimedOperation(ctx context.Context, operation string, imageURL string) (*NydusTimedOperation, context.Context) {
	op, nextCtx := timedtrace.Start(ctx, timedtrace.Config{
		TracerName:      "nydus",
		Operation:       operation,
		IdentifierKey:   "image_url",
		IdentifierValue: imageURL,
		LogPrefix:       "Nydus trace",
		Attributes: []attribute.KeyValue{
			attribute.String("nydus.operation", operation),
			attribute.String("nydus.image_url", imageURL),
		},
	})
	return &NydusTimedOperation{op: op}, nextCtx
}

// Stage records a stage timing and creates a span event
func (t *NydusTimedOperation) Stage(stageName string, duration time.Duration) {
	t.op.Stage(stageName, duration)
}

// End completes the operation and logs all timing information
func (t *NydusTimedOperation) End() {
	t.op.End()
}

// Fail marks the operation as failed with an error
func (t *NydusTimedOperation) Fail(err error) {
	t.op.Fail(err)
}
