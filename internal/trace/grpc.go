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

package trace

import (
	"context"
	"strings"
	"time"

	"github.com/inclusionAI/sandboxd/internal/metrics"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func InjectTraceInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// get trace id from context
	traceID, ok := ctx.Value(ContextKeyTraceId).(string)
	if !ok {
		traceID = GetTraceIdFromContext(ctx).String()
		ctx = context.WithValue(ctx, ContextKeyTraceId, traceID)
	}
	logrus.WithField(ContextKeyTraceId, traceID).Debugf("received %s request, raw-request:[%+v]", info.FullMethod, req)
	start := time.Now()
	resp, err := handler(ctx, req)
	cost := time.Since(start)
	metrics.RecordActionLatencyMs(nameOfMethod(info.FullMethod), cost.Milliseconds())
	if err != nil {
		metrics.RecordActionResult(nameOfMethod(info.FullMethod), "failed")
	} else {
		metrics.RecordActionResult(nameOfMethod(info.FullMethod), "success")
	}
	return resp, err
}

func nameOfMethod(fullMethod string) string {
	// fullMethod is in format "/package.Service/Method"
	// we only need the "Method" part
	return fullMethod[strings.LastIndex(fullMethod, "/")+1:]
}
