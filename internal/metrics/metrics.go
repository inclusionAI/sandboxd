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

package metrics

import "github.com/prometheus/client_golang/prometheus"

// register metrics
func init() {
	prometheus.MustRegister(ActionLatencyMsHis)
	prometheus.MustRegister(ActionResultCounter)
	prometheus.MustRegister(ResourceGauge)
	prometheus.MustRegister(RuntimeCallResultCounter)
	prometheus.MustRegister(GcQueueLengthGauge)
}

var (
	ActionLatencyMsHis = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "sandbox",
			Subsystem: "internal",
			Name:      "sandbox_action_latency_ms_his",
			Help:      "Sandbox action latency in milliseconds",
			Buckets:   []float64{100, 1000, 5000, 10000, 30000, 60000},
		},
		[]string{"action"},
	)

	ActionResultCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sandbox",
			Subsystem: "internal",
			Name:      "sandbox_action_success_counter",
			Help:      "Sandbox action success counter",
		},
		[]string{"action", "result"},
	)

	ResourceGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "sandbox",
			Subsystem: "internal",
			Name:      "sandbox_resource_gauge",
			Help:      "Sandbox resource gauge, including network endpoints, cgroups, and sandboxes.",
		},
		[]string{"type"},
	)

	RuntimeCallResultCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sandbox",
			Subsystem: "internal",
			Name:      "sandbox_runtime_call_result_counter",
			Help:      "Sandbox runtime call result counter",
		},
		[]string{"action", "result", "runtime"},
	)

	GcQueueLengthGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "sandbox",
			Subsystem: "internal",
			Name:      "gc_queue_len",
		},
		[]string{"type"},
	)
)

func RecordActionLatencyMs(stage string, cost int64) {
	ActionLatencyMsHis.WithLabelValues(stage).Observe(float64(cost))
}

func RecordActionResult(action string, result string) {
	ActionResultCounter.WithLabelValues(action, result).Inc()
}

func RecordResourceGauge(resourceType string, value float64) {
	ResourceGauge.WithLabelValues(resourceType).Set(value)
}

func RecordRuntimeCallResult(action string, result string, runtime string) {
	RuntimeCallResultCounter.WithLabelValues(action, result, runtime).Inc()
}

func RecordGcQueueLength(resourceType string, value float64) {
	GcQueueLengthGauge.WithLabelValues(resourceType).Set(value)
}
