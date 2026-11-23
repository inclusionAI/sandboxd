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

package resourcemanager

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestNextRetryInterval(t *testing.T) {
	assert.Equal(t, watchRetryMinInterval, nextRetryInterval(0))
	assert.Equal(t, 2*watchRetryMinInterval, nextRetryInterval(watchRetryMinInterval))
	assert.Equal(t, 32*time.Second, nextRetryInterval(16*time.Second))
	assert.Equal(t, watchRetryMaxInterval, nextRetryInterval(watchRetryMaxInterval))
	assert.Equal(t, watchRetryMaxInterval, nextRetryInterval(2*watchRetryMaxInterval))
}

func TestCalcPodRequestWithInitContainers(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("100m"),
							corev1.ResourceMemory: apiresource.MustParse("128Mi"),
						},
					},
				},
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("200m"),
							corev1.ResourceMemory: apiresource.MustParse("256Mi"),
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("500m"),
							corev1.ResourceMemory: apiresource.MustParse("64Mi"),
						},
					},
				},
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse("150m"),
							corev1.ResourceMemory: apiresource.MustParse("600Mi"),
						},
					},
				},
			},
		},
	}

	req := calcPodRequest(pod)
	assert.Equal(t, int64(500), req.cpuMilli)
	assert.Equal(t, int64(600<<20), req.memBytes)
}

func TestCalcPodRequestIncludesRestartableInitAndOverhead(t *testing.T) {
	restartAlways := corev1.ContainerRestartPolicyAlways
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU:    apiresource.MustParse("500m"),
					corev1.ResourceMemory: apiresource.MustParse("512Mi"),
				}},
			}},
			InitContainers: []corev1.Container{
				{
					RestartPolicy: &restartAlways,
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceCPU:    apiresource.MustParse("200m"),
						corev1.ResourceMemory: apiresource.MustParse("128Mi"),
					}},
				},
				{
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceCPU:    apiresource.MustParse("900m"),
						corev1.ResourceMemory: apiresource.MustParse("1Gi"),
					}},
				},
			},
			Overhead: corev1.ResourceList{
				corev1.ResourceCPU:    apiresource.MustParse("50m"),
				corev1.ResourceMemory: apiresource.MustParse("64Mi"),
			},
		},
	}

	req := calcPodRequest(pod)
	assert.Equal(t, int64(1150), req.cpuMilli)
	assert.Equal(t, int64(1216<<20), req.memBytes)
}

func TestShouldCountPod(t *testing.T) {
	assert.False(t, shouldCountPod(nil, "node-a"))

	running := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "100m", "128Mi")
	assert.True(t, shouldCountPod(running, "node-a"))

	pending := running.DeepCopy()
	pending.Status.Phase = corev1.PodPending
	assert.True(t, shouldCountPod(pending, "node-a"))

	succeeded := running.DeepCopy()
	succeeded.Status.Phase = corev1.PodSucceeded
	assert.False(t, shouldCountPod(succeeded, "node-a"))

	failed := running.DeepCopy()
	failed.Status.Phase = corev1.PodFailed
	assert.False(t, shouldCountPod(failed, "node-a"))

	otherNode := running.DeepCopy()
	otherNode.Spec.NodeName = "node-b"
	assert.False(t, shouldCountPod(otherNode, "node-a"))
}

func TestPodKey(t *testing.T) {
	assert.Equal(t, "", podKey(nil))

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod"}}
	assert.Equal(t, "ns/pod", podKey(pod))
}

func TestMaxInt64(t *testing.T) {
	assert.Equal(t, int64(10), maxInt64(10, 0))
	assert.Equal(t, int64(0), maxInt64(-1, 0))
	assert.Equal(t, int64(3), maxInt64(1, 3))
}

func TestPodRequestMaybeCounted(t *testing.T) {
	mgr := &k8sWatchResourceManager{localNodeName: "node-a"}

	req, ok := mgr.podRequestMaybeCounted(nil)
	assert.False(t, ok)
	assert.Equal(t, podResourceRequest{}, req)

	running := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "250m", "256Mi")
	req, ok = mgr.podRequestMaybeCounted(running)
	assert.True(t, ok)
	assert.Equal(t, int64(250), req.cpuMilli)
	assert.Equal(t, int64(256<<20), req.memBytes)

	succeeded := running.DeepCopy()
	succeeded.Status.Phase = corev1.PodSucceeded
	req, ok = mgr.podRequestMaybeCounted(succeeded)
	assert.False(t, ok)
	assert.Equal(t, podResourceRequest{}, req)
}

func TestK8sWatchResourceManagerUpdateNodeTotal(t *testing.T) {
	mgr := &k8sWatchResourceManager{podRequests: map[string]podResourceRequest{}}
	node := &corev1.Node{
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    apiresource.MustParse("8"),
				corev1.ResourceMemory: apiresource.MustParse("32Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    apiresource.MustParse("7500m"),
				corev1.ResourceMemory: apiresource.MustParse("30Gi"),
			},
		},
	}

	mgr.updateNodeTotal(node)
	cpu, mem, _, _ := mgr.snapshot()
	assert.Equal(t, int64(7500), cpu)
	assert.Equal(t, int64(30<<30), mem)
}

func TestK8sWatchResourceManagerPodLifecycleAffectsAllocated(t *testing.T) {
	mgr := &k8sWatchResourceManager{
		localNodeName: "node-a",
		podRequests:   map[string]podResourceRequest{},
	}

	pod := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "500m", "1Gi")
	mgr.onPodUpdate(pod)
	_, _, allocatedCPU, allocatedMem := mgr.snapshot()
	assert.Equal(t, int64(500), allocatedCPU)
	assert.Equal(t, int64(1<<30), allocatedMem)

	updated := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "900m", "2Gi")
	mgr.onPodUpdate(updated)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(900), allocatedCPU)
	assert.Equal(t, int64(2<<30), allocatedMem)

	mgr.onPodDelete(updated)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(0), allocatedCPU)
	assert.Equal(t, int64(0), allocatedMem)
}

func TestK8sWatchResourceManagerTerminalAndUnboundPodsAreIgnored(t *testing.T) {
	mgr := &k8sWatchResourceManager{
		localNodeName: "node-a",
		podRequests:   map[string]podResourceRequest{},
	}

	pending := newTestPod("default", "pod-a", "node-a", corev1.PodPending, "300m", "512Mi")
	mgr.onPodUpdate(pending)
	_, _, allocatedCPU, allocatedMem := mgr.snapshot()
	assert.Equal(t, int64(300), allocatedCPU)
	assert.Equal(t, int64(512<<20), allocatedMem)

	succeeded := pending.DeepCopy()
	succeeded.Status.Phase = corev1.PodSucceeded
	mgr.onPodUpdate(succeeded)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(0), allocatedCPU)
	assert.Equal(t, int64(0), allocatedMem)

	otherNodePod := newTestPod("default", "pod-b", "node-b", corev1.PodRunning, "700m", "1Gi")
	mgr.onPodUpdate(otherNodePod)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(0), allocatedCPU)
	assert.Equal(t, int64(0), allocatedMem)
}

func TestK8sWatchResourceManagerPodSnapshotUsesCurrentRequests(t *testing.T) {
	mgr := &k8sWatchResourceManager{
		localNodeName: "node-a",
		allocatedCPU:  100,
		allocatedMem:  256 << 20,
		podRequests: map[string]podResourceRequest{
			"default/pod-a": {cpuMilli: 100, memBytes: 256 << 20},
		},
	}

	running := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "700m", "1Gi")
	mgr.onPodUpdate(running)
	_, _, allocatedCPU, allocatedMem := mgr.snapshot()
	assert.Equal(t, int64(700), allocatedCPU)
	assert.Equal(t, int64(1<<30), allocatedMem)
}

func TestK8sWatchResourceManagerWatchEventHandlers(t *testing.T) {
	mgr := &k8sWatchResourceManager{localNodeName: "node-a", podRequests: map[string]podResourceRequest{}}

	node := &corev1.Node{}
	node.ResourceVersion = "11"
	node.Status.Allocatable = corev1.ResourceList{
		corev1.ResourceCPU:    apiresource.MustParse("6"),
		corev1.ResourceMemory: apiresource.MustParse("24Gi"),
	}
	rv, err := mgr.handleNodeEvent(watch.Event{Type: watch.Modified, Object: node})
	assert.NoError(t, err)
	assert.Equal(t, "11", rv)
	cpu, mem, _, _ := mgr.snapshot()
	assert.Equal(t, int64(6000), cpu)
	assert.Equal(t, int64(24<<30), mem)

	rv, err = mgr.handleNodeEvent(watch.Event{Type: watch.Deleted, Object: node})
	assert.NoError(t, err)
	assert.Equal(t, "11", rv)
	cpu, mem, _, _ = mgr.snapshot()
	assert.Equal(t, int64(0), cpu)
	assert.Equal(t, int64(0), mem)

	errStatus := &metav1.Status{Code: 410, Message: "gone"}
	_, err = mgr.handleNodeEvent(watch.Event{Type: watch.Error, Object: errStatus})
	assert.Error(t, err)

	pod := newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "300m", "256Mi")
	pod.ResourceVersion = "21"
	rv, err = mgr.handlePodEvent(watch.Event{Type: watch.Added, Object: pod})
	assert.NoError(t, err)
	assert.Equal(t, "21", rv)
	_, _, allocatedCPU, allocatedMem := mgr.snapshot()
	assert.Equal(t, int64(300), allocatedCPU)
	assert.Equal(t, int64(256<<20), allocatedMem)

	rv, err = mgr.handlePodEvent(watch.Event{Type: watch.Deleted, Object: pod})
	assert.NoError(t, err)
	assert.Equal(t, "21", rv)
	_, _, allocatedCPU, allocatedMem = mgr.snapshot()
	assert.Equal(t, int64(0), allocatedCPU)
	assert.Equal(t, int64(0), allocatedMem)

	_, err = mgr.handlePodEvent(watch.Event{Type: watch.Error, Object: errStatus})
	assert.Error(t, err)
}

func TestK8sWatchResourceManagerGetAvailableResource(t *testing.T) {
	mgr := &k8sWatchResourceManager{
		totalCPU:          4000,
		totalMem:          int64(10 << 30),
		allocatedCPU:      1500,
		allocatedMem:      int64((3 << 30) + (512 << 20)),
		podRequests:       map[string]podResourceRequest{},
		nodeSnapshotReady: true,
		podSnapshotReady:  true,
		nodeWatching:      true,
		podWatching:       true,
	}

	cpu, mem, err := mgr.GetAvailableResource()
	assert.NoError(t, err)
	assert.Equal(t, int64(2500), cpu)
	assert.Equal(t, int64((6<<30)+(512<<20)), mem)

	mgr.allocatedCPU = 5000
	mgr.allocatedMem = int64(12 << 30)
	cpu, mem, err = mgr.GetAvailableResource()
	assert.NoError(t, err)
	assert.Equal(t, int64(0), cpu)
	assert.Equal(t, int64(0), mem)
}

func newTestPod(namespace, name, nodeName string, phase corev1.PodPhase, cpuReq, memReq string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{
				{
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    apiresource.MustParse(cpuReq),
							corev1.ResourceMemory: apiresource.MustParse(memReq),
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{Phase: phase},
	}
}

func newWatchTestManager(t *testing.T) (*k8sWatchResourceManager, *fake.Clientset) {
	t.Helper()
	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.NodeList{
			ListMeta: metav1.ListMeta{ResourceVersion: "10"},
			Items: []corev1.Node{{Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    apiresource.MustParse("4"),
				corev1.ResourceMemory: apiresource.MustParse("10Gi"),
			}}}},
		}, nil
	})
	client.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{
			ListMeta: metav1.ListMeta{ResourceVersion: "20"},
			Items:    []corev1.Pod{*newTestPod("default", "pod-a", "node-a", corev1.PodRunning, "1", "2Gi")},
		}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mgr := &k8sWatchResourceManager{
		client: client, localNodeName: "node-a", ctx: ctx, cancel: cancel,
		podRequests: make(map[string]podResourceRequest),
	}
	return mgr, client
}

func startTestResourceWatch(t *testing.T, mgr *k8sWatchResourceManager, client *fake.Clientset, node bool, version string, watcher watch.Interface) <-chan error {
	t.Helper()
	resource := "pods"
	if node {
		resource = "nodes"
	}
	client.PrependWatchReactor(resource, func(action ktesting.Action) (bool, watch.Interface, error) {
		assert.Equal(t, version, action.(ktesting.WatchAction).GetWatchRestrictions().ResourceVersion)
		return true, watcher, nil
	})
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if node {
			_, err := mgr.watchNodeStream(version)
			result <- err
		} else {
			_, err := mgr.watchPodStream(version)
			result <- err
		}
	}()
	t.Cleanup(func() {
		mgr.cancel()
		watcher.Stop()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("watch did not stop after cancellation")
		}
	})
	require.Eventually(t, func() bool {
		mgr.mu.RLock()
		defer mgr.mu.RUnlock()
		if node {
			return mgr.nodeWatching
		}
		return mgr.podWatching
	}, time.Second, time.Millisecond)
	return result
}

func TestK8sWatchRequiresBothSnapshotsAndLiveStreams(t *testing.T) {
	mgr, client := newWatchTestManager(t)
	_, _, err := mgr.GetAvailableResource()
	require.Error(t, err)
	_, err = mgr.initNodeSnapshot()
	require.NoError(t, err)
	startTestResourceWatch(t, mgr, client, true, "10", watch.NewRaceFreeFake())
	startTestResourceWatch(t, mgr, client, false, "20", watch.NewRaceFreeFake())
	_, _, err = mgr.GetAvailableResource()
	require.Error(t, err, "a live pod stream cannot substitute for the initial pod list")
	_, err = mgr.initPodSnapshot()
	require.NoError(t, err)
	cpu, mem, err := mgr.GetAvailableResource()
	require.NoError(t, err)
	assert.Equal(t, int64(3000), cpu)
	assert.Equal(t, int64(8<<30), mem)
	// No events have arrived. Healthy quiet streams still keep the cache fresh.
	m := &Module{nodeResource: mgr}
	m.lastRefresh.Store(time.Now().Add(-time.Hour).UnixNano())
	m.refreshOnce()
	assert.True(t, m.Healthy())
}

func TestK8sWatchDisconnectsAreReportedIndependently(t *testing.T) {
	for _, node := range []bool{true, false} {
		for _, gone := range []bool{false, true} {
			t.Run(fmt.Sprintf("node=%t/expired=%t", node, gone), func(t *testing.T) {
				mgr, client := newWatchTestManager(t)
				_, err := mgr.initNodeSnapshot()
				require.NoError(t, err)
				_, err = mgr.initPodSnapshot()
				require.NoError(t, err)
				nodeWatch, podWatch := watch.NewRaceFreeFake(), watch.NewRaceFreeFake()
				nodeResult := startTestResourceWatch(t, mgr, client, true, "10", nodeWatch)
				podResult := startTestResourceWatch(t, mgr, client, false, "20", podWatch)
				failedWatch, result := podWatch, podResult
				if node {
					failedWatch, result = nodeWatch, nodeResult
				}
				if gone {
					failedWatch.Error(&metav1.Status{Code: 410, Message: "expired resource version"})
				} else {
					failedWatch.Stop()
				}
				select {
				case err := <-result:
					require.Error(t, err)
				case <-time.After(time.Second):
					t.Fatal("closed or errored watch did not return")
				}
				// Updates to the surviving stream must not mask the failed one.
				mgr.updateNodeTotal(&corev1.Node{Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    apiresource.MustParse("8"),
					corev1.ResourceMemory: apiresource.MustParse("20Gi"),
				}}})
				_, _, err = mgr.GetAvailableResource()
				require.Error(t, err)
			})
		}
	}
}

func TestK8sWatchEstablishmentFailureDoesNotPublishCachedCapacity(t *testing.T) {
	for _, node := range []bool{true, false} {
		t.Run(fmt.Sprintf("node=%t", node), func(t *testing.T) {
			mgr, client := newWatchTestManager(t)
			_, err := mgr.initNodeSnapshot()
			require.NoError(t, err)
			_, err = mgr.initPodSnapshot()
			require.NoError(t, err)
			version := "10"
			if node {
				version = "20"
			}
			startTestResourceWatch(t, mgr, client, !node, version, watch.NewRaceFreeFake())
			client.PrependWatchReactor("*", func(ktesting.Action) (bool, watch.Interface, error) {
				return true, nil, errors.New("API server unavailable")
			})
			if node {
				_, err = mgr.watchNodeStream("10")
			} else {
				_, err = mgr.watchPodStream("20")
			}
			require.Error(t, err)
			_, _, err = mgr.GetAvailableResource()
			require.Error(t, err)
		})
	}
}

func TestK8sWatchLoopRequiresSuccessfulRelistBeforeReconnect(t *testing.T) {
	for _, initialVersion := range []string{"", "expired-version"} {
		t.Run(initialVersion, func(t *testing.T) {
			mgr, _ := newWatchTestManager(t)
			var watchCalls atomic.Int32
			mgr.watchResourceLoop("pod", initialVersion, func() (string, error) {
				mgr.cancel()
				return "", errors.New("API server unavailable")
			}, func(version string) (string, error) {
				watchCalls.Add(1)
				assert.Equal(t, initialVersion, version)
				return version, errors.New("expired resource version")
			})
			if initialVersion == "" {
				assert.Zero(t, watchCalls.Load(), "failed initial list must not start a watch from now")
			} else {
				assert.Equal(t, int32(1), watchCalls.Load(), "failed relist must not reconnect an old cache")
			}
		})
	}
}

func TestK8sWatchStopCancelsQuietStreams(t *testing.T) {
	mgr, client := newWatchTestManager(t)
	client.PrependWatchReactor("*", func(ktesting.Action) (bool, watch.Interface, error) {
		return true, watch.NewRaceFreeFake(), nil
	})
	require.NoError(t, mgr.start())
	require.Eventually(t, func() bool {
		_, _, err := mgr.GetAvailableResource()
		return err == nil
	}, time.Second, time.Millisecond)
	done := make(chan struct{})
	go func() { mgr.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on a quiet stream")
	}
	_, _, err := mgr.GetAvailableResource()
	require.Error(t, err)
}

func TestK8sWatchBacksOffQuickClosuresAfterSuccessfulRelists(t *testing.T) {
	mgr, client := newWatchTestManager(t)
	attempts := make(chan time.Time, 3)
	client.PrependWatchReactor("pods", func(ktesting.Action) (bool, watch.Interface, error) {
		select {
		case attempts <- time.Now():
		case <-mgr.ctx.Done():
		}
		stream := watch.NewRaceFreeFake()
		stream.Stop()
		return true, stream, nil
	})
	mgr.watchWG.Add(1)
	go mgr.watchPodLoop("20")
	t.Cleanup(mgr.Stop)

	var times [3]time.Time
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for i := range times {
		select {
		case times[i] = <-attempts:
		case <-deadline.C:
			t.Fatal("watch did not reconnect after relisting")
		}
	}
	require.GreaterOrEqual(t, times[1].Sub(times[0]), watchRetryMinInterval)
	require.GreaterOrEqual(t, times[2].Sub(times[1]), 2*watchRetryMinInterval)
}
