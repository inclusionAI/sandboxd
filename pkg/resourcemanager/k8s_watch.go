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
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

const (
	watchRetryMinInterval  = time.Second
	watchRetryMaxInterval  = time.Minute
	snapshotRequestTimeout = 10 * time.Second
	watchRequestTimeout    = time.Minute
)

var errWatchClosed = errors.New("watch channel closed")

type k8sWatchResourceManager struct {
	client        kubernetes.Interface
	localNodeName string
	ctx           context.Context
	cancel        context.CancelFunc
	stopOnce      sync.Once
	watchWG       sync.WaitGroup

	mu sync.RWMutex

	totalCPU     int64
	totalMem     int64
	allocatedCPU int64
	allocatedMem int64
	podRequests  map[string]podResourceRequest

	// A watch can be quiet indefinitely without making its snapshot stale.
	// Track complete snapshots and live streams separately from event times.
	// Disconnected streams must not make repeated cache reads look fresh.
	nodeSnapshotReady bool
	podSnapshotReady  bool
	nodeWatching      bool
	podWatching       bool
}

type podResourceRequest struct {
	cpuMilli int64
	memBytes int64
}

func newK8sWatchResourceManager() (*k8sWatchResourceManager, error) {
	nodeClt, err := newNodeK8sClient()
	if err != nil {
		return nil, fmt.Errorf("failed to build node k8s client: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &k8sWatchResourceManager{
		client:        nodeClt.client,
		localNodeName: nodeClt.localNodeName,
		ctx:           ctx,
		cancel:        cancel,
		podRequests:   make(map[string]podResourceRequest),
	}
	if err := mgr.start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start k8s watch resource manager: %w", err)
	}
	return mgr, nil
}

func (mgr *k8sWatchResourceManager) start() error {
	nodeResourceVersion := ""
	if rv, err := mgr.initNodeSnapshot(); err != nil {
		logrus.Warningf("failed to init node snapshot, will retry in background: %v", err)
	} else {
		nodeResourceVersion = rv
	}

	podResourceVersion := ""
	if rv, err := mgr.initPodSnapshot(); err != nil {
		logrus.Warningf("failed to init pod snapshot, will retry in background: %v", err)
	} else {
		podResourceVersion = rv
	}

	mgr.watchWG.Add(2)
	go mgr.watchNodeLoop(nodeResourceVersion)
	go mgr.watchPodLoop(podResourceVersion)
	return nil
}

// Stop terminates the Kubernetes watches and waits for their retry loops to
// exit. It is safe to call more than once.
func (mgr *k8sWatchResourceManager) Stop() {
	mgr.stopOnce.Do(func() {
		if mgr.cancel != nil {
			mgr.cancel()
		}
	})
	mgr.watchWG.Wait()
}

func (mgr *k8sWatchResourceManager) requestContext() context.Context {
	if mgr.ctx != nil {
		return mgr.ctx
	}
	return context.Background()
}

func (mgr *k8sWatchResourceManager) stopped() bool {
	return mgr.ctx != nil && mgr.ctx.Err() != nil
}

func (mgr *k8sWatchResourceManager) initNodeSnapshot() (string, error) {
	ctx, cancel := context.WithTimeout(mgr.requestContext(), snapshotRequestTimeout)
	defer cancel()
	nodeList, err := mgr.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", mgr.localNodeName).String(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to list current node %s: %w", mgr.localNodeName, err)
	}
	if len(nodeList.Items) == 0 {
		return "", fmt.Errorf("node %s not found", mgr.localNodeName)
	}
	if nodeList.ResourceVersion == "" {
		return "", fmt.Errorf("node snapshot has no resource version")
	}
	node := &nodeList.Items[0]
	mgr.updateNodeTotal(node)
	mgr.mu.Lock()
	mgr.nodeSnapshotReady = true
	mgr.mu.Unlock()
	return nodeList.ResourceVersion, nil
}

func (mgr *k8sWatchResourceManager) initPodSnapshot() (string, error) {
	ctx, cancel := context.WithTimeout(mgr.requestContext(), snapshotRequestTimeout)
	defer cancel()
	podList, err := mgr.client.CoreV1().Pods(corev1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", mgr.localNodeName).String(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to list pods on node %s: %w", mgr.localNodeName, err)
	}
	if podList.ResourceVersion == "" {
		return "", fmt.Errorf("pod snapshot has no resource version")
	}
	podRequests := make(map[string]podResourceRequest, len(podList.Items))
	allocatedCPU := int64(0)
	allocatedMem := int64(0)
	for i := range podList.Items {
		pod := &podList.Items[i]
		if !shouldCountPod(pod, mgr.localNodeName) {
			continue
		}
		req := calcPodRequest(pod)
		podRequests[podKey(pod)] = req
		allocatedCPU += req.cpuMilli
		allocatedMem += req.memBytes
	}
	mgr.mu.Lock()
	mgr.podRequests = podRequests
	mgr.allocatedCPU = allocatedCPU
	mgr.allocatedMem = allocatedMem
	mgr.podSnapshotReady = true
	mgr.mu.Unlock()
	return podList.ResourceVersion, nil
}

func nextRetryInterval(current time.Duration) time.Duration {
	if current <= 0 {
		return watchRetryMinInterval
	}
	next := current * 2
	if next > watchRetryMaxInterval {
		return watchRetryMaxInterval
	}
	return next
}

func (mgr *k8sWatchResourceManager) waitForRetry(interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-mgr.requestContext().Done():
		return false
	}
}

func (mgr *k8sWatchResourceManager) watchNodeLoop(resourceVersion string) {
	defer mgr.watchWG.Done()
	mgr.watchResourceLoop("node", resourceVersion, mgr.initNodeSnapshot, mgr.watchNodeStream)
}

func (mgr *k8sWatchResourceManager) watchPodLoop(resourceVersion string) {
	defer mgr.watchWG.Done()
	mgr.watchResourceLoop("pod", resourceVersion, mgr.initPodSnapshot, mgr.watchPodStream)
}

// Every new stream follows a complete snapshot. In particular, never start a
// watch from "now" after a failed initial list, or treat reconnecting after an
// expired resource version as proof that an incomplete old cache is valid.
func (mgr *k8sWatchResourceManager) watchResourceLoop(
	name, resourceVersion string,
	initSnapshot func() (string, error),
	watchStream func(string) (string, error),
) {
	retryInterval := watchRetryMinInterval
	for {
		if mgr.stopped() {
			return
		}
		if resourceVersion == "" {
			var err error
			resourceVersion, err = initSnapshot()
			if err != nil {
				logrus.Warningf("failed to refresh %s snapshot: %v", name, err)
				if !mgr.waitForRetry(retryInterval) {
					return
				}
				retryInterval = nextRetryInterval(retryInterval)
				continue
			}
		}
		retryInterval = watchRetryMinInterval
		_, err := watchStream(resourceVersion)
		resourceVersion = ""
		if mgr.stopped() {
			return
		}
		if errors.Is(err, errWatchClosed) || errors.Is(err, context.DeadlineExceeded) {
			logrus.Debugf("%s watch renewing: %v", name, err)
		} else if err != nil {
			logrus.Warningf("%s watch loop exited: %v", name, err)
		}
		if !mgr.waitForRetry(retryInterval) {
			return
		}
	}
}

func (mgr *k8sWatchResourceManager) watchNodeStream(resourceVersion string) (string, error) {
	ctx, cancel := context.WithTimeout(mgr.requestContext(), watchRequestTimeout)
	defer cancel()
	timeoutSeconds := int64(watchRequestTimeout / time.Second)
	watcher, err := mgr.client.CoreV1().Nodes().Watch(ctx, metav1.ListOptions{
		FieldSelector:       fields.OneTermEqualSelector("metadata.name", mgr.localNodeName).String(),
		ResourceVersion:     resourceVersion,
		AllowWatchBookmarks: true,
		TimeoutSeconds:      &timeoutSeconds,
	})
	if err != nil {
		return resourceVersion, fmt.Errorf("failed to watch node %s: %w", mgr.localNodeName, err)
	}
	defer watcher.Stop()
	mgr.setWatching(true, true)
	defer mgr.setWatching(true, false)

	currentResourceVersion := resourceVersion
	for {
		var event watch.Event
		select {
		case <-ctx.Done():
			return currentResourceVersion, ctx.Err()
		case next, ok := <-watcher.ResultChan():
			if !ok {
				return currentResourceVersion, fmt.Errorf("node %w", errWatchClosed)
			}
			event = next
		}
		nextResourceVersion, eventErr := mgr.handleNodeEvent(event)
		if nextResourceVersion != "" {
			currentResourceVersion = nextResourceVersion
		}
		if eventErr != nil {
			return currentResourceVersion, eventErr
		}
	}
}

func (mgr *k8sWatchResourceManager) watchPodStream(resourceVersion string) (string, error) {
	ctx, cancel := context.WithTimeout(mgr.requestContext(), watchRequestTimeout)
	defer cancel()
	timeoutSeconds := int64(watchRequestTimeout / time.Second)
	watcher, err := mgr.client.CoreV1().Pods(corev1.NamespaceAll).Watch(ctx, metav1.ListOptions{
		FieldSelector:       fields.OneTermEqualSelector("spec.nodeName", mgr.localNodeName).String(),
		ResourceVersion:     resourceVersion,
		AllowWatchBookmarks: true,
		TimeoutSeconds:      &timeoutSeconds,
	})
	if err != nil {
		return resourceVersion, fmt.Errorf("failed to watch pods on node %s: %w", mgr.localNodeName, err)
	}
	defer watcher.Stop()
	mgr.setWatching(false, true)
	defer mgr.setWatching(false, false)

	currentResourceVersion := resourceVersion
	for {
		var event watch.Event
		select {
		case <-ctx.Done():
			return currentResourceVersion, ctx.Err()
		case next, ok := <-watcher.ResultChan():
			if !ok {
				return currentResourceVersion, fmt.Errorf("pod %w", errWatchClosed)
			}
			event = next
		}
		nextResourceVersion, eventErr := mgr.handlePodEvent(event)
		if nextResourceVersion != "" {
			currentResourceVersion = nextResourceVersion
		}
		if eventErr != nil {
			return currentResourceVersion, eventErr
		}
	}
}

func (mgr *k8sWatchResourceManager) setWatching(node, watching bool) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if node {
		mgr.nodeWatching = watching
	} else {
		mgr.podWatching = watching
	}
}

func (mgr *k8sWatchResourceManager) handleNodeEvent(event watch.Event) (string, error) {
	switch event.Type {
	case watch.Added, watch.Modified:
		node, ok := event.Object.(*corev1.Node)
		if !ok {
			return "", nil
		}
		mgr.updateNodeTotal(node)
		return node.ResourceVersion, nil
	case watch.Deleted:
		node, ok := event.Object.(*corev1.Node)
		if !ok {
			return "", nil
		}
		mgr.clearNodeTotal()
		return node.ResourceVersion, nil
	case watch.Bookmark:
		node, ok := event.Object.(*corev1.Node)
		if !ok {
			return "", nil
		}
		return node.ResourceVersion, nil
	case watch.Error:
		if status, ok := event.Object.(*metav1.Status); ok {
			return "", fmt.Errorf("node watch error: code=%d, message=%s", status.Code, status.Message)
		}
		return "", fmt.Errorf("node watch received error event")
	default:
		return "", nil
	}
}

func (mgr *k8sWatchResourceManager) handlePodEvent(event watch.Event) (string, error) {
	switch event.Type {
	case watch.Added, watch.Modified:
		pod, ok := event.Object.(*corev1.Pod)
		if !ok {
			return "", nil
		}
		mgr.onPodUpdate(pod)
		return pod.ResourceVersion, nil
	case watch.Deleted:
		pod, ok := event.Object.(*corev1.Pod)
		if !ok {
			return "", nil
		}
		mgr.onPodDelete(pod)
		return pod.ResourceVersion, nil
	case watch.Bookmark:
		pod, ok := event.Object.(*corev1.Pod)
		if !ok {
			return "", nil
		}
		return pod.ResourceVersion, nil
	case watch.Error:
		if status, ok := event.Object.(*metav1.Status); ok {
			return "", fmt.Errorf("pod watch error: code=%d, message=%s", status.Code, status.Message)
		}
		return "", fmt.Errorf("pod watch received error event")
	default:
		return "", nil
	}
}

func (mgr *k8sWatchResourceManager) onPodUpdate(pod *corev1.Pod) {
	if pod == nil {
		return
	}
	key := podKey(pod)
	newReq, newCount := mgr.podRequestMaybeCounted(pod)

	mgr.mu.Lock()
	oldReq, oldCount := mgr.podRequests[key]
	if newCount {
		mgr.podRequests[key] = newReq
	} else {
		delete(mgr.podRequests, key)
	}
	if oldCount {
		mgr.allocatedCPU -= oldReq.cpuMilli
		mgr.allocatedMem -= oldReq.memBytes
	}
	if newCount {
		mgr.allocatedCPU += newReq.cpuMilli
		mgr.allocatedMem += newReq.memBytes
	}
	mgr.mu.Unlock()
}

func (mgr *k8sWatchResourceManager) onPodDelete(pod *corev1.Pod) {
	if pod == nil {
		return
	}
	key := podKey(pod)
	mgr.mu.Lock()
	req, ok := mgr.podRequests[key]
	if ok {
		mgr.allocatedCPU -= req.cpuMilli
		mgr.allocatedMem -= req.memBytes
		delete(mgr.podRequests, key)
	}
	mgr.mu.Unlock()
}

func (mgr *k8sWatchResourceManager) podRequestMaybeCounted(pod *corev1.Pod) (podResourceRequest, bool) {
	if pod == nil {
		return podResourceRequest{}, false
	}
	if !shouldCountPod(pod, mgr.localNodeName) {
		return podResourceRequest{}, false
	}
	return calcPodRequest(pod), true
}

func shouldCountPod(pod *corev1.Pod, localNodeName string) bool {
	if pod == nil {
		return false
	}
	if pod.Spec.NodeName != localNodeName {
		return false
	}
	switch pod.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return false
	default:
		return true
	}
}

func calcPodRequest(pod *corev1.Pod) podResourceRequest {
	if pod == nil {
		return podResourceRequest{}
	}
	cpuMilli := int64(0)
	memBytes := int64(0)
	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		cpuMilli += container.Resources.Requests.Cpu().MilliValue()
		memBytes += container.Resources.Requests.Memory().Value()
	}
	restartableInitCPU := int64(0)
	restartableInitMem := int64(0)
	maxInitCPU := int64(0)
	maxInitMem := int64(0)
	for i := range pod.Spec.InitContainers {
		container := &pod.Spec.InitContainers[i]
		cpu := container.Resources.Requests.Cpu().MilliValue()
		mem := container.Resources.Requests.Memory().Value()
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			restartableInitCPU += cpu
			restartableInitMem += mem
			cpuMilli += cpu
			memBytes += mem
			cpu = restartableInitCPU
			mem = restartableInitMem
		} else {
			cpu += restartableInitCPU
			mem += restartableInitMem
		}
		if cpu > maxInitCPU {
			maxInitCPU = cpu
		}
		if mem > maxInitMem {
			maxInitMem = mem
		}
	}
	if maxInitCPU > cpuMilli {
		cpuMilli = maxInitCPU
	}
	if maxInitMem > memBytes {
		memBytes = maxInitMem
	}
	cpuMilli += pod.Spec.Overhead.Cpu().MilliValue()
	memBytes += pod.Spec.Overhead.Memory().Value()
	return podResourceRequest{cpuMilli: cpuMilli, memBytes: memBytes}
}

func podKey(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	return pod.Namespace + "/" + pod.Name
}

func (mgr *k8sWatchResourceManager) updateNodeTotal(node *corev1.Node) {
	if node == nil {
		return
	}
	cpuMilli := node.Status.Allocatable.Cpu().MilliValue()
	memBytes := node.Status.Allocatable.Memory().Value()
	mgr.mu.Lock()
	mgr.totalCPU = cpuMilli
	mgr.totalMem = memBytes
	mgr.mu.Unlock()
}

func (mgr *k8sWatchResourceManager) clearNodeTotal() {
	mgr.mu.Lock()
	mgr.totalCPU = 0
	mgr.totalMem = 0
	mgr.mu.Unlock()
}

func (mgr *k8sWatchResourceManager) snapshot() (int64, int64, int64, int64) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.totalCPU, mgr.totalMem, mgr.allocatedCPU, mgr.allocatedMem
}

func maxInt64(v int64, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}

func (mgr *k8sWatchResourceManager) GetAvailableResource() (int64, int64, error) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	if !mgr.nodeSnapshotReady || !mgr.podSnapshotReady ||
		!mgr.nodeWatching || !mgr.podWatching {
		return 0, 0, fmt.Errorf("kubernetes resource cache is not synchronized with both watches")
	}
	totalCPU, totalMem := mgr.totalCPU, mgr.totalMem
	allocatedCPU, allocatedMem := mgr.allocatedCPU, mgr.allocatedMem
	cpuMilli := maxInt64(totalCPU-allocatedCPU, 0)
	memBytes := maxInt64(totalMem-allocatedMem, 0)
	logrus.Infof("report k8s watch resource info: total(cpu: %d, mem: %d), allocated(cpu: %d, mem: %d), available(cpu: %d, mem: %d)",
		totalCPU, totalMem, allocatedCPU, allocatedMem, cpuMilli, memBytes)
	return cpuMilli, memBytes, nil
}
