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

package networkmanager

import (
	"time"

	"github.com/inclusionAI/sandboxd/config"
)

// Pool-local constants previously living in pkg/resourcemanager/types.go.
// Moved here so the network pool owns all its plumbing; sandbox.Manager no
// longer holds shared resource-type knowledge.
const (
	defaultIpRange = "10.88.0.1/16"

	BridgeName        = "sandbox0"
	containerEthName  = "eth0"
	ContainerLoopName = "lo"
	bridgeMac         = "02:3f:e1:bd:13:b8"

	// maxVethNum is the max number of veth pair the bridge can host; capped
	// by netlink's per-bridge link limit of 1024.
	maxVethNum = 1000
)

const (
	// shrinkInterval is how often each pool checks whether it holds more idle
	// resources than cacheSize and trims the excess. The periodic timer ONLY
	// shrinks — growth is demand-driven (init fill + on-demand create), never
	// timer-driven.
	shrinkInterval = 30 * time.Second

	// interfaceDestroyPacing throttles veth teardown during shrink. Linux
	// unregisters net devices asynchronously on a workqueue (kworker) that
	// holds the RTNL lock and is not preempted, so deleting many veths
	// back-to-back starves other netlink users — including our own foreground
	// on-demand veth creation. Pacing the (background-only) shrink path
	// protects foreground allocation.
	interfaceDestroyPacing = 20 * time.Millisecond
)

// MaxSandboxLimit returns the single, authoritative ceiling on concurrent
// sandboxes. Every sandbox consumes exactly one cgroup and one network
// interface (1:1), so the cgroup pool, the interface pool and the sandbox
// admission gate must all share this value. It is the configured
// max_instance_num clamped to the per-bridge veth hard limit (maxVethNum),
// since no more sandboxes can run than there are interfaces for them.
func MaxSandboxLimit(maxInstanceNum int) int {
	if maxInstanceNum <= 0 {
		maxInstanceNum = config.DefaultMaxSandboxNum
	}
	return min(maxInstanceNum, maxVethNum)
}
