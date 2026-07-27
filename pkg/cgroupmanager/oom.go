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

package cgroupmanager

// oomWatcher owns the kernel subscriptions for every cgroup managed by one
// CgroupManager. Add and Remove follow the physical cgroup lifetime, while
// Reset clears the observation when a cgroup is returned to the idle cache.
type oomWatcher interface {
	Add(name string) error
	Remove(name string)
	Reset(name string) error
	OOMKilled(name string) (bool, error)
	Close() error
}
