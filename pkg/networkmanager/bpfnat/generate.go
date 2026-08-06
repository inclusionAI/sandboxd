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

package bpfnat

// bpf2go is pinned by go.mod. The project generation target supplies the
// pinned Clang and system UAPI headers in tools/bpf.Dockerfile.
//go:generate bpf2go -cc clang-14 -target bpfel -no-global-types bpfnat_legacy ../../../bpf/bpfnat/prog/bpfnat.bpf.c -- -DNO_INLINE -D__TARGET_ARCH_x86 -I ../../../bpf/bpfnat/include -I ../../../bpf/bpfnat/lib -I /usr/include -I /usr/include/bpf -I /usr/include/x86_64-linux-gnu -Wall -Werror
//go:generate bpf2go -cc clang-14 -target bpfel -no-global-types bpfnat_timer ../../../bpf/bpfnat/prog/bpfnat.bpf.c -- -DNO_INLINE -DBPF_TIMER_ENABLED -D__TARGET_ARCH_x86 -I ../../../bpf/bpfnat/include -I ../../../bpf/bpfnat/lib -I /usr/include -I /usr/include/bpf -I /usr/include/x86_64-linux-gnu -Wall -Werror
