// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

//go:generate bpf2go -cc clang-14 -target bpfel -no-global-types networkacl ../../../bpf/networkacl/prog/networkacl.bpf.c -- -D__TARGET_ARCH_x86 -I ../../../bpf/networkacl/include -I /usr/include -I /usr/include/bpf -I /usr/include/x86_64-linux-gnu -Wall -Werror
