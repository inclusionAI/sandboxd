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

package config

import "time"

const (
	StopTimeout = 10 * time.Second

	DefaultSocketAddress = "/run/sandboxd/sandboxd.sock"
	DefaultRootDir       = "/home/akernel/sandboxd"
	DefaultTimeout       = time.Second * 10

	DefaultSandboxRootDir = "/home/akernel/sandboxd/root"
	DefaultStoreDir       = "/home/akernel/sandboxd/store"

	DefaultLogDir        = "/var/log/sandboxd"
	DefaultImageLibDir   = "/home/akernel/images"
	DefaultFilestoreDir  = "/home/akernel/filestore"
	DefaultLoopDeviceDir = "/dev"

	DefaultFilestoreOvercommitRatio = 1.0

	DefaultHttpAddress = "127.0.0.1:23001"

	DefaultMaxSandboxNum    = 1000
	DefaultMaxCacheLimitNum = 800

	DefaultCgroupRoot = "/sandbox"

	DefaultIPRange       = "10.88.0.1/16"
	DefaultHostPortStart = 21006
	DefaultHostPortCount = 65535 - DefaultHostPortStart + 1

	DefaultRunscBinary    = "/usr/local/bin/runsc"
	DefaultRuncBinary     = "/usr/local/bin/runc"
	DefaultRuncShimBinary = "/usr/local/bin/runc-shim"
	DefaultRuncStateRoot  = "/run/sandboxd/runc"
	DefaultKataBinary     = "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
	DefaultKataConfig     = "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml"
	DefaultSandboxLogger  = "/usr/local/bin/sandbox-logger"
	DefaultKVMDevice      = "/dev/kvm"

	DefaultKataDANConfigDir = "/run/kata-containers/dans"
)
