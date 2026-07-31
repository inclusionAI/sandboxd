// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

// LocalhostHostsFileContent is the default /etc/hosts content for sandboxes.
// OCI images rely on the runtime to provide this file; without it localhost
// resolution can fall through to external DNS. Runtimes that bind-mount a
// per-sandbox hosts file and rootfs preparation that materializes a missing
// /etc/hosts must both use this single source.
const LocalhostHostsFileContent = `127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
`
