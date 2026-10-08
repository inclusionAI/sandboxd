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

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Load only the helpers under test: sourcing the entrypoint would start
// privileged workloads and install its destructive cleanup trap.
func e2eFunctions(t *testing.T, names ...string) string {
	t.Helper()
	data, err := os.ReadFile("e2e-run.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	var result strings.Builder
	for _, name := range names {
		marker := "\n" + name + "() {\n"
		start := strings.Index(source, marker)
		if start < 0 {
			t.Fatalf("function %s not found", name)
		}
		body := source[start+1:]
		end := strings.Index(body, "\n}\n")
		if end < 0 {
			t.Fatalf("function %s has no closing brace", name)
		}
		result.WriteString(body[:end+3])
	}
	return result.String()
}

func runE2EHelper(t *testing.T, script string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", "set -euo pipefail\n"+script)
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("helper timed out: %s", output)
	}
	return string(output), err
}

func TestDirectDNSDependencies(t *testing.T) {
	functions := e2eFunctions(t, "fail", "check_direct_dns_dependencies")
	for _, runtime := range []string{"all", "runsc", "runc"} {
		for _, missing := range []string{"none", "dnsmasq", "timeout"} {
			t.Run(runtime+"/"+missing, func(t *testing.T) {
				script := fmt.Sprintf(`
E2E_RUNTIME=%q
DISABLE_CGROUP=0
MISSING=%q
command() { [ "$1" = -v ] && [ "$2" != "${MISSING}" ]; }
`, runtime, missing) + functions + "check_direct_dns_dependencies\nprintf 'passed\\n'\n"
				output, err := runE2EHelper(t, script)
				if missing == "none" {
					if err != nil || !strings.Contains(output, "passed") {
						t.Fatalf("dependencies available: err=%v, output=%s", err, output)
					}
				} else if err == nil || !strings.Contains(output, "missing command: "+missing) {
					t.Fatalf("missing %s: err=%v, output=%s", missing, err, output)
				}
			})
		}
	}
	for _, tc := range []struct {
		name, runtime, mode string
		disabled            int
	}{
		{"disabled_all", "all", "e2e", 1},
		{"disabled_runsc", "runsc", "e2e", 1},
		{"kata", "kata", "e2e", 0},
		{"firecracker", "firecracker", "e2e", 0},
		{"serve_all", "all", "serve", 0},
		{"serve_runsc", "runsc", "serve", 0},
		{"serve_runc", "runc", "serve", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := fmt.Sprintf(`
E2E_RUNTIME=%q
DISABLE_CGROUP=%d
command() { printf 'unexpected dependency check\n'; return 1; }
`, tc.runtime, tc.disabled) + functions + fmt.Sprintf("check_direct_dns_dependencies %q\nprintf 'passed\\n'\n", tc.mode)
			output, err := runE2EHelper(t, script)
			if err != nil || !strings.Contains(output, "passed") {
				t.Fatalf("fixture not selected: err=%v, output=%s", err, output)
			}
		})
	}
}

func TestStopSandboxd(t *testing.T) {
	functions := e2eFunctions(t, "log", "fail", "stop_sandboxd")
	for _, tc := range []struct {
		name, message, tap                         string
		stopAfter, waitStatus, bridge, links, term int
		forceKill                                  bool
	}{
		{name: "graceful", stopAfter: 1, bridge: 1},
		{name: "failed_exit", bridge: 1, waitStatus: 17, message: "shutdown exited with status 17"},
		{name: "stale_bridge", message: "sandbox bridge remained"},
		{name: "detached_tap", bridge: 1, tap: "7: tap.test: <BROADCAST> mtu 1500", message: "sandbox TAPs remained"},
		{name: "inspection_failed", bridge: 1, links: 1, message: "could not inspect network links"},
		{name: "timeout", stopAfter: 300, bridge: 1, forceKill: true, message: "did not shut down within 30 seconds"},
		{name: "signal_failed", bridge: 1, term: 1, message: "could not stop sandboxd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Every process and network operation is stubbed. No real PID is
			// signalled, and two no-delay iterations cover the bounded wait.
			script := fmt.Sprintf(`
SANDBOXD_PID=12345
BRIDGE_NAME=sandbox0
STOP_AFTER=%d
WAIT_STATUS=%d
BRIDGE_STATUS=%d
LINKS_STATUS=%d
TERM_STATUS=%d
TAP=%q
POLLS=0
EVENTS=""
kill() {
    case "$1" in
        -TERM) EVENTS="${EVENTS} TERM"; return "${TERM_STATUS}" ;;
        -0) POLLS=$((POLLS + 1)); [ "${POLLS}" -le "${STOP_AFTER}" ] ;;
        -KILL) EVENTS="${EVENTS} KILL" ;;
        *) return 99 ;;
    esac
}
wait() { EVENTS="${EVENTS} WAIT"; return "${WAIT_STATUS}"; }
sleep() { :; }
seq() { printf '1\n2\n'; }
ip() {
    if [ "$1" = link ]; then
        return "${BRIDGE_STATUS}"
    fi
    printf '%%s\n' "${TAP}"
    return "${LINKS_STATUS}"
}
trap 'printf "pid=%%s; events=%%s\n" "${SANDBOXD_PID}" "${EVENTS}"' EXIT
`, tc.stopAfter, tc.waitStatus, tc.bridge, tc.links, tc.term, tc.tap) + functions + "stop_sandboxd\nprintf 'passed\\n'\n"
			output, err := runE2EHelper(t, script)
			if tc.message == "" {
				if err != nil || !strings.Contains(output, "passed") {
					t.Fatalf("graceful stop: err=%v, output=%s", err, output)
				}
			} else if err == nil || !strings.Contains(output, tc.message) || strings.Contains(output, "passed") {
				t.Fatalf("want failure %q: err=%v, output=%s", tc.message, err, output)
			}
			if strings.Contains(output, "KILL") != tc.forceKill {
				t.Fatalf("force kill=%v: %s", tc.forceKill, output)
			}
			if tc.term == 0 && !strings.Contains(output, "pid=; events= TERM") {
				t.Fatalf("stopped process must be reaped and forgotten: %s", output)
			}
			if tc.term == 0 && !strings.Contains(output, "WAIT") {
				t.Fatalf("stopped process was not reaped: %s", output)
			}
		})
	}
}
