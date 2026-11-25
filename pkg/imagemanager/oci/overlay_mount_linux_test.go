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

//go:build linux

package oci

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadonlyOverlayLegacyByteLimit(t *testing.T) {
	const pageSize = 4096
	const prefix = "lowerdir=/top:/"
	for _, tc := range []struct {
		name       string
		legacySize int
		structured bool
	}{
		{name: "last legacy byte", legacySize: pageSize - 1},
		{name: "requires structured options", legacySize: pageSize, structured: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Use UTF-8 to catch character counts masquerading as byte counts.
			paddingBytes := tc.legacySize - len(prefix)
			bottom := "/" + strings.Repeat("界", paddingBytes/len("界")) + strings.Repeat("x", paddingBytes%len("界"))
			lowerDirs := []string{"/top", bottom}
			calls := 0
			legacy := func(target, opts string) error {
				calls++
				if tc.structured || target != "/merged" || opts != prefix+strings.TrimPrefix(bottom, "/") {
					t.Fatalf("unexpected legacy call with %d bytes at %s", len(opts), target)
				}
				return nil
			}
			structured := func(target string, layers []string) error {
				calls++
				if !tc.structured || target != "/merged" || !slices.Equal(layers, lowerDirs) {
					t.Fatalf("unexpected structured call at %s with %d layers", target, len(layers))
				}
				return unix.ENOSYS
			}
			err := mountReadonlyOverlayWith("/merged", lowerDirs, pageSize, legacy, structured, nil)
			if tc.structured {
				if !errors.Is(err, unix.ENOSYS) || !strings.Contains(err.Error(), "4096 bytes, exceeding the legacy mount limit of 4095 bytes") {
					t.Fatalf("expected byte limit and original error, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("got %d mount attempts, want 1", calls)
			}
		})
	}
}

func TestReadonlyOverlayCompactFallback(t *testing.T) {
	const pageSize = 4096
	lowerDirs := []string{"/top", "/" + strings.Repeat("x", pageSize)}
	unsupported := fmt.Errorf("%w: VFS: Legacy: Cumulative options too large: %w", errStructuredOverlayUnavailable, unix.EINVAL)
	tooLarge := errors.New("compact lowerdirs exceed the budget")
	for _, tc := range []struct {
		name        string
		nativeErr   error
		compactErr  error
		wantCompact bool
	}{
		{name: "native succeeds"},
		{name: "permission error", nativeErr: unix.EPERM},
		{name: "attach error", nativeErr: unix.EINVAL},
		{name: "compact legacy mount", nativeErr: unsupported, wantCompact: true},
		{name: "cannot fit", nativeErr: unsupported, compactErr: tooLarge, wantCompact: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const compact = "lowerdir=/a/c2/fs:/a/c1/fs"
			var calls []string
			err := mountReadonlyOverlayWith("/merged", lowerDirs, pageSize,
				func(target, data string) error {
					calls = append(calls, "legacy")
					if target != "/merged" || data != compact {
						t.Fatalf("unexpected compact mount %s with %q", target, data)
					}
					return nil
				},
				func(target string, dirs []string) error {
					calls = append(calls, "native")
					if target != "/merged" || !slices.Equal(dirs, lowerDirs) {
						t.Fatal("structured mount must receive the canonical paths")
					}
					return tc.nativeErr
				},
				func(budget int) (string, error) {
					calls = append(calls, "compact")
					if budget != pageSize-1 {
						t.Fatalf("budget = %d, want %d", budget, pageSize-1)
					}
					return compact, tc.compactErr
				})
			wantCalls := []string{"native"}
			wantErr := tc.nativeErr
			if tc.wantCompact {
				wantCalls = append(wantCalls, "compact")
				if tc.compactErr == nil {
					wantCalls = append(wantCalls, "legacy")
					wantErr = nil
				}
			}
			if !slices.Equal(calls, wantCalls) || !errors.Is(err, wantErr) {
				t.Fatalf("calls = %v, err = %v, want %v and %v", calls, err, wantCalls, wantErr)
			}
			if tc.compactErr != nil &&
				(!errors.Is(err, tc.compactErr) || !strings.Contains(err.Error(), "Cumulative options too large")) {
				t.Fatalf("expected both failures, got %v", err)
			}
		})
	}
}

// Run in a private mount namespace with SANDBOXD_OCI_OVERLAY_MOUNT_TEST=1.
func TestReadonlyOCIOverlayKernelMount(t *testing.T) {
	if os.Getenv("SANDBOXD_OCI_OVERLAY_MOUNT_TEST") != "1" {
		t.Skip("requires explicit opt-in inside a private mount namespace")
	}
	for _, tc := range []struct {
		name       string
		layerCount int
		structured bool
	}{
		{name: "bind", layerCount: 1},
		{name: "legacy", layerCount: 2},
		{name: "structured", structured: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.structured && os.Getpagesize() >= 64*1024 {
				t.Skip("the mountinfo line limit is smaller than the legacy option page on this host")
			}
			work := t.TempDir()
			merged := filepath.Join(work, "merged")
			if err := os.Mkdir(merged, 0755); err != nil {
				t.Fatal(err)
			}
			layerCount := tc.layerCount
			if tc.structured {
				layerCount = os.Getpagesize()/128 + 1
			}
			layers := make([]string, 0, layerCount)
			for i := range layerCount {
				name := fmt.Sprintf("layer-%03d-%s", i, strings.Repeat("x", 128))
				if i == layerCount-1 {
					name += `:,\`
				}
				layer := filepath.Join(work, name)
				if err := os.Mkdir(layer, 0755); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{fmt.Sprintf("marker-%03d", i), "precedence"} {
					if err := os.WriteFile(filepath.Join(layer, name), fmt.Appendf(nil, "%d", i), 0644); err != nil {
						t.Fatal(err)
					}
				}
				layers = append(layers, layer)
			}
			data, err := buildOverlayMountData(layers)
			if err != nil {
				t.Fatal(err)
			}
			if (len(data) >= os.Getpagesize()) != tc.structured {
				t.Fatalf("%d bytes do not select the %s mount path", len(data), tc.name)
			}
			t.Cleanup(func() {
				if err := unmountOverlay(merged); err != nil && !isNotMountedError(err) {
					t.Error(err)
				}
			})
			mgr := &Manager{}
			if err := mgr.mountOverlay(&OciMountTxnRecord{MountPath: merged, LowerDirs: layers}); err != nil {
				t.Fatal(err)
			}
			assertFile := func(name, want string) {
				t.Helper()
				got, err := os.ReadFile(filepath.Join(merged, name))
				if err != nil || string(got) != want {
					t.Fatalf("%s = %q, %v, want %q", name, got, err, want)
				}
			}
			for i := range layers {
				assertFile(fmt.Sprintf("marker-%03d", i), fmt.Sprint(i))
			}
			assertFile("precedence", "0")
			if err := os.WriteFile(filepath.Join(merged, "unexpected-write"), nil, 0644); !errors.Is(err, unix.EROFS) {
				t.Fatalf("write to OCI overlay: %v, want EROFS", err)
			}
			if err := defaultOverlayUnmount(merged); err != nil {
				t.Fatal(err)
			}
			if entries, err := os.ReadDir(merged); err != nil || len(entries) != 0 {
				t.Fatalf("expected empty mountpoint after unmount, got %v, %v", entries, err)
			}
		})
	}
}
