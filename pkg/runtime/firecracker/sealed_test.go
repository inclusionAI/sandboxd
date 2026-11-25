// SPDX-License-Identifier: Apache-2.0

package firecracker

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSealedCaptureRequiresVMMMappingAndHealthyGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs")
	if err := os.WriteFile(path, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	// File existence is insufficient if the installed VMM ignored the feature.
	if verifySealedMapping(os.Getpid(), path) == nil {
		t.Fatal("accepted unmapped table")
	}
	header, err := sealedHeader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(header)
	if err := verifySealedMapping(os.Getpid(), path); err != nil {
		t.Fatal(err)
	}
	header[0] = 1
	if err := cutSealed(header, 1); err != nil {
		t.Fatal(err)
	}
	if cutSealed(header, 1) == nil || cutSealed(header, 2) == nil {
		t.Fatal("cut a stale or unmerged generation")
	}
	header[4] = 1
	header[8] = 1
	if cutSealed(header, 2) == nil || header[0] != 2 {
		t.Fatal("cut a failed device")
	}
}

func TestSealedDeleteUsesAttemptReceipt(t *testing.T) {
	root := t.TempDir()
	local := t.TempDir()
	h := Handler{sealedScratch: root}
	token := strings.Repeat("ab", 16)
	private := filepath.Join(root, "vm-"+token)
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"/elsewhere\n" + token, root + "\n../other", root + "\n"} {
		if err := os.WriteFile(filepath.Join(local, "sealed-owner"), []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
		if h.cleanSealedScratch(local) == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if err := os.WriteFile(filepath.Join(local, "sealed-owner"), []byte(root+"\n"+token), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.cleanSealedScratch(local); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(private); !os.IsNotExist(err) {
		t.Fatal("private parent survived deletion")
	}
	if err := h.cleanSealedScratch(local); err != nil {
		t.Fatal(err)
	}
}

func TestSealedVMMEnvironmentIsPerRestore(t *testing.T) {
	t.Setenv("FC_SEALED_BLOCK_PATH", "inherited-by-mistake")
	for _, enabled := range []bool{false, true} {
		env := sealedVMMEnv(enabled)
		if slices.Contains(env, "FC_SEALED_BLOCK_PATH=inherited-by-mistake") || slices.Contains(env, "FC_SEALED_BLOCK_PATH=overlay.ext4") != enabled {
			t.Fatal("incorrect drive activation")
		}
	}
}
