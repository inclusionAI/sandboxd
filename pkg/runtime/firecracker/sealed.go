// SPDX-License-Identifier: Apache-2.0

package firecracker

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

//go:embed sealed_bridge.py
var sealedBridge string

func validateSealedConfig(c config.FirecrackerConfig, runtimeName string) error {
	if c.SealedCheckpointHelper == "" && c.SealedCheckpointScratch == "" {
		return nil
	}
	if runtimeName != config.RuntimeNameFirecracker || c.WritableIOEngine != "Async" || c.WritableCacheType != "Writeback" || c.CheckpointMode != firecrackerCheckpointModeIncremental {
		return errors.New("sealed checkpoints require hardware Firecracker, Async, Writeback and incremental checkpoint mode")
	}
	for _, p := range []string{c.SealedCheckpointHelper, c.SealedCheckpointScratch} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return fmt.Errorf("expected absolute sealed checkpoint path, got %q", p)
		}
	}
	file, err := os.Stat(c.SealedCheckpointHelper)
	if err != nil {
		return err
	}
	if !file.Mode().IsRegular() {
		return errors.New("invalid sealed checkpoint helper")
	}
	info, err := os.Lstat(c.SealedCheckpointScratch)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("sealed_checkpoint_scratch must be a private directory (0700)")
	}
	return nil
}

func sealedVMMEnv(enabled bool) []string {
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "FC_SEALED_BLOCK_PATH=") {
			env = append(env, v)
		}
	}
	if enabled {
		env = append(env, "FC_SEALED_BLOCK_PATH="+firecrackerCheckpointOverlayName)
	}
	return env
}

// The old VMM silently ignores FC_SEALED_BLOCK_PATH. Verify the control mmap
// before releasing any guest vCPU; pathname alone cannot prove file identity.
func verifySealedMapping(pid int, path string) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return err
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[1] != "rw-s" || fields[2] != "00000000" {
			continue
		}
		var major, minor uint32
		if _, err := fmt.Sscanf(fields[3], "%x:%x", &major, &minor); err != nil {
			continue
		}
		ino, err := strconv.ParseUint(fields[4], 10, 64)
		if err == nil && ino == st.Ino && unix.Mkdev(major, minor) == uint64(st.Dev) {
			return nil
		}
	}
	return errors.New("restored VMM has not mapped the sealed drive control file; a matching Firecracker sealed-block build and Async snapshot are required")
}

func (h *Handler) sealedPrivateDir(storage string) (string, error) {
	data, err := os.ReadFile(filepath.Join(storage, "sealed-owner"))
	if err != nil {
		return "", err
	}
	// Never take a removal path from a caller-owned checkpoint or from VM state.
	root, token, ok := strings.Cut(string(data), "\n")
	b, err := hex.DecodeString(token)
	if !ok || root != h.sealedScratch || root == "" || err != nil || len(b) != 16 {
		return "", errors.New("invalid sealed owner or changed shared scratch root")
	}
	return filepath.Join(root, "vm-"+token), nil
}

func (h *Handler) cleanSealedScratch(storage string) error {
	dir, err := h.sealedPrivateDir(storage)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func (h *Handler) sealedBridgeCall(ctx context.Context, action, storage, dir string) (string, error) {
	if h.sealedHelper == "" {
		return "", errors.New("sealed checkpoint helper is required for this running VM")
	}
	scratch, err := h.sealedPrivateDir(storage)
	if err != nil {
		return "", err
	}
	path, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(h.sealedScratch)
	if err != nil {
		return "", err
	}
	if path == root || strings.HasPrefix(path, root+"/") || strings.HasPrefix(root, path+"/") {
		return "", errors.New("checkpoint directory overlaps private sealed storage")
	}
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", sealedBridge, h.sealedHelper, action, filepath.Join(storage, "sealed"), scratch, path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sealed checkpoint %s: %w: %s", action, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func (h *Handler) instantiateSealed(ctx context.Context, a *firecrackerCheckpointArtifact, storage, stateDir string, diskLimit uint64) (firecrackerCheckpointFiles, int64, error) {
	files := a.Files
	var fs unix.Statfs_t
	if err := unix.Statfs(storage, &fs); err != nil {
		return files, 0, err
	}
	if fs.Type != unix.XFS_SUPER_MAGIC {
		return files, 0, errors.New("sealed live storage requires node-local XFS")
	}
	disk, err := os.Stat(files.Overlay)
	if err != nil {
		return files, 0, err
	}
	if disk.Size() <= 0 || uint64(disk.Size()) > diskLimit {
		return files, 0, fmt.Errorf("sealed checkpoint disk size %d exceeds target disk budget %d or is empty", disk.Size(), diskLimit)
	}
	if err := h.digestCache.verifyFirecrackerCheckpointDigests(ctx, a); err != nil {
		return files, 0, err
	}
	if err := checkRestoredMemorySize(a.Manifest.MemorySize); err != nil {
		return files, 0, err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return files, 0, err
	}
	if err := os.WriteFile(filepath.Join(storage, "sealed-owner"), []byte(h.sealedScratch+"\n"+hex.EncodeToString(token[:])), 0600); err != nil {
		return files, 0, err
	}
	if _, err := h.sealedBridgeCall(ctx, "init", storage, filepath.Dir(files.State)); err != nil {
		return files, 0, err
	}
	for _, name := range []string{"epochs", "lower", "upper.2", "upper.3", "merged.0", "merged.1"} {
		if err := os.Symlink(filepath.Join(storage, "sealed", name), filepath.Join(stateDir, name)); err != nil {
			return files, 0, err
		}
	}
	files.Overlay = filepath.Join(storage, firecrackerCheckpointOverlayName)
	if err := os.Symlink(filepath.Join(storage, "sealed", firecrackerCheckpointOverlayName), files.Overlay); err != nil {
		return files, 0, err
	}
	return files, a.Manifest.MemorySize, nil
}

// Map only the header. The reference worker and the VMM use aligned atomic
// u32 words for active generation, committed merge, and sticky drive failure.
func sealedHeader(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < 4096 {
		return nil, errors.New("truncated sealed control header")
	}
	return unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
}

func cutSealed(header []byte, g uint32) error {
	word := func(i int) *uint32 { return (*uint32)(unsafe.Pointer(&header[i])) }
	if g == 0 || g == ^uint32(0) || atomic.LoadUint32(word(4)) != g-1 || atomic.LoadUint32(word(8)) != 0 || !atomic.CompareAndSwapUint32(word(0), g, g+1) {
		return errors.New("sealed checkpoint generation or device error at disk cut")
	}
	return nil
}

func (h *Handler) checkpointSealed(ctx context.Context, c runtimecore.CheckpointConfig, instance *firecrackerInstance, state firecrackerPersistedState, api *firecrackerAPI) (retErr error) {
	if c.SnapshotType != "" && c.SnapshotType != firecrackerSnapshotTypeDiff {
		return fmt.Errorf("sealed drive requires a KVM Diff snapshot, got %q", c.SnapshotType)
	}
	if err := checkFirecrackerCheckpointDirVacant(c.Directory); err != nil {
		return err
	}
	compat, err := h.buildCheckpointCompat(state.Vcpus, false)
	if err != nil {
		return err
	}
	storage := filepath.Dir(state.OverlayPath)
	hdr, err := sealedHeader(filepath.Join(storage, "sealed", "epochs"))
	if err != nil {
		return err
	}
	defer unix.Munmap(hdr)
	h.prepareGuestCheckpoint(ctx, state)
	gen, err := h.sealedBridgeCall(ctx, "prepare", storage, c.Directory)
	if err != nil {
		return err
	}
	g, err := strconv.ParseUint(gen, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid sealed checkpoint generation: %w", err)
	}
	local := filepath.Join(storage, "sealed", "capture-"+gen)
	if err := api.pause(ctx); err != nil {
		return err
	}
	// Preserve the guest checkpoint FIFO's exactly-once release semantics.
	released := false
	defer func() {
		if retErr == nil || released || !firecrackerProcessMatches(state.PID, h.binary, state.APIPath, state.ID) {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), firecrackerAgentTimeout)
		defer cancel()
		if err := api.resume(cleanup); err != nil {
			retErr = errors.Join(retErr, err)
			return
		}
		retErr = errors.Join(retErr, releaseSealedGuest(cleanup, state, "error"))
	}()
	if err := h.withCheckpointSnapshotMemoryCharge(c.CgroupPath, instance, state, func() error {
		return api.createSnapshot(ctx, filepath.Join(local, "vmstate"), filepath.Join(local, "memory"), "", firecrackerSnapshotTypeDiff)
	}); err != nil {
		return err
	}
	if err := cutSealed(hdr, uint32(g)); err != nil {
		return err
	}
	if c.LeaveRunning {
		if err := api.resume(ctx); err != nil {
			return err
		}
		released = true
		if err := releaseSealedGuest(ctx, state, "resume"); err != nil {
			return err
		}
	}
	if _, err := h.sealedBridgeCall(ctx, "finish", storage, c.Directory); err != nil {
		return err
	}
	out := firecrackerCheckpointFiles{
		State:   filepath.Join(c.Directory, firecrackerCheckpointStateName),
		Memory:  filepath.Join(c.Directory, firecrackerCheckpointMemoryName),
		Overlay: filepath.Join(c.Directory, firecrackerCheckpointOverlayName),
	}
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: firecrackerSnapshotTypeDiff,
		MemorySize:   int64(state.MemoryMiB) << 20,
		Compat:       compat,
	}
	if err := finalizeFirecrackerCheckpointV2(ctx, out, manifest); err != nil {
		return err
	}
	if !c.LeaveRunning {
		return h.finishCheckpointedSandbox(instance, state, c.ID)
	}
	return nil
}

func releaseSealedGuest(ctx context.Context, state firecrackerPersistedState, outcome string) error {
	return requestFirecrackerAgent(ctx, state.VsockPath, firecrackerproto.MessageCheckpoint, firecrackerproto.CheckpointRequest{Outcome: outcome, HostTimeUnixNano: time.Now().UnixNano()})
}
