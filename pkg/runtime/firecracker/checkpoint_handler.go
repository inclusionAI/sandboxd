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

package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
	"github.com/sirupsen/logrus"
)

// Checkpoint writes a v2 checkpoint directory owned by the caller and keeps
// the incremental lineage alive across generations:
//
//   - tier 1: a base from a previous checkpoint in the same Firecracker
//     process — reflink-clone it and let a SoftDirty snapshot patch the pages
//     of the current window into the clone;
//   - tier 2: a base from the last restore — clone it and use the pagemap
//     (Incremental) ledger, which is the baseline a restored process tracks;
//   - tier 3: no usable base — preallocate a zero memory file and take a
//     first SoftDirty window.
//
// The recorded base only advances to a memory image the running Firecracker
// actually produced (mirroring the fork's ack semantics), so a failed
// generation never leaves a stale base that a later window could be patched
// into incorrectly.
func (handler *Handler) Checkpoint(
	ctx context.Context,
	config runtimecore.CheckpointConfig,
) (retErr error) {
	sandboxID := config.ID
	tStarted := time.Now()
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		return err
	}
	instance.operationMu.Lock()
	defer instance.operationMu.Unlock()
	state := instance.snapshot()
	if state.Exited || !state.Configured ||
		!firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		return fmt.Errorf("Firecracker sandbox %s is not running", sandboxID)
	}

	api := newFirecrackerAPI(state.APIPath)
	requestedType, err := resolveRequestedSnapshotType(
		handler.checkpointMode, config.SnapshotType,
	)
	if err != nil {
		return fmt.Errorf("Firecracker sandbox %s: %w", sandboxID, err)
	}
	snapshotType, base, _, layoutMemorySize, err := selectFirecrackerSnapshotTier(
		int64(state.MemoryMiB)<<20,
		state.BaseMemoryPath,
		state.BaseMemoryIncremental,
		state.BaseMemoryLineageLost,
		requestedType,
	)
	if err != nil {
		return err
	}
	// Hashing the VMM binary and the guest kernel happens before the pause:
	// the first checkpoint after a daemon start pays it once, later ones
	// read the cache.
	compat, err := handler.buildCheckpointCompat(state.Vcpus)
	if err != nil {
		return err
	}

	// Layout happens before the pause: cloning the base is pure host-side
	// work the guest should not wait for. A tier-1/2 layout failure degrades
	// to a Full snapshot; anything else is unrecoverable.
	files, err := prepareFirecrackerCheckpointV2(config.Directory, base, layoutMemorySize)
	if err != nil {
		if base == "" || layoutMemorySize <= 0 {
			return fmt.Errorf("lay out Firecracker checkpoint for %s: %w", sandboxID, err)
		}
		logrus.Warnf(
			"firecracker: incremental layout for %s failed, rebuilding from Full: %v",
			sandboxID, err,
		)
		// The base cannot be laid out, but the VMM soft-dirty ledger may
		// still be armed against it: mark the lineage lost and fall back to
		// a Full snapshot, which writes the complete memory image without
		// consulting the ledger. A SoftDirty first window is NOT a safe
		// fallback here — armed, it writes only the window delta.
		instance.markBaseMemoryLineageLost()
		base = ""
		snapshotType = firecrackerSnapshotTypeFull
		if files, err = prepareFirecrackerCheckpointV2(config.Directory, "", 0); err != nil {
			return fmt.Errorf("lay out Firecracker checkpoint for %s: %w", sandboxID, err)
		}
	}
	tPrepared := time.Now()

	// Best-effort guest flush (U4): sync the writable layer while the guest is
	// still running, so the overlay cloned below captures quiesced data. A
	// miss (old guest agent, slow sync, dead vsock) never fails the checkpoint
	// — the overlay clone is crash-consistent either way.
	tFlushed := time.Now()
	flushCtx, flushCancel := context.WithTimeout(ctx, firecrackerFlushTimeout)
	flushErr := requestFirecrackerAgentWaiting(
		flushCtx,
		state.VsockPath,
		firecrackerproto.MessageFlush,
		nil,
		firecrackerFlushTimeout,
	)
	flushCancel()
	tFlushed = time.Now()
	if flushErr != nil {
		logrus.Debugf(
			"firecracker: guest flush before checkpointing %s skipped: %v",
			sandboxID, flushErr,
		)
	}

	// Best-effort guest shrink (E2B absorption), config-gated because it is
	// net-negative for read-hot workloads: dropping the caches makes the next
	// re-read re-materialize pages through block DMA, which re-dirties the
	// next window (measured: snapshot phase 23-72ms without vs 130-143ms with
	// on a continuous 512MiB re-read loop). It helps long parks of
	// cold-cache sandboxes, which is why it stays available.
	if handler.shrinkBeforeCheckpoint {
		shrinkCtx, shrinkCancel := context.WithTimeout(ctx, firecrackerFlushTimeout)
		shrinkErr := requestFirecrackerAgentWaiting(
			shrinkCtx,
			state.VsockPath,
			firecrackerproto.MessageShrink,
			nil,
			firecrackerFlushTimeout,
		)
		shrinkCancel()
		if shrinkErr != nil {
			logrus.Debugf(
				"firecracker: guest shrink before checkpointing %s skipped: %v",
				sandboxID, shrinkErr,
			)
		}
	}

	if err := api.pause(ctx); err != nil {
		discardUnsealedFirecrackerCheckpoint(files)
		return fmt.Errorf("pause Firecracker sandbox %s: %w", sandboxID, err)
	}
	handoffReleased := false
	defer func() {
		if retErr == nil || handoffReleased ||
			!firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			firecrackerAgentTimeout,
		)
		defer cancel()
		if err := api.resume(cleanupCtx); err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("resume Firecracker sandbox %s after checkpoint failure: %w", sandboxID, err),
			)
			return
		}
		if err := requestFirecrackerAgent(
			cleanupCtx,
			state.VsockPath,
			firecrackerproto.MessageCheckpoint,
			firecrackerproto.CheckpointRequest{Outcome: "error"},
		); err != nil {
			retErr = errors.Join(
				retErr,
				fmt.Errorf("release Firecracker sandbox %s after checkpoint failure: %w", sandboxID, err),
			)
			return
		}
		handoffReleased = true
	}()
	tPaused := time.Now()
	// Clone the writable layer BEFORE the memory snapshot: the snapshot writes
	// the whole guest memory into the page cache inside the window, and an
	// overlay FICLONE after it can stall for seconds on the same filesystem's
	// writeback of that fresh dirty data (measured 12.8s at a 2GiB layer after
	// a 4GiB snapshot). Cloning first runs with a cache that does not yet hold
	// the snapshot, removing the interaction. No in-clone fsync is needed because
	// checkpoint artifacts deliberately remain in the page cache.
	if _, err := cloneFileNoSync(state.OverlayPath, files.Overlay); err != nil {
		discardUnsealedFirecrackerCheckpoint(files)
		// The deferred handoff cleanup above resumes the guest and sends
		// the error outcome; an explicit resume here would race with it.
		return fmt.Errorf("snapshot Firecracker writable layer for %s: %w", sandboxID, err)
	}
	tOverlay := time.Now()
	snapshotAttempted := false
	snapshotErr := handler.withCheckpointSnapshotMemoryCharge(
		config.CgroupPath,
		instance,
		state,
		func() error {
			snapshotAttempted = true
			return api.createSnapshot(
				ctx, files.State, files.Memory, snapshotType,
			)
		},
	)
	if snapshotErr != nil {
		// The VMM disarms its ledger on write failures, but not on every
		// failure shape (a request can fail after the memory write already
		// acked and re-armed, e.g. in the state write). The lineage must be
		// treated as lost either way: the previous base is no longer
		// provably the one the ledger tracks. No in-pause retry — the next
		// checkpoint takes a Full snapshot through the normal path.
		if snapshotAttempted {
			instance.markBaseMemoryLineageLost()
		}
		discardUnsealedFirecrackerCheckpoint(files)
		// The deferred handoff cleanup above resumes the guest and sends
		// the error outcome if the VMM survived; an explicit resume here
		// would race with it.
		return fmt.Errorf("create Firecracker %s snapshot for %s: %w",
			snapshotType, sandboxID, snapshotErr)
	}
	// The snapshot succeeded: files.Memory is now the complete guest memory
	// image and the baseline the Firecracker ledger tracks.
	tSnapshotted := time.Now()

	resumeErr := error(nil)
	if config.LeaveRunning {
		if err := api.resume(ctx); err != nil {
			resumeErr = fmt.Errorf("resume Firecracker sandbox %s: %w", sandboxID, err)
		}
		if resumeErr == nil {
			if err := requestFirecrackerAgent(
				ctx,
				state.VsockPath,
				firecrackerproto.MessageCheckpoint,
				firecrackerproto.CheckpointRequest{Outcome: "resume"},
			); err != nil {
				logrus.Warnf(
					"firecracker: release checkpointed sandbox %s: %v",
					sandboxID, err,
				)
			}
			handoffReleased = true
		}
	}
	tResumed := time.Now()

	// Post-resume tail: seal the logical generation and adopt its base without
	// forcing dirty checkpoint pages to stable storage. Hashing and manifest
	// publication remain outside the pause window.
	//
	// Failure handling past this point: the VMM already wrote the delta and
	// re-armed its window, so discarding the artifact invalidates the
	// lineage — record it as lost (the next checkpoint takes a Full
	// snapshot). Adopting the doomed memory file would leave a dangling
	// base that degrades to the same armed-delta corruption.
	memoryInfo, err := os.Lstat(files.Memory)
	if err != nil {
		instance.markBaseMemoryLineageLost()
		discardUnsealedFirecrackerCheckpoint(files)
		return errors.Join(resumeErr, fmt.Errorf(
			"inspect Firecracker checkpoint memory for %s: %w", sandboxID, err,
		))
	}
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: snapshotType,
		MemorySize:   memoryInfo.Size(),
		Compat:       compat,
	}
	if base != "" {
		manifest.BaseMemory = filepath.Base(filepath.Dir(base))
	}
	if err := finalizeFirecrackerCheckpointV2(ctx, files, manifest); err != nil {
		instance.markBaseMemoryLineageLost()
		discardUnsealedFirecrackerCheckpoint(files)
		return errors.Join(resumeErr, fmt.Errorf(
			"seal Firecracker checkpoint for %s: %w", sandboxID, err,
		))
	}
	adoptCheckpointMemory(instance, files.Memory, false)
	// Persist the adopted base. A persist failure does not fail the sealed
	// artifact, and it cannot corrupt a later generation: recovery never
	// trusts a pre-restart lineage (recoverState marks it lost and forces
	// the next checkpoint to Full), so a stale durable state only costs one
	// Full snapshot after the eventual restart.
	if err := handler.persistInstance(instance); err != nil {
		logrus.Warnf(
			"firecracker: persist adopted base for %s failed (recovery forces a Full snapshot after the next daemon restart): %v",
			sandboxID, err,
		)
	}
	if !handler.checkpointWriteback.schedule(files.Memory) {
		logrus.Warnf(
			"firecracker: checkpoint memory writeback queue is full; skip %s",
			files.Memory,
		)
	}

	// Pause window = pause..resume (snapshot + overlay clone); layout and
	// sealing are host-side work outside it by design.
	phaseMS := func(from, to time.Time) int64 { return to.Sub(from).Milliseconds() }
	tEnd := time.Now()
	logrus.Infof(
		"firecracker: checkpointed sandbox %s type=%s memory=%dMiB dir=%s "+
			"phases: layout=%dms flush=%dms pause=%dms snapshot=%dms overlay=%dms "+
			"resume=%dms seal=%dms total=%dms",
		sandboxID, snapshotType, memoryInfo.Size()>>20, config.Directory,
		phaseMS(tStarted, tPrepared), phaseMS(tPrepared, tFlushed),
		phaseMS(tFlushed, tPaused), phaseMS(tOverlay, tSnapshotted),
		phaseMS(tPaused, tOverlay),
		phaseMS(tSnapshotted, tResumed), phaseMS(tResumed, tEnd),
		phaseMS(tStarted, tEnd),
	)

	if !config.LeaveRunning {
		return handler.finishCheckpointedSandbox(instance, state, sandboxID)
	}
	if resumeErr != nil {
		// The artifact is sealed and the base adopted; only the guest is
		// still paused, which the caller must see as a failure.
		return resumeErr
	}
	logrus.Infof(
		"firecracker: checkpointed sandbox %s type=%s memory=%dMiB dir=%s",
		sandboxID, snapshotType, memoryInfo.Size()>>20, config.Directory,
	)
	return nil
}

func (handler *Handler) finishCheckpointedSandbox(
	instance *firecrackerInstance,
	state firecrackerPersistedState,
	sandboxID string,
) error {
	handler.stopInstance(instance, true)
	if firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		return fmt.Errorf("stop Firecracker sandbox %s after checkpoint", sandboxID)
	}
	if instance.finish(runtimecore.Exit{ExitedAt: time.Now(), ExitCode: 0}) && instance.shouldPersist() {
		if err := handler.persistInstance(instance); err != nil {
			logrus.Warnf("firecracker: persist checkpoint exit state for %s: %v", sandboxID, err)
		}
	}
	return nil
}

// resolveRequestedSnapshotType applies the checkpoint_mode gate to a
// checkpoint request. Outside the incremental mode every generation is a
// Full snapshot; the incremental types stay available only to deployments
// that opted in, so an explicit request for them is a configuration error
// rather than something to silently reinterpret.
func resolveRequestedSnapshotType(mode, requested string) (string, error) {
	if mode != firecrackerCheckpointModeIncremental {
		switch requested {
		case "", firecrackerSnapshotTypeFull:
			return firecrackerSnapshotTypeFull, nil
		default:
			return "", fmt.Errorf(
				"snapshot type %q requires checkpoint_mode = %q (currently %q)",
				requested, firecrackerCheckpointModeIncremental, mode,
			)
		}
	}
	return requested, nil
}

// selectFirecrackerSnapshotTier resolves how the next generation is taken.
// An empty request leaves the automatic three-tier choice to the recorded
// lineage: Full establishes the first baseline, Incremental follows a restore,
// and SoftDirty windows follow a successful checkpoint. An explicit
// request pins the snapshot type: Full drops the lineage for one generation
// (Firecracker writes the whole memory file itself, so the layout
// preallocates nothing), Incremental demands the pagemap base only a
// restore establishes, and SoftDirty demands a usable base. A drifted base
// or a lost lineage cannot fall back to SoftDirty: with the VMM soft-dirty
// ledger armed a SoftDirty request writes only the window delta, so the
// artifact would silently miss every page written before the window opened.
// Those cases force (or, for explicit incremental requests, demand) Full,
// which ignores the ledger and writes the complete memory image.
func selectFirecrackerSnapshotTier(
	memorySize int64,
	basePath string,
	baseIncremental bool,
	lineageLost bool,
	requested string,
) (snapshotType, base string, incremental bool, layoutMemorySize int64, err error) {
	base, incremental = basePath, baseIncremental
	if memorySize > 0 && base != "" && !firecrackerBaseMemoryUsable(base, memorySize) {
		// The base drifted (crash cleanup, operator interference): the VMM
		// ledger may still be armed against it, so this is a lost lineage,
		// not a first-window opportunity.
		base = ""
		lineageLost = true
	}
	if lineageLost && base != "" {
		base = ""
		incremental = false
	}
	switch requested {
	case "":
		// Automatic tier selection.
		snapshotType = firecrackerSnapshotTypeSoftDirty
		layoutMemorySize = memorySize
		if memorySize <= 0 || base == "" || lineageLost {
			snapshotType = firecrackerSnapshotTypeFull
			if memorySize > 0 {
				layoutMemorySize = 0
			}
		} else if base != "" && incremental {
			snapshotType = firecrackerSnapshotTypeIncremental
		}
		return snapshotType, base, incremental, layoutMemorySize, nil
	case firecrackerSnapshotTypeFull:
		// Firecracker writes the whole memory file itself: no clone, no
		// preallocation, and the lineage restarts at this artifact.
		return requested, "", false, 0, nil
	case firecrackerSnapshotTypeIncremental:
		if base == "" || !incremental {
			return "", "", false, 0, fmt.Errorf(
				"Firecracker Incremental checkpoint needs the pagemap base a restore establishes",
			)
		}
		return requested, base, incremental, memorySize, nil
	case firecrackerSnapshotTypeSoftDirty:
		if lineageLost {
			return "", "", false, 0, fmt.Errorf(
				"Firecracker SoftDirty checkpoint has no usable base (lineage lost by a failed checkpoint or a daemon restart); take a Full checkpoint first",
			)
		}
		return requested, base, incremental, memorySize, nil
	}
	return "", "", false, 0, fmt.Errorf(
		"unsupported Firecracker snapshot type %q", requested,
	)
}

// buildCheckpointCompat assembles the compatibility tuple for a guest with
// the given vCPU count, digesting the VMM binary, guest kernel, and initrd
// once per handler and caching the results.
func (handler *Handler) buildCheckpointCompat(vcpus uint32) (*firecrackerCheckpointCompat, error) {
	handler.compatMu.Lock()
	defer handler.compatMu.Unlock()
	if handler.compatDigests == nil {
		compat := &firecrackerCheckpointCompat{Arch: runtime.GOARCH}
		var err error
		if compat.Firecracker, err = digestFirecrackerStackFile(handler.binary); err != nil {
			return nil, fmt.Errorf("digest Firecracker binary: %w", err)
		}
		if compat.Kernel, err = digestFirecrackerStackFile(handler.kernelPath); err != nil {
			return nil, fmt.Errorf("digest Firecracker guest kernel: %w", err)
		}
		if handler.initrdPath != "" {
			if compat.Initrd, err = digestFirecrackerStackFile(handler.initrdPath); err != nil {
				return nil, fmt.Errorf("digest Firecracker initrd: %w", err)
			}
		}
		handler.compatDigests = compat
	}
	compat := *handler.compatDigests
	compat.Vcpus = vcpus
	compat.KernelArgs = handler.kernelArgs
	return &compat, nil
}

// verifyCheckpointCompat refuses to restore an artifact whose recorded
// software stack differs from this handler's. Fields the manifest did not
// record are skipped, and a manifest without a tuple at all (pre-M3
// artifacts) restores without stack verification.
func (handler *Handler) verifyCheckpointCompat(
	artifact *firecrackerCheckpointArtifact,
) error {
	// Legacy v1 archives have no manifest at all; verify only v2 artifacts.
	if artifact.Manifest == nil {
		return nil
	}
	recorded := artifact.Manifest.Compat
	if recorded == nil {
		return nil
	}
	local, err := handler.buildCheckpointCompat(recorded.Vcpus)
	if err != nil {
		return err
	}
	var mismatches []string
	for _, field := range []struct{ name, recorded, local string }{
		{"arch", recorded.Arch, local.Arch},
		{"firecracker", recorded.Firecracker, local.Firecracker},
		{"kernel", recorded.Kernel, local.Kernel},
		{"initrd", recorded.Initrd, local.Initrd},
		{"kernel_args", recorded.KernelArgs, local.KernelArgs},
	} {
		if field.recorded != "" && field.recorded != field.local {
			mismatches = append(mismatches, field.name)
		}
	}
	if len(mismatches) > 0 {
		return fmt.Errorf(
			"Firecracker checkpoint %s was built on an incompatible stack (mismatched: %s)",
			artifact.Files.State, strings.Join(mismatches, ", "),
		)
	}
	return nil
}

func digestFirecrackerStackFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// firecrackerBaseMemoryUsable reports whether the recorded base can still be
// patched by an incremental snapshot of a guest with the given memory size.
func firecrackerBaseMemoryUsable(path string, memorySize int64) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 && info.Size() == memorySize
}

// discardUnsealedFirecrackerCheckpoint removes the components of a checkpoint
// directory that never reached a manifest; sealed artifacts are left alone.
func discardUnsealedFirecrackerCheckpoint(files firecrackerCheckpointFiles) {
	for _, path := range []string{files.State, files.Memory, files.Overlay} {
		if path != "" {
			_ = os.Remove(path)
		}
	}
}

// adoptCheckpointMemory records the memory image a Firecracker process
// produced (the artifact a checkpoint just wrote, or the file a restore just
// loaded) as the incremental base, keeping the lineage consistent with the
// in-process ledger. The base stays caller-owned: it is the previous
// artifact's own memory file, so consecutive generations reflink-share when
// they live on one filesystem and no hidden per-sandbox copy exists.
func adoptCheckpointMemory(
	instance *firecrackerInstance,
	memoryPath string,
	incremental bool,
) {
	info, err := os.Lstat(memoryPath)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 {
		logrus.Warnf(
			"firecracker: checkpoint base %s is not a usable regular file: %v",
			memoryPath, err,
		)
		// The base sandboxd recorded cannot be patched anymore; whether the
		// VMM ledger is armed is unknown, so force the safe Full path.
		instance.markBaseMemoryLineageLost()
		return
	}
	instance.setBaseMemory(memoryPath, incremental)
}

// instantiateFirecrackerCheckpoint materializes the runtime-side pieces of an
// opened checkpoint for a restore and reports the guest memory size it
// carries. v1 archives are unpacked into the sandbox state directory; v2
// directories are restored in place — Firecracker mmaps the artifact's memory
// file, so the caller must keep the checkpoint directory intact for the
// lifetime of the restored sandbox — and only the writable layer is cloned
// into sandbox-owned storage, because the restored VM writes to it.
func instantiateFirecrackerCheckpoint(
	ctx context.Context,
	artifact *firecrackerCheckpointArtifact,
	digests *checkpointDigestCache,
	checkpointDir, stateDir, overlayPath string,
) (firecrackerCheckpointFiles, int64, error) {
	files := firecrackerCheckpointFiles{Overlay: overlayPath}
	switch artifact.Layout {
	case firecrackerCheckpointLayoutV1Archive:
		files.State = filepath.Join(stateDir, firecrackerCheckpointStateName)
		files.Memory = filepath.Join(stateDir, firecrackerCheckpointMemoryName)
		if err := extractFirecrackerCheckpointArchive(
			ctx,
			filepath.Join(checkpointDir, checkpointImageName),
			files,
		); err != nil {
			return files, 0, err
		}
		info, err := os.Lstat(files.Memory)
		if err != nil {
			return files, 0, fmt.Errorf("inspect restored Firecracker memory: %w", err)
		}
		if err := checkRestoredMemorySize(info.Size()); err != nil {
			return files, 0, err
		}
		return files, info.Size(), nil
	case firecrackerCheckpointLayoutV2Directory:
		if err := digests.verifyFirecrackerCheckpointDigests(ctx, artifact); err != nil {
			return files, 0, fmt.Errorf(
				"verify Firecracker checkpoint %s: %w",
				checkpointDir, err,
			)
		}
		files.State = artifact.Files.State
		files.Memory = artifact.Files.Memory
		// The cloned overlay is a live runtime file, not a durable artifact.
		// FICLONE makes it immediately usable by Firecracker; syncing here can
		// force unrelated deferred checkpoint writeback onto restore latency.
		if _, err := cloneFileNoSync(artifact.Files.Overlay, files.Overlay); err != nil {
			return files, 0, fmt.Errorf("instantiate Firecracker writable layer: %w", err)
		}
		if err := checkRestoredMemorySize(artifact.Manifest.MemorySize); err != nil {
			return files, 0, err
		}
		return files, artifact.Manifest.MemorySize, nil
	}
	return files, 0, fmt.Errorf(
		"unsupported Firecracker checkpoint layout %d", artifact.Layout,
	)
}

func checkRestoredMemorySize(memorySize int64) error {
	if memorySize <= 0 || memorySize%(1<<20) != 0 {
		return fmt.Errorf(
			"Firecracker checkpoint memory size %d is not MiB-aligned", memorySize,
		)
	}
	return nil
}

func (handler *Handler) Restore(
	ctx context.Context,
	startConfig runtimecore.StartConfig,
) (retErr error) {
	tStarted := time.Now()
	artifact, err := openFirecrackerCheckpoint(startConfig.CheckpointDir)
	if err != nil {
		return fmt.Errorf(
			"open Firecracker checkpoint %s: %w",
			startConfig.CheckpointDir, err,
		)
	}
	if err := handler.verifyCheckpointCompat(artifact); err != nil {
		return fmt.Errorf(
			"refuse Firecracker restore from %s: %w",
			startConfig.CheckpointDir, err,
		)
	}
	if startConfig.DisableCgroup || startConfig.CgroupPath == "" {
		return errors.New("Firecracker requires a managed cgroup")
	}
	if startConfig.EnableKVM {
		return errors.New("Firecracker does not expose nested KVM to the guest")
	}
	if startConfig.SpecUpdates != nil {
		return errors.New("Firecracker does not support host device-provider OCI updates")
	}
	if startConfig.Network == nil || startConfig.Network.Interface == nil {
		return errors.New("Firecracker requires a cached TAP network")
	}
	handler.mu.RLock()
	_, alreadyRunning := handler.instances[startConfig.ID]
	handler.mu.RUnlock()
	if alreadyRunning {
		return fmt.Errorf("Firecracker sandbox %s already exists", startConfig.ID)
	}
	tOpened := time.Now()

	bundlePath, spec, err := handler.ociLoader.GenerateOci(runtimecore.OciLoadOptions{
		SandboxID:  startConfig.ID,
		Config:     startConfig,
		CgroupPath: startConfig.CgroupPath,
	})
	if err != nil {
		return fmt.Errorf("generate Firecracker restore OCI metadata: %w", err)
	}
	plan, err := prepareFirecrackerStorage(spec, startConfig)
	if err != nil {
		return err
	}
	storageDir, err := createFirecrackerStorageDirectory(handler.storageRoot, startConfig.ID)
	if err != nil {
		return err
	}
	keepStorage := false
	defer func() {
		if !keepStorage {
			retErr = errors.Join(
				retErr,
				cleanupFirecrackerOverlay(handler.storageRoot, startConfig.ID),
			)
		}
	}()

	stateDir := filepath.Join(bundlePath, firecrackerArtifactsDir)
	if err := os.Mkdir(stateDir, 0700); err != nil {
		return fmt.Errorf("create Firecracker restore state directory: %w", err)
	}
	runtimeDir := handler.runtimeDirectory(startConfig.ID)
	runtimeCreated := false
	keepRuntimeArtifacts := false
	defer func() {
		if keepRuntimeArtifacts {
			return
		}
		retErr = errors.Join(retErr, os.RemoveAll(stateDir))
		if runtimeCreated {
			retErr = errors.Join(
				retErr,
				handler.cleanupRuntimeDirectory(startConfig.ID, filepath.Join(
					runtimeDir, firecrackerAPISocket,
				)),
			)
		}
	}()
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		return fmt.Errorf("create Firecracker socket directory %s: %w", runtimeDir, err)
	}
	runtimeCreated = true
	apiPath := filepath.Join(runtimeDir, firecrackerAPISocket)
	vsockPath := filepath.Join(runtimeDir, firecrackerVsock)
	if len(apiPath) >= 100 || len(vsockPath) >= 100 {
		return fmt.Errorf("Firecracker Unix socket path is too long under %s", runtimeDir)
	}
	if err := removeFirecrackerSocket(apiPath); err != nil {
		return err
	}
	if err := removeFirecrackerSocket(vsockPath); err != nil {
		return err
	}

	// v1 archives are unpacked into the sandbox state directory; v2
	// directories are restored in place — Firecracker mmaps the artifact's
	// memory file, so the caller must keep the checkpoint directory intact
	// for the lifetime of the restored sandbox. Only the writable layer is
	// instantiated into sandbox-owned storage (the restored VM writes to it).
	tPrepared := time.Now()
	checkpointFiles, memorySize, err := instantiateFirecrackerCheckpoint(
		ctx,
		artifact,
		&handler.digestCache,
		startConfig.CheckpointDir,
		stateDir,
		filepath.Join(storageDir, "overlay.ext4"),
	)
	if err != nil {
		return err
	}
	if err := os.Symlink(checkpointFiles.Overlay, filepath.Join(
		stateDir, firecrackerCheckpointOverlayName,
	)); err != nil {
		return fmt.Errorf("link restored Firecracker writable layer: %w", err)
	}
	tInstantiated := time.Now()

	stdout, err := openFirecrackerOutput(startConfig.Stdout)
	if err != nil {
		return err
	}
	defer stdout.Close()
	stderr, err := openFirecrackerOutput(startConfig.Stderr)
	if err != nil {
		return err
	}
	defer stderr.Close()
	command := exec.Command(
		handler.binary,
		"--api-sock", apiPath,
		"--id", startConfig.ID,
	)
	command.Dir = stateDir
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start Firecracker restore VMM: %w", err)
	}
	restoredVcpus := uint32(0)
	if artifact.Manifest != nil && artifact.Manifest.Compat != nil {
		compat := artifact.Manifest.Compat
		// Informational only: the vmstate pins the real count.
		restoredVcpus = compat.Vcpus
	}
	instance := &firecrackerInstance{
		state: firecrackerPersistedState{
			ID:          startConfig.ID,
			PID:         command.Process.Pid,
			BundlePath:  bundlePath,
			APIPath:     apiPath,
			VsockPath:   vsockPath,
			OverlayPath: checkpointFiles.Overlay,
			MemoryMiB:   uint32(memorySize >> 20),
			Vcpus:       restoredVcpus,
			CreatedAt:   time.Now().Format(time.RFC3339Nano),
		},
		done: make(chan struct{}),
	}
	handler.mu.Lock()
	handler.instances[startConfig.ID] = instance
	handler.mu.Unlock()
	go handler.waitCommand(instance, command)

	restoreSucceeded := false
	defer func() {
		if restoreSucceeded {
			return
		}
		instance.markDeleting()
		handler.stopInstance(instance, true)
		handler.mu.Lock()
		delete(handler.instances, startConfig.ID)
		handler.mu.Unlock()
	}()
	if err := attachFirecrackerProcess(startConfig.CgroupPath, command.Process.Pid); err != nil {
		return fmt.Errorf("attach restored Firecracker to cgroup: %w", err)
	}
	if err := handler.persistInstance(instance); err != nil {
		return err
	}

	readyCtx, readyCancel := context.WithTimeout(ctx, firecrackerAgentTimeout)
	api := newFirecrackerAPI(apiPath)
	if err := api.waitReady(readyCtx); err != nil {
		readyCancel()
		return err
	}
	readyCancel()
	tReady := time.Now()
	if err := api.loadSnapshot(
		ctx,
		checkpointFiles.State,
		checkpointFiles.Memory,
		startConfig.Network.Interface.Name,
		vsockPath,
	); err != nil {
		return fmt.Errorf("load Firecracker checkpoint for %s: %w", startConfig.ID, err)
	}
	tLoaded := time.Now()
	agentCtx, agentCancel := context.WithTimeout(ctx, firecrackerAgentTimeout)
	defer agentCancel()
	if err := waitForFirecrackerAgent(agentCtx, vsockPath); err != nil {
		return err
	}
	if err := requestFirecrackerAgent(
		agentCtx,
		vsockPath,
		firecrackerproto.MessageSetNetwork,
		plan.configure.Network,
	); err != nil {
		return fmt.Errorf("configure restored Firecracker network: %w", err)
	}
	if err := requestFirecrackerAgent(
		agentCtx,
		vsockPath,
		firecrackerproto.MessageCheckpoint,
		firecrackerproto.CheckpointRequest{
			Outcome:     "restore",
			Environment: plan.configure.Process.Env,
		},
	); err != nil {
		return fmt.Errorf("release restored Firecracker sandbox: %w", err)
	}
	instance.markConfigured()
	// A restored Firecracker diffs against the memory file it loaded, so the
	// sandbox-owned base adopts that image and the next checkpoint runs as a
	// pagemap (Incremental) generation.
	adoptCheckpointMemory(instance, checkpointFiles.Memory, true)
	if err := handler.persistInstance(instance); err != nil {
		return err
	}
	go handler.waitGuest(instance)
	if err := runtimecommon.WriteSandboxRuntimeMarker(bundlePath, config.RuntimeNameFirecracker); err != nil {
		return fmt.Errorf("persist Firecracker restore runtime marker: %w", err)
	}
	restoreSucceeded = true
	keepStorage = true
	keepRuntimeArtifacts = true
	phaseMS := func(from, to time.Time) int64 { return to.Sub(from).Milliseconds() }
	tEnd := time.Now()
	logrus.Infof(
		"firecracker: restored sandbox %s pid=%d "+
			"phases: open=%dms prepare=%dms instantiate=%dms vmm_ready=%dms "+
			"load=%dms agent=%dms total=%dms",
		startConfig.ID, command.Process.Pid,
		phaseMS(tStarted, tOpened), phaseMS(tOpened, tPrepared),
		phaseMS(tPrepared, tInstantiated), phaseMS(tInstantiated, tReady),
		phaseMS(tReady, tLoaded), phaseMS(tLoaded, tEnd),
		phaseMS(tStarted, tEnd),
	)
	return nil
}
