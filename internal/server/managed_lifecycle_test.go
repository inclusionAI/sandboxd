package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/managedlease"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

func TestManagedCheckpointAndCloneOwnIndependentCollectionLeases(t *testing.T) {
	h := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	h.config.ManagedRuntimeRoot = t.TempDir()
	id := strings.Repeat("a", 32)
	ctx := context.Background()
	root := h.config.ManagedRuntimeRoot
	if err := os.Mkdir(filepath.Join(root, "records"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := h.managedLeases().Create(id); err != nil {
		t.Fatal(err)
	}
	record := managedRecord{CollectionID: id, LifecycleVersion: managedLifecycleVersion, TenantID: "tenant", Profile: "profile"}
	if err := writePrivateJSON(filepath.Join(root, "records", id+".json"), record, 0600); err != nil {
		t.Fatal(err)
	}
	storeRunningSandbox(t, h, "source", config.RuntimeNameRunsc)
	sandbox, err := h.sandboxManager.Get("source")
	if err != nil {
		t.Fatal(err)
	}
	sandbox.Metadata.Labels = map[string]string{managedCollectionLabel: id}
	owner, _, claimErr := h.claimManagedSandbox(ctx, "source", id)
	err = claimErr
	if err != nil {
		t.Fatal(err)
	}
	capture, err := h.holdManagedCheckpoint(ctx, "source")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.releaseManagedSandbox("source", owner); err != nil {
		t.Fatal(err)
	}
	cleanupCalls := 0
	cleanup := func() error { cleanupCalls++; return nil }
	if done, err := h.managedLeases().Collect(ctx, id, cleanup); done || err != nil {
		t.Fatalf("inflight capture lost lower: %v %v", done, err)
	}
	checkpoint := t.TempDir()
	if err := h.writeManagedRuntimeCheckpoint(ctx, "source", checkpoint); err != nil {
		t.Fatal(err)
	}
	capture()
	if err := h.managedLeases().VerifyPin(ctx, id, filepath.Join(checkpoint, managedlease.CheckpointFile)); err != nil {
		t.Fatal(err)
	}
	if done, err := h.managedLeases().Collect(ctx, id, cleanup); done || err != nil {
		t.Fatalf("retained checkpoint lost lower: %v %v", done, err)
	}
	_, cloneRelease, err := h.claimManagedSandbox(ctx, "clone", id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(checkpoint); err != nil {
		t.Fatal(err)
	}
	if done, err := h.managedLeases().Collect(ctx, id, cleanup); done || err != nil {
		t.Fatalf("restored clone lost lower: %v %v", done, err)
	}
	cloneRelease()
	if done, err := h.managedLeases().Collect(ctx, id, cleanup); !done || err != nil || cleanupCalls != 1 {
		t.Fatalf("final release: %v %v calls=%d", done, err, cleanupCalls)
	}
}

func TestLegacyManagedCollectionIsNeverCollectedFromMissingReferences(t *testing.T) {
	h := managedTestService(t)
	id := strings.Repeat("b", 32)
	if err := os.Mkdir(filepath.Join(h.config.ManagedRuntimeRoot, "records"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.config.ManagedRuntimeRoot, "records", id+".json")
	if err := writePrivateJSON(path, managedRecord{CollectionID: id}, 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := h.collectManagedCollection(context.Background(), id); done || err != nil {
		t.Fatalf("legacy record collected: %v %v", done, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("legacy ownership was removed")
	}
}

func TestOldAttemptCleanupCannotReleaseReusedSandboxIdentity(t *testing.T) {
	h := managedTestService(t)
	id := strings.Repeat("c", 32)
	ctx := context.Background()
	root := h.config.ManagedRuntimeRoot
	if err := os.Mkdir(filepath.Join(root, "records"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateJSON(filepath.Join(root, "records", id+".json"), managedRecord{CollectionID: id, LifecycleVersion: managedLifecycleVersion}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.managedLeases().Create(id); err != nil {
		t.Fatal(err)
	}
	first, firstRelease, err := h.claimManagedSandbox(ctx, "same-id", id)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.releaseManagedSandbox("same-id", first); err != nil {
		t.Fatal(err)
	}
	second, secondRelease, err := h.claimManagedSandbox(ctx, "same-id", id)
	if err != nil {
		t.Fatal(err)
	}
	defer secondRelease()
	firstRelease()
	if first == second {
		t.Fatal("sandbox retry reused an owner identity")
	}
	if err := h.managedLeases().VerifyPin(ctx, id, filepath.Join(root, "owners", second)); err != nil {
		t.Fatal("stale cleanup released the replacement owner")
	}
}

func TestManagedRecoveryValidatesDependenciesAndCoalescesDigestAliases(t *testing.T) {
	h := managedTestService(t)
	id := strings.Repeat("d", 32)
	root := h.config.ManagedRuntimeRoot
	if err := os.Mkdir(filepath.Join(root, "records"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateJSON(filepath.Join(root, "records", id+".json"), managedRecord{CollectionID: id, Registry: "registry.test", RepositoryPrefix: "managed/" + id + "/"}, 0600); err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(root, "collections", id, ".metadata")
	if err := os.MkdirAll(metadata, 0700); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	guestRoot := "/opt/akernel-images/" + digest
	one := "registry.test/managed/" + id + "/one@sha256:" + digest
	two := "registry.test/managed/" + id + "/two@sha256:" + digest
	write := func(images []map[string]string) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"images": images})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(metadata, "plan.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write([]map[string]string{{"reference": one, "root": guestRoot}, {"reference": two, "root": guestRoot}})
	plan, err := h.managedPlan(id)
	if err != nil || len(plan.Images) != 1 || plan.Images[0].Reference != one {
		t.Fatalf("digest aliases were remounted independently: %+v %v", plan, err)
	}
	for _, image := range []map[string]string{{"reference": one, "root": digest}, {"reference": one, "root": "/opt/akernel-images/" + strings.Repeat("b", 64)}, {"reference": "registry.test/other@sha256:" + digest, "root": guestRoot}, {"reference": "foreign.test/managed/" + id + "/one@sha256:" + digest, "root": guestRoot}} {
		write([]map[string]string{image})
		if _, err := h.managedPlan(id); err == nil {
			t.Fatalf("invalid dependency accepted: %v", image)
		}
	}
}
