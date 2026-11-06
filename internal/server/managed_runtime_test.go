package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"errors"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
)

func managedTestService(t *testing.T) *sandboxService {
	t.Helper()
	return &sandboxService{config: config.Config{PluginConfig: config.PluginConfig{ManagedRuntimeConfig: config.ManagedRuntimeConfig{
		ManagedRuntimeRoot: t.TempDir(), ManagedRuntimeProfiles: map[string]config.ManagedRuntimeProfile{"compose-v1": {
			Image: "registry.test/tools@sha256:" + strings.Repeat("a", 64), Registry: "registry.test", ProviderURL: "http://node.internal:8840",
			BuildkitEndpoint: "tcp://builder.internal:9094", BootstrapRoot: "/operator/runtime.img", AllowedTenants: []string{"allowed"}, WritableMB: 4096,
		}},
	}}}}
}

func TestManagedRegistryAuthUsesSharedParser(t *testing.T) {
	for _, input := range []string{`{"registry.test":{"Auth":"test-value"}}`, `{"auths":{"registry.test":{"auth":"test-value"}}}`, `{"auths":{"https://registry.test/v1/":{"auth":"test-value"}}}`} {
		path := filepath.Join(t.TempDir(), "auth.json")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := managedRegistryAuth(path, "registry.test")
		if err != nil || got != "test-value" {
			t.Fatalf("shared auth parser was not used: %v", err)
		}
		if _, err := managedRegistryAuth(path, "other.test"); err == nil || strings.Contains(err.Error(), "test-value") {
			t.Fatalf("missing credential did not fail safely: %v", err)
		}
	}
}

func TestManagedProfileAuthorizationPrecedesFilesystemChanges(t *testing.T) {
	h := managedTestService(t)
	_, err := h.prepareManagedRuntime(context.Background(), &runtime.StartRequest{Runtime: "runsc", ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Labels: map[string]string{"adx.tenant_id": "other"}}, "")
	if !errors.Is(err, errord.ErrPermissionDenied) {
		t.Fatalf("authorization: %v", err)
	}
	entries, _ := os.ReadDir(h.config.ManagedRuntimeRoot)
	if len(entries) != 0 {
		t.Fatal("denied profile changed node state")
	}
}

func TestManagedProfileCannotOverridePlatformMountsOrUpper(t *testing.T) {
	for _, request := range []*runtime.StartRequest{
		{ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Mounts: []*runtime.Mount{{Target: "/opt/akernel-images", Source: &runtime.Mount_HostPath{HostPath: "/etc"}}}},
		{ExtraConfig: `{"managedRuntimeProfile":"compose-v1","fileBackedTmpfsMounts":[]}`},
	} {
		h := managedTestService(t)
		request.Runtime = "runsc"
		request.WritableLayerLimitBytes = 8192 << 20
		request.Labels = map[string]string{"adx.tenant_id": "allowed"}
		if _, err := h.prepareManagedRuntime(context.Background(), request, ""); err == nil {
			t.Fatal("platform profile override accepted")
		}
	}
}

func TestManagedCheckpointRejectsForeignOrChangedProfile(t *testing.T) {
	h := managedTestService(t)
	directory := t.TempDir()
	saved := managedCheckpoint{CollectionID: strings.Repeat("a", 32), TenantID: "foreign", Profile: "compose-v1", ProfileDigest: profileFingerprint(h.config.ManagedRuntimeProfiles["compose-v1"])}
	data, _ := json.Marshal(saved)
	if err := os.WriteFile(filepath.Join(directory, managedCheckpointFile), data, 0600); err != nil {
		t.Fatal(err)
	}
	req := &runtime.StartRequest{Runtime: "runsc", WritableLayerLimitBytes: 8192 << 20, ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Labels: map[string]string{"adx.tenant_id": "allowed"}}
	if _, err := h.prepareManagedRuntime(context.Background(), req, directory); err == nil {
		t.Fatal("cross-tenant collection restored")
	}
	req.ExtraConfig = ""
	if _, err := h.prepareManagedRuntime(context.Background(), req, directory); err == nil {
		t.Fatal("managed snapshot restored without profile")
	}
}

func TestPlainSandboxDoesNotAcquireManagedConfiguration(t *testing.T) {
	h := managedTestService(t)
	req := &runtime.StartRequest{Runtime: "runsc"}
	rollback, err := h.prepareManagedRuntime(context.Background(), req, "")
	if err != nil || rollback != nil || len(req.Mounts) != 0 {
		t.Fatalf("plain sandbox changed: %v", err)
	}
}

func TestManagedCheckpointReusesAuthorizedCollectionWithoutFreshMounts(t *testing.T) {
	h := managedTestService(t)
	id := strings.Repeat("a", 32)
	root := h.config.ManagedRuntimeRoot
	profile := h.config.ManagedRuntimeProfiles["compose-v1"]
	saved := managedCheckpoint{CollectionID: id, TenantID: "allowed", Profile: "compose-v1", ProfileDigest: profileFingerprint(profile)}
	directory := t.TempDir()
	if err := writePrivateJSON(filepath.Join(directory, managedCheckpointFile), saved, 0600); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"records", filepath.Join("collections", id), filepath.Join("guests", id)} {
		if err := os.MkdirAll(filepath.Join(root, part), 0700); err != nil {
			t.Fatal(err)
		}
	}
	record := managedRecord{CollectionID: id, TenantID: saved.TenantID, Profile: saved.Profile, ProfileDigest: saved.ProfileDigest}
	if err := writePrivateJSON(filepath.Join(root, "records", id+".json"), record, 0600); err != nil {
		t.Fatal(err)
	}
	// Current authorization may expand without changing a saved runtime's ABI.
	profile.AllowedTenants = []string{"new-tenant", "allowed"}
	h.config.ManagedRuntimeProfiles["compose-v1"] = profile
	req := &runtime.StartRequest{Runtime: "runsc", WritableLayerLimitBytes: 8192 << 20, ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Labels: map[string]string{"adx.tenant_id": "allowed"}}
	rollback, err := h.prepareManagedRuntime(context.Background(), req, directory)
	if err != nil {
		t.Fatal(err)
	}
	rollback()
	if req.Labels[managedCollectionLabel] != id || len(req.Mounts) != 4 || req.Rootfs.GetImageUrl() != profile.Image {
		t.Fatal("restore did not rebind the authorized runtime")
	}
	if _, err := os.Stat(filepath.Join(root, "records", id+".json")); err != nil {
		t.Fatal("failed restore rollback destroyed retained snapshot collection")
	}
	profile.AllowedTenants = []string{"new-tenant"}
	h.config.ManagedRuntimeProfiles["compose-v1"] = profile
	denied := &runtime.StartRequest{Runtime: "runsc", WritableLayerLimitBytes: 8192 << 20, ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Labels: map[string]string{"adx.tenant_id": "allowed"}}
	if _, err := h.prepareManagedRuntime(context.Background(), denied, directory); !errors.Is(err, errord.ErrPermissionDenied) {
		t.Fatalf("revoked tenant restored: %v", err)
	}
}

func TestManagedStorageFloorBeforeFilesystemChanges(t *testing.T) {
	for _, total := range []uint64{0, 4096, 4097, 8191} {
		h := managedTestService(t)
		req := &runtime.StartRequest{Runtime: "runsc", WritableLayerLimitBytes: total << 20, ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Labels: map[string]string{"adx.tenant_id": "allowed"}}
		_, err := h.prepareManagedRuntime(context.Background(), req, "")
		if err == nil || !strings.Contains(err.Error(), "8192 MiB") {
			t.Fatalf("total %d: %v", total, err)
		}
		entries, _ := os.ReadDir(h.config.ManagedRuntimeRoot)
		if len(entries) != 0 {
			t.Fatal("storage rejection changed node state")
		}
	}
}

func TestManagedFingerprintStillRejectsRuntimeChanges(t *testing.T) {
	p := managedTestService(t).config.ManagedRuntimeProfiles["compose-v1"]
	original := profileFingerprint(p)
	for _, change := range []func(*config.ManagedRuntimeProfile){
		func(p *config.ManagedRuntimeProfile) { p.Image += "changed" },
		func(p *config.ManagedRuntimeProfile) { p.BootstrapRoot += "changed" },
		func(p *config.ManagedRuntimeProfile) { p.WritableMB++ },
		func(p *config.ManagedRuntimeProfile) { p.MinimumRootMB = 8192 },
	} {
		changed := p
		change(&changed)
		if profileFingerprint(changed) == original {
			t.Fatal("runtime change retained compatibility fingerprint")
		}
	}
}
