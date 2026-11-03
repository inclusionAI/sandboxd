package server

import (
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
			BuildkitEndpoint: "tcp://builder.internal:9094", AllowedTenants: []string{"allowed"}, WritableMB: 4096,
		}},
	}}}}
}

func TestManagedProfileAuthorizationPrecedesFilesystemChanges(t *testing.T) {
	h := managedTestService(t)
	_, err := h.prepareManagedRuntime(&runtime.StartRequest{Runtime: "runsc", ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Labels: map[string]string{"adx.tenant_id": "other"}}, "")
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
		request.Labels = map[string]string{"adx.tenant_id": "allowed"}
		if _, err := h.prepareManagedRuntime(request, ""); err == nil {
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
	req := &runtime.StartRequest{Runtime: "runsc", ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Labels: map[string]string{"adx.tenant_id": "allowed"}}
	if _, err := h.prepareManagedRuntime(req, directory); err == nil {
		t.Fatal("cross-tenant collection restored")
	}
	req.ExtraConfig = ""
	if _, err := h.prepareManagedRuntime(req, directory); err == nil {
		t.Fatal("managed snapshot restored without profile")
	}
}

func TestPlainSandboxDoesNotAcquireManagedConfiguration(t *testing.T) {
	h := managedTestService(t)
	req := &runtime.StartRequest{Runtime: "runsc"}
	rollback, err := h.prepareManagedRuntime(req, "")
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
	req := &runtime.StartRequest{Runtime: "runsc", ExtraConfig: `{"managedRuntimeProfile":"compose-v1"}`, Labels: map[string]string{"adx.tenant_id": "allowed"}}
	rollback, err := h.prepareManagedRuntime(req, directory)
	if err != nil {
		t.Fatal(err)
	}
	rollback()
	if req.Labels[managedCollectionLabel] != id || len(req.Mounts) != 3 || req.Rootfs.GetImageUrl() != profile.Image {
		t.Fatal("restore did not rebind the authorized runtime")
	}
	if _, err := os.Stat(filepath.Join(root, "records", id+".json")); err != nil {
		t.Fatal("failed restore rollback destroyed retained snapshot collection")
	}
}
