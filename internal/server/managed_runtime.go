package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/managedlease"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/registryauth"
	"golang.org/x/sys/unix"
)

const managedProfileKey = "managedRuntimeProfile"
const managedCollectionLabel = "akernel.managed_runtime.collection"
const managedOwnerLabel = "akernel.managed_runtime.owner"
const managedProfileLabel = "akernel.managed_runtime.profile"
const managedCheckpointFile = "managed-runtime.json"

var managedName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var managedID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type managedRecord struct {
	LifecycleVersion int    `json:"lifecycle_version,omitempty"`
	CollectionID     string `json:"collection_id"`
	TenantID         string `json:"tenant_id"`
	Profile          string `json:"profile"`
	ProfileDigest    string `json:"profile_digest"`
	Registry         string `json:"registry"`
	RepositoryPrefix string `json:"repository_prefix"`
	AuthFile         string `json:"auth_file"`
	Scheme           string `json:"scheme"`
	TokenSHA256      string `json:"token_sha256"`
}

type managedCheckpoint struct {
	CollectionID  string `json:"collection_id"`
	TenantID      string `json:"tenant_id"`
	Profile       string `json:"profile"`
	ProfileDigest string `json:"profile_digest"`
}

func managedProfileSelection(request *runtime.StartRequest) (string, error) {
	var extra map[string]json.RawMessage
	if request.ExtraConfig != "" {
		if err := json.Unmarshal([]byte(request.ExtraConfig), &extra); err != nil {
			return "", err
		}
	}
	selected, ok := extra[managedProfileKey]
	if !ok {
		return "", nil
	}
	var profile string
	if err := json.Unmarshal(selected, &profile); err != nil || !managedName.MatchString(profile) {
		return "", fmt.Errorf("invalid managed runtime profile")
	}
	return profile, nil
}

func profileFingerprint(profile config.ManagedRuntimeProfile) string {
	// Authorization is checked against current policy before compatibility.
	// Adding/reordering tenants must not invalidate another tenant's snapshot.
	profile.AllowedTenants = nil
	data, _ := json.Marshal(profile)
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func managedRegistryAuth(path, host string) (string, error) {
	auths, err := registryauth.Load(path)
	if err != nil || auths[host].Auth == "" {
		// Do not expose file contents or credentials in admission failures.
		return "", fmt.Errorf("managed Registry credential is unavailable")
	}
	return auths[host].Auth, nil
}

func writePrivateJSON(path string, value any, mode os.FileMode) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	return errors.Join(writeErr, syncErr, file.Close())
}

// prepareManagedRuntime consumes trusted ADX labels and an operator-only profile.
// No guest-supplied HostPath, endpoint, credential or collection is accepted.
// New local collections use durable live/checkpoint leases. Legacy collections
// remain conservatively pinned until an operator drains their service.
func (h *sandboxService) prepareManagedRuntime(ctx context.Context, request *runtime.StartRequest, checkpointDir string) (func(), error) {
	profileName, err := managedProfileSelection(request)
	if err != nil {
		return nil, err
	}
	if request.Labels[managedCollectionLabel] != "" || request.Labels[managedProfileLabel] != "" || request.Labels[managedOwnerLabel] != "" {
		return nil, fmt.Errorf("managed runtime labels are platform-owned")
	}
	if profileName == "" {
		if checkpointDir != "" {
			if _, err := os.Stat(filepath.Join(checkpointDir, managedCheckpointFile)); err == nil {
				return nil, fmt.Errorf("managed runtime profile is required for this checkpoint")
			}
		}
		return nil, nil
	}
	profile, ok := h.config.ManagedRuntimeProfiles[profileName]
	if !ok {
		return nil, fmt.Errorf("managed runtime profile is unavailable")
	}
	tenant := request.Labels["adx.tenant_id"]
	if tenant == "" || !slices.Contains(profile.AllowedTenants, tenant) {
		return nil, fmt.Errorf("managed runtime profile is not authorized for this tenant: %w", errord.ErrPermissionDenied)
	}
	if request.Runtime != config.RuntimeNameRunsc {
		return nil, fmt.Errorf("managed Docker runtime requires runsc")
	}
	minimumMB, err := profile.MinimumStorageMB()
	if err != nil {
		return nil, err
	}
	if request.WritableLayerLimitBytes < minimumMB<<20 {
		return nil, fmt.Errorf("managed runtime profile %q requires at least %d MiB total writable storage (upper plus root)", profileName, minimumMB)
	}
	if _, err := name.NewDigest(profile.Image); err != nil {
		return nil, fmt.Errorf("managed runtime requires a pinned tool image: %w", err)
	}
	root := h.config.ManagedRuntimeRoot
	if !filepath.IsAbs(profile.BootstrapRoot) {
		return nil, fmt.Errorf("managed runtime requires an operator-owned bootstrap root")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || profile.WritableMB < 1 || profile.ProviderURL == "" || profile.BuildkitEndpoint == "" || profile.Registry == "" {
		return nil, fmt.Errorf("managed runtime operator profile is incomplete")
	}
	hasBootstrap := false
	for _, mount := range request.Mounts {
		if mount.Target == "/__adx" && mount.Type == "erofs" && mount.GetHostPath() == profile.BootstrapRoot && slices.Contains(mount.Options, "ro") {
			hasBootstrap = true
			continue
		}
		if mount.GetHostPath() != "" {
			return nil, fmt.Errorf("managed runtime does not accept client-selected node paths")
		}
		for _, target := range []string{"/__adx", "/opt/akernel-images", "/run/akernel-build", "/root/.docker/config.json", "/var/lib/akernel-image-snapshots"} {
			requested := filepath.Clean(mount.Target)
			if requested == "/" || requested == target || strings.HasPrefix(target, requested+"/") || strings.HasPrefix(requested, target+"/") {
				return nil, fmt.Errorf("managed runtime mount target is platform-owned: %s", target)
			}
		}
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(request.ExtraConfig), &extra); err != nil {
		return nil, err
	}
	if _, ok := extra["fileBackedTmpfsMounts"]; ok {
		return nil, fmt.Errorf("managed runtime writable backing is platform-owned")
	}
	for _, part := range []string{"records", "guests", "collections"} {
		if err := os.MkdirAll(filepath.Join(root, part), 0700); err != nil {
			return nil, err
		}
	}
	var record managedRecord
	var finish func()
	created := false
	if checkpointDir != "" {
		data, err := os.ReadFile(filepath.Join(checkpointDir, managedCheckpointFile))
		if err != nil {
			return nil, fmt.Errorf("managed runtime checkpoint descriptor is missing: %w", err)
		}
		var saved managedCheckpoint
		if err := json.Unmarshal(data, &saved); err != nil {
			return nil, err
		}
		if !managedID.MatchString(saved.CollectionID) || saved.TenantID != tenant || saved.Profile != profileName || saved.ProfileDigest != profileFingerprint(profile) {
			return nil, fmt.Errorf("managed runtime checkpoint identity does not match the authorized profile")
		}
		data, err = os.ReadFile(filepath.Join(root, "records", saved.CollectionID+".json"))
		if err != nil {
			return nil, fmt.Errorf("managed image collection is unavailable on this node: %w", err)
		}
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, err
		}
		if record.CollectionID != saved.CollectionID || record.TenantID != tenant || record.Profile != profileName || record.ProfileDigest != saved.ProfileDigest {
			return nil, fmt.Errorf("managed image collection identity mismatch")
		}
		if record.LifecycleVersion != 0 && record.LifecycleVersion != managedLifecycleVersion {
			return nil, fmt.Errorf("unsupported managed collection lifecycle")
		}
		if record.LifecycleVersion == managedLifecycleVersion {
			if err := h.managedLeases().VerifyPin(ctx, record.CollectionID, filepath.Join(checkpointDir, managedlease.CheckpointFile)); err != nil {
				return nil, err
			}
		}
		for _, path := range []string{filepath.Join(root, "collections", record.CollectionID), filepath.Join(root, "guests", record.CollectionID)} {
			info, err := os.Stat(path)
			if err != nil || !info.IsDir() {
				return nil, fmt.Errorf("managed image collection storage is unavailable")
			}
		}
	} else {
		var identity [16]byte
		var secret [32]byte
		if _, err := rand.Read(identity[:]); err != nil {
			return nil, err
		}
		if _, err := rand.Read(secret[:]); err != nil {
			return nil, err
		}
		id := hex.EncodeToString(identity[:])
		token := id + "." + hex.EncodeToString(secret[:])
		hash := sha256.Sum256([]byte(token))
		prefix := profile.RepositoryPrefix
		if prefix == "" {
			prefix = "managed"
		}
		if matched, _ := regexp.MatchString(`^[a-z0-9][a-z0-9/_-]*$`, prefix); !matched {
			return nil, fmt.Errorf("invalid managed artifact repository prefix")
		}
		scheme := "https"
		if profile.RegistryInsecure {
			scheme = "http"
		}
		record = managedRecord{LifecycleVersion: managedLifecycleVersion, CollectionID: id, TenantID: tenant, Profile: profileName, ProfileDigest: profileFingerprint(profile), Registry: profile.Registry, RepositoryPrefix: prefix + "/" + id + "/", AuthFile: profile.RegistryAuthFile, Scheme: scheme, TokenSHA256: hex.EncodeToString(hash[:])}
		guest := filepath.Join(root, "guests", id)
		collection := filepath.Join(root, "collections", id)
		if err := os.Mkdir(guest, 0700); err != nil {
			return nil, err
		}
		rollback := func() {
			if finish != nil {
				finish()
			}
			_ = unix.Unmount(collection, 0)
			_ = os.RemoveAll(guest)
			_ = os.RemoveAll(collection)
			_ = os.Remove(filepath.Join(root, "records", id+".json"))
		}
		if err := os.Mkdir(collection, 0755); err != nil {
			rollback()
			return nil, err
		}
		if err := unix.Mount(collection, collection, "", unix.MS_BIND, ""); err != nil {
			rollback()
			return nil, err
		}
		if err := unix.Mount("", collection, "", unix.MS_SHARED, ""); err != nil {
			rollback()
			return nil, err
		}
		if err := os.Mkdir(filepath.Join(collection, ".metadata"), 0755); err != nil {
			rollback()
			return nil, err
		}
		if err := writePrivateJSON(filepath.Join(collection, ".metadata", "plan.json"), map[string]any{"images": []any{}, "automatic": true}, 0444); err != nil {
			rollback()
			return nil, err
		}
		auth, err := managedRegistryAuth(profile.RegistryAuthFile, profile.Registry)
		if err != nil {
			rollback()
			return nil, err
		}
		profileData := map[string]any{"registry": profile.Registry, "registry_insecure": profile.RegistryInsecure, "prefix": prefix + "/" + id, "endpoint": profile.BuildkitEndpoint, "builder": "akernel-remote", "provider": profile.ProviderURL, "token_file": "/run/akernel-build/token", "plan": "/opt/akernel-images/.metadata/plan.json", "writable_mb": profile.WritableMB}
		if err := writePrivateJSON(filepath.Join(guest, "profile.json"), profileData, 0400); err != nil {
			rollback()
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(guest, "token"), []byte(token), 0400); err != nil {
			rollback()
			return nil, err
		}
		if err := writePrivateJSON(filepath.Join(guest, "docker-config.json"), map[string]any{"auths": map[string]any{profile.Registry: map[string]string{"auth": auth}}}, 0400); err != nil {
			rollback()
			return nil, err
		}
		if err := h.managedLeases().Create(id); err != nil {
			rollback()
			return nil, err
		}
		finish, err = h.pinManagedOperation(ctx, record)
		if err != nil {
			rollback()
			return nil, err
		}
		// Publish the capability only after the initial operation is pinned;
		// a background collector must never see a new unowned record.
		if err := writePrivateJSON(filepath.Join(root, "records", id+".json"), record, 0600); err != nil {
			rollback()
			return nil, err
		}
		created = true
	}
	if finish == nil {
		finish, err = h.pinManagedOperation(ctx, record)
		if err != nil {
			return nil, err
		}
	}
	returned := false
	defer func() {
		if !returned {
			finish()
		}
	}()
	id := record.CollectionID
	guest := filepath.Join(root, "guests", id)
	collection := filepath.Join(root, "collections", id)
	request.Rootfs = &runtime.RootfsConfig{Readonly: false, Type: runtime.RootfsSrcType_IMAGE, Source: &runtime.RootfsConfig_ImageUrl{ImageUrl: profile.Image}}
	if !hasBootstrap {
		request.Mounts = append(request.Mounts, &runtime.Mount{Type: "erofs", Target: "/__adx", Options: []string{"ro"}, Source: &runtime.Mount_HostPath{HostPath: profile.BootstrapRoot}})
	}
	for _, mount := range [][2]string{{collection, "/opt/akernel-images"}, {guest, "/run/akernel-build"}, {filepath.Join(guest, "docker-config.json"), "/root/.docker/config.json"}} {
		request.Mounts = append(request.Mounts, &runtime.Mount{Type: "bind", Target: mount[1], Options: []string{"ro", "rbind"}, Source: &runtime.Mount_HostPath{HostPath: mount[0]}})
	}
	extra["fileBackedTmpfsMounts"] = []map[string]any{{"target": "/var/lib/akernel-image-snapshots", "sizeMB": profile.WritableMB}}
	data, err := json.Marshal(extra)
	if err != nil {
		return nil, err
	}
	request.ExtraConfig = string(data)
	if request.Labels == nil {
		request.Labels = map[string]string{}
	}
	request.Labels[managedProfileLabel] = profileName
	request.Labels[managedCollectionLabel] = id
	rollback := func() {
		finish()
		if created && record.LifecycleVersion == managedLifecycleVersion {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = h.collectManagedCollection(ctx, id)
		}
	}
	returned = true
	return rollback, nil
}

func (h *sandboxService) writeManagedRuntimeCheckpoint(ctx context.Context, sandboxID, checkpointDir string) error {
	if h.config.ManagedRuntimeRoot == "" {
		return nil
	}
	sandbox, err := h.sandboxManager.Get(sandboxID)
	if err != nil {
		return err
	}
	labels := sandbox.Metadata.Labels
	id := labels[managedCollectionLabel]
	if id == "" {
		return nil
	}
	if !managedID.MatchString(id) {
		return fmt.Errorf("invalid managed collection identity")
	}
	data, err := os.ReadFile(filepath.Join(h.config.ManagedRuntimeRoot, "records", id+".json"))
	if err != nil {
		return err
	}
	var record managedRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}
	if err := writePrivateJSON(filepath.Join(checkpointDir, managedCheckpointFile), managedCheckpoint{CollectionID: id, TenantID: record.TenantID, Profile: record.Profile, ProfileDigest: record.ProfileDigest}, 0600); err != nil {
		return err
	}
	if record.LifecycleVersion == managedLifecycleVersion {
		return h.managedLeases().Pin(ctx, id, filepath.Join(checkpointDir, managedlease.CheckpointFile))
	}
	return nil
}
