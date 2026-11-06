package api

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/nydus"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/oci"
)

// This exercises the actual Unix management endpoint, registry clients, OCI
// extraction and kernel overlay mount. Run via make managed-registry-test in a
// private mount namespace whose private hosts file resolves registry-http.test.
func TestManagedHTTPRegistryMountIntegration(t *testing.T) {
	if os.Getenv("SANDBOXD_MANAGED_REGISTRY_TEST") != "1" {
		t.Skip("run make managed-registry-test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("explicit integration requires mount privileges")
	}
	server := httptest.NewServer(registry.New())
	defer server.Close()
	host := "registry-http.test:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	const content = "managed HTTP private hostname regression\n"
	if err := tw.WriteHeader(&tar.Header{Name: "witness", Mode: 0644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer, layer)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(host+"/managed/probe:latest", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	reference := host + "/managed/probe@" + digest.String()
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "default-https-fails", true: "operator-http-mounts"}[enabled], func(t *testing.T) {
			policy := map[string]string{}
			if enabled {
				policy[host] = "http"
			}
			client, err := imageregistry.NewClientWithRegistrySchemes("", policy)
			if err != nil {
				t.Fatal(err)
			}
			manager, err := oci.NewManager(t.TempDir(), "", client)
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			worker, err := NewHttpWorker(&HttpWorkerConfig{DBPath: filepath.Join(t.TempDir(), "mounts.db"), OCIManager: manager, NydusClient: nydus.NewRegistryClientFromShared(client)})
			if err != nil {
				t.Fatal(err)
			}
			defer worker.Close()
			dir, err := os.MkdirTemp("", "r4-sock-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			socket := filepath.Join(dir, "image.sock")
			shared := NewSharedOCIService(worker)
			endpoint, err := ListenManagement(socket, shared, client)
			if err != nil {
				t.Fatal(err)
			}
			defer endpoint.Close()
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			}}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}
			post := func(path string, data any) (int, []byte) {
				t.Helper()
				body, _ := json.Marshal(data)
				response, err := httpClient.Post("http://unix"+path, "application/json", bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				payload, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				return response.StatusCode, payload
			}
			// Metadata's per-call insecure flag alone must not implicitly change mounts.
			status, payload := post("/registry_metadata", map[string]any{"reference": reference, "kind": "manifests", "insecure": true})
			if status != 200 {
				t.Fatalf("metadata %d: %s", status, payload)
			}
			status, payload = post("/oci_mount", map[string]string{"image_url": reference, "owner": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
			if !enabled {
				if status != 500 {
					t.Fatalf("default unexpectedly accepted HTTP: %d %s", status, payload)
				}
				return
			}
			if status != 200 {
				t.Fatalf("mount %d: %s", status, payload)
			}
			var response OCIMountResponse
			if err = json.Unmarshal(payload, &response); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(response.MountPath, "witness"))
			if err != nil || string(data) != content {
				t.Fatalf("real mounted data: %q %v", data, err)
			}
			// Idempotent preparation holds one owner; separate owners and an
			// ordinary rootfs must survive each other's independent deletion.
			status, payload = post("/oci_mount", map[string]string{"image_url": reference, "owner": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
			if status != 200 {
				t.Fatalf("repeat %d: %s", status, payload)
			}
			status, payload = post("/oci_mount", map[string]string{"image_url": reference, "owner": strings.Repeat("b", 32)})
			if status != 200 {
				t.Fatalf("second owner %d: %s", status, payload)
			}
			if _, err := shared.MountOCI(context.Background(), &OCIMountRequest{ImageURL: reference}); err != nil {
				t.Fatal(err)
			}
			for _, owner := range []string{strings.Repeat("a", 32), strings.Repeat("b", 32)} {
				if err := endpoint.ReleaseOwner(context.Background(), owner); err != nil {
					t.Fatal(err)
				}
			}
			if data, err := os.ReadFile(filepath.Join(response.MountPath, "witness")); err != nil || string(data) != content {
				t.Fatalf("live rootfs lost after collection release: %q %v", data, err)
			}
			if err := shared.UmountOCI(&OCIUmountRequest{ImageURL: reference}); err != nil {
				t.Fatal(err)
			}
			if mounts, err := manager.ListMountedDetails(); err != nil || len(mounts) != 0 {
				t.Fatalf("last rootfs release leaked: %v %v", mounts, err)
			}
			status, payload = post("/oci_mount", map[string]string{"image_url": reference, "owner": strings.Repeat("c", 32)})
			if status != 200 {
				t.Fatalf("fresh owner %d: %s", status, payload)
			}
			endpoint.Close()
			mounts, err := manager.ListMountedDetails()
			if err != nil || len(mounts) != 0 {
				t.Fatalf("mount leaked: %v %v", mounts, err)
			}
		})
	}
	// Real Nydus manifest/config/bootstrap acquisition over the same HTTP hostname.
	// This fixture checks transport/extraction; real FUSE C/R is separately qualified.
	buf.Reset()
	tw = tar.NewWriter(&buf)
	const bootstrap = "transport-bootstrap-fixture"
	if err := tw.WriteHeader(&tar.Header{Name: nydus.BootstrapFileNameInLayer, Mode: 0644, Size: int64(len(bootstrap))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(bootstrap)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	bootLayer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	nydusImage, err := mutate.Append(empty.Image, mutate.Addendum{Layer: bootLayer, Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"}})
	if err != nil {
		t.Fatal(err)
	}
	nydusTag, _ := name.NewTag(host+"/managed/nydus:latest", name.Insecure)
	if err := remote.Write(nydusTag, nydusImage); err != nil {
		t.Fatal(err)
	}
	nydusDigest, _ := nydusImage.Digest()
	client, err := imageregistry.NewClientWithRegistrySchemes("", map[string]string{host: "http"})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapClient := nydus.NewRegistryClientFromShared(client)
	nydusRef := host + "/managed/nydus@" + nydusDigest.String()
	for range 2 { // Also exercise the metadata-preserving bootstrap cache hit.
		file, _, process, err := bootstrapClient.FetchAndExtractBootstrapWithImageConfig(context.Background(), nydusRef, t.TempDir(), "")
		if err != nil || process == nil {
			t.Fatalf("Nydus HTTP bootstrap/config: %v", err)
		}
		data, err := os.ReadFile(file)
		if err != nil || string(data) != bootstrap {
			t.Fatalf("bootstrap: %q %v", data, err)
		}
	}

}
