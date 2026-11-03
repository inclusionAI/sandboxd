package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type managementMounter struct{ calls int }

func TestManagementParallelImagesAndShutdownJoin(t *testing.T) {
	entered := make(chan struct{}, 2)
	var active atomic.Int32
	path := filepath.Join(t.TempDir(), "private", "management.sock")
	service := &blockingImageService{mount: func(ctx context.Context, _ *OCIMountRequest) (*OCIMountResponse, error) {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	server, err := ListenManagement(path, service)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	defer client.CloseIdleConnections()
	done := make(chan struct{}, 2)
	for _, c := range []string{"a", "b"} {
		go func(c string) {
			defer func() { done <- struct{}{} }()
			response, err := client.Post("http://unix/oci_mount", "application/json", strings.NewReader(`{"image_url":"registry.test/managed/`+c+`@sha256:`+strings.Repeat(c, 64)+`"}`))
			if err == nil {
				response.Body.Close()
			}
		}(c)
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("management lock serialized different images")
		}
	}
	server.Close()
	if active.Load() != 0 {
		t.Fatal("shutdown returned while preparation survived")
	}
	for range 2 {
		<-done
	}
}

type metadataReader struct{ calls int }

func (m *metadataReader) Metadata(context.Context, string, string, bool) ([]byte, string, error) {
	m.calls++
	return []byte(`{"config":"verified"}`), "application/json", nil
}

func TestPrivateMetadataDelegatesOnlyValidatedReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "management.sock")
	reader := &metadataReader{}
	server, err := ListenManagement(path, &managementMounter{}, reader)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	defer client.CloseIdleConnections()
	ref := "registry.test/managed/main@sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"reference":"registry.test/managed/main:tag","kind":"manifests"}`, 400},
		{`{"reference":"` + ref + `","kind":"files"}`, 400},
		{`{"reference":"` + ref + `","kind":"manifests","auth":"client-secret"}`, 400},
		{`{"reference":"` + ref + `","kind":"manifests"} {}`, 400},
		{`{"reference":"` + ref + `","kind":"manifests","insecure":true}`, 200},
	} {
		response, err := client.Post("http://unix/registry_metadata", "application/json", strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != test.status {
			t.Fatalf("got %d want %d", response.StatusCode, test.status)
		}
		response.Body.Close()
	}
	if reader.calls != 1 {
		t.Fatalf("unvalidated metadata read: %d", reader.calls)
	}
}

func (m *managementMounter) UmountOCI(*OCIUmountRequest) error { return nil }

func (m *managementMounter) MountOCI(ctx context.Context, request *OCIMountRequest) (*OCIMountResponse, error) {
	m.calls++
	return &OCIMountResponse{MountPath: "/owned/shared/lower"}, nil
}

func TestPrivateManagementSocketValidatesBeforeMount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "management.sock")
	mounter := &managementMounter{}
	server, err := ListenManagement(path, mounter)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	defer client.CloseIdleConnections()
	ref := "registry.test/poc/main@sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"image_url":"registry.test/poc/main:latest"}`, 400},
		{`{"image_url":"` + ref + `","mount_path":"/etc"}`, 400},
		{`{"image_url":"` + ref + `"} {}`, 400},
		{`{"image_url":"` + ref + `"}`, 200},
	} {
		response, err := client.Post("http://unix/oci_mount", "application/json", strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != test.status {
			t.Errorf("status=%d want %d", response.StatusCode, test.status)
		}
		if test.status == 200 {
			var value OCIMountResponse
			if err := json.NewDecoder(response.Body).Decode(&value); err != nil || value.MountPath != "/owned/shared/lower" {
				t.Errorf("response: %+v %v", value, err)
			}
		}
		response.Body.Close()
	}
	if mounter.calls != 1 {
		t.Fatalf("invalid requests reached mount provider: %d", mounter.calls)
	}
}

func TestManagementSocketRefusesNonPrivateParentAndExistingSocket(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if server, err := ListenManagement(filepath.Join(root, "socket"), &managementMounter{}); err == nil {
		server.Close()
		t.Fatal("public parent accepted")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "socket")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if server, err := ListenManagement(path, &managementMounter{}); err == nil {
		server.Close()
		t.Fatal("occupied socket was replaced")
	}
}
