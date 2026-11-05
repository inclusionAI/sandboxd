package imageregistry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMetadataUsesStandardBearerReuseAndRefresh(t *testing.T) {
	payload := []byte(`{"rootfs":{"type":"layers","diff_ids":[]}}`)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
	var tokenCalls, generation atomic.Int32
	generation.Store(1)
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "password" || r.URL.Query().Get("scope") != "repository:managed/image:pull" {
			t.Errorf("token request did not retain account and pull scope")
			http.Error(w, "denied", 401)
			return
		}
		tokenCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("token-%d", generation.Load()), "expires_in": 900})
	}))
	defer tokens.Close()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" || r.Header.Get("Authorization") != fmt.Sprintf("Bearer token-%d", generation.Load()) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+tokens.URL+`/token",service="registry",scope="repository:managed/image:pull"`)
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer registry.Close()
	host := strings.TrimPrefix(registry.URL, "http://")
	authFile := filepath.Join(t.TempDir(), "auth.json")
	config, _ := json.Marshal(map[string]any{host: map[string]string{"Auth": base64.StdEncoding.EncodeToString([]byte("user:password"))}})
	if err := os.WriteFile(authFile, config, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(authFile)
	if err != nil {
		t.Fatal(err)
	}
	ref := host + "/managed/image@" + digest
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 3; i++ {
		if i == 1 {
			cancel() // Cached auth must not retain the first caller's context.
			ctx = context.Background()
		}
		got, media, err := client.Metadata(ctx, ref, "blobs", true)
		if err != nil || string(got) != string(payload) || media != "application/json" {
			t.Fatalf("metadata: %s %s %v", got, media, err)
		}
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token was not reused: %d exchanges", tokenCalls.Load())
	}
	generation.Store(2)
	if _, _, err := client.Metadata(ctx, ref, "blobs", true); err != nil || tokenCalls.Load() != 2 {
		t.Fatalf("token refresh failed: %v, exchanges %d", err, tokenCalls.Load())
	}
	bad := host + "/managed/image@sha256:" + strings.Repeat("0", 64)
	if _, _, err := client.Metadata(ctx, bad, "blobs", true); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("unverified Registry metadata accepted: %v", err)
	}
}
