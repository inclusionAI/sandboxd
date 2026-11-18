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

package nydus

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	remoteTransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
)

func TestFetchAndExtractBootstrapFallsBackToDirectFetchAfterProxyRetries(t *testing.T) {
	prevDelay := nydusFetchRetryDelay
	prevMaxDelay := nydusFetchRetryMaxDelay
	nydusFetchRetryDelay = time.Millisecond
	nydusFetchRetryMaxDelay = time.Millisecond
	defer func() {
		nydusFetchRetryDelay = prevDelay
		nydusFetchRetryMaxDelay = prevMaxDelay
	}()

	var proxyFetches int
	var directFetches int
	var extractCalls int

	client := &RegistryClient{
		fetchImageFn: func(_ context.Context, _ string, proxyURL string, useHTTP bool) (v1.Image, error) {
			if proxyURL != "" {
				proxyFetches++
			} else {
				if useHTTP {
					t.Fatal("origin fallback should default to HTTPS")
				}
				directFetches++
			}
			return empty.Image, nil
		},
		isNydusImageFn: func(v1.Image) (bool, error) {
			return true, nil
		},
		extractBootstrapFn: func(_ context.Context, _ v1.Image, outputDir string) (string, error) {
			extractCalls++
			if extractCalls <= nydusFetchRetryAttempts {
				return "", fmt.Errorf("failed to decompress layer: %w", &remoteTransport.Error{StatusCode: http.StatusInternalServerError})
			}
			return filepath.Join(outputDir, "bootstrap"), nil
		},
	}

	got, _, _, err := client.FetchAndExtractBootstrapWithImageConfig(context.Background(), "registry.example/test:nydus", t.TempDir(), "http://proxy.local")
	if err != nil {
		t.Fatalf("FetchAndExtractBootstrap() error = %v", err)
	}
	if got == "" {
		t.Fatalf("FetchAndExtractBootstrap() returned empty bootstrap path")
	}
	if proxyFetches != nydusFetchRetryAttempts {
		t.Fatalf("proxy fetch count = %d, want %d", proxyFetches, nydusFetchRetryAttempts)
	}
	if directFetches != 1 {
		t.Fatalf("direct fetch count = %d, want 1", directFetches)
	}
	if extractCalls != nydusFetchRetryAttempts+1 {
		t.Fatalf("extract call count = %d, want %d", extractCalls, nydusFetchRetryAttempts+1)
	}
}

func TestFetchAndExtractBootstrapRetriesOnUnexpectedEOF(t *testing.T) {
	prevDelay := nydusFetchRetryDelay
	prevMaxDelay := nydusFetchRetryMaxDelay
	nydusFetchRetryDelay = time.Millisecond
	nydusFetchRetryMaxDelay = time.Millisecond
	defer func() {
		nydusFetchRetryDelay = prevDelay
		nydusFetchRetryMaxDelay = prevMaxDelay
	}()

	var proxyFetches int
	var directFetches int

	client := &RegistryClient{
		fetchImageFn: func(_ context.Context, _ string, proxyURL string, _ bool) (v1.Image, error) {
			if proxyURL != "" {
				proxyFetches++
				return nil, fmt.Errorf("failed to fetch layer: %w", io.ErrUnexpectedEOF)
			}
			directFetches++
			return empty.Image, nil
		},
		isNydusImageFn: func(v1.Image) (bool, error) {
			return true, nil
		},
		extractBootstrapFn: func(_ context.Context, _ v1.Image, outputDir string) (string, error) {
			return filepath.Join(outputDir, "bootstrap"), nil
		},
	}

	got, _, _, err := client.FetchAndExtractBootstrapWithImageConfig(context.Background(), "registry.example/test:nydus", t.TempDir(), "http://proxy.local")
	if err != nil {
		t.Fatalf("FetchAndExtractBootstrap() error = %v", err)
	}
	if got == "" {
		t.Fatalf("FetchAndExtractBootstrap() returned empty bootstrap path")
	}
	if proxyFetches != nydusFetchRetryAttempts {
		t.Fatalf("proxy fetch count = %d, want %d", proxyFetches, nydusFetchRetryAttempts)
	}
	if directFetches != 1 {
		t.Fatalf("direct fetch count = %d, want 1", directFetches)
	}
}

func TestFetchAndExtractBootstrapSkipsDirectFallbackForNonRetryableError(t *testing.T) {
	prevDelay := nydusFetchRetryDelay
	prevMaxDelay := nydusFetchRetryMaxDelay
	nydusFetchRetryDelay = time.Millisecond
	nydusFetchRetryMaxDelay = time.Millisecond
	defer func() {
		nydusFetchRetryDelay = prevDelay
		nydusFetchRetryMaxDelay = prevMaxDelay
	}()

	var proxyFetches int
	var directFetches int

	client := &RegistryClient{
		fetchImageFn: func(_ context.Context, _ string, proxyURL string, _ bool) (v1.Image, error) {
			if proxyURL == "" {
				directFetches++
				return nil, fmt.Errorf("unexpected origin fetch")
			}
			proxyFetches++
			return nil, fmt.Errorf("failed to fetch manifest: %w", &remoteTransport.Error{StatusCode: http.StatusNotFound})
		},
	}

	if _, _, _, err := client.FetchAndExtractBootstrapWithImageConfig(context.Background(), "registry.example/test:nydus", t.TempDir(), "http://proxy.local"); err == nil {
		t.Fatalf("FetchAndExtractBootstrap() error = nil, want non-nil")
	}
	if proxyFetches != 1 {
		t.Fatalf("proxy fetch count = %d, want 1", proxyFetches)
	}
	if directFetches != 0 {
		t.Fatalf("direct fetch count = %d, want 0", directFetches)
	}
}

func TestNydusBootstrapProxyFallback(t *testing.T) {
	for _, tc := range []struct {
		name, stage, rateLimitSource string
		stall, hold429Body           bool
		originFailure                string
		wantOrigin                   int32
	}{
		{name: "proxy manifest 429", stage: "manifest", rateLimitSource: "proxy", wantOrigin: 1},
		{name: "proxy layer 429", stage: "layer", rateLimitSource: "proxy", wantOrigin: 1},
		{name: "proxy config 429 with stalled body", stage: "config", rateLimitSource: "proxy", hold429Body: true, wantOrigin: 1},
		{name: "proxy CONNECT 429", stage: "connect", rateLimitSource: "proxy", wantOrigin: 1},
		{name: "proxy layer stalls after headers", stage: "layer", stall: true, wantOrigin: 1},
		{name: "origin 429 after fallback", stage: "manifest", rateLimitSource: "proxy", originFailure: "429", wantOrigin: 1},
		{name: "origin stalls after fallback", stage: "manifest", rateLimitSource: "proxy", originFailure: "stall", wantOrigin: 1},
		{name: "upstream 429 via proxy", stage: "manifest", rateLimitSource: "backend"},
		{name: "unattributed 429 via proxy", stage: "manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldTimeout := nydusProxyTimeout
			if tc.stall {
				nydusProxyTimeout = 300 * time.Millisecond
			}
			oldPrepareTimeout := nydusPrepareTimeout
			if tc.originFailure == "stall" {
				nydusPrepareTimeout = 500 * time.Millisecond
			}
			t.Cleanup(func() {
				nydusProxyTimeout = oldTimeout
				nydusPrepareTimeout = oldPrepareTimeout
			})

			handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
			var originPulls, rejected atomic.Int32
			originHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/") && r.Header.Get("X-Test-Route") == "" {
					originPulls.Add(1)
					switch tc.originFailure {
					case "429":
						w.Header().Set("Retry-After", "30")
						w.WriteHeader(http.StatusTooManyRequests)
						return
					case "stall":
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
						<-r.Context().Done()
						return
					}
				}
				handler.ServeHTTP(w, r)
			})
			var origin *httptest.Server
			if tc.stage == "connect" {
				origin = httptest.NewTLSServer(originHandler)
			} else {
				origin = httptest.NewServer(originHandler)
			}
			t.Cleanup(origin.Close)
			originURL, err := url.Parse(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			imageURL := originURL.Host + "/test/image:latest"
			layerDigest := seedNydusRegistry(t, origin, imageURL)
			forward := httputil.NewSingleHostReverseProxy(originURL)
			requestCanceled := make(chan struct{}, 1)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bootstrapBlob := strings.HasSuffix(r.URL.Path, layerDigest)
				match := r.Method == http.MethodConnect && tc.stage == "connect" ||
					r.Method == http.MethodGet && (tc.stage == "manifest" && strings.Contains(r.URL.Path, "/manifests/") ||
						tc.stage == "config" && strings.Contains(r.URL.Path, "/blobs/") && !bootstrapBlob ||
						tc.stage == "layer" && bootstrapBlob)
				if !match {
					r.Header.Set("X-Test-Route", "proxy")
					forward.ServeHTTP(w, r)
					return
				}
				rejected.Add(1)
				if tc.stall {
					w.WriteHeader(http.StatusOK)
				} else {
					if tc.rateLimitSource != "" {
						w.Header().Set("X-Dragonfly-Error-Type", tc.rateLimitSource)
					}
					w.Header().Set("Retry-After", "30")
					w.WriteHeader(http.StatusTooManyRequests)
				}
				if tc.stall || tc.hold429Body {
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					select {
					case requestCanceled <- struct{}{}:
					default:
					}
				}
			}))
			t.Cleanup(proxy.Close)
			shared, err := imageregistry.NewClientWithRegistrySchemes("", map[string]string{originURL.Host: originURL.Scheme})
			if err != nil {
				t.Fatal(err)
			}
			client := NewRegistryClientFromShared(shared)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Now()
			path, _, _, err := client.FetchAndExtractBootstrapWithImageConfig(ctx, imageURL, filepath.Join(t.TempDir(), "daemon"), proxy.URL)
			t.Logf("elapsed=%s proxy_matches=%d origin_pulls=%d", time.Since(start), rejected.Load(), originPulls.Load())
			if got := originPulls.Load(); got != tc.wantOrigin {
				t.Fatalf("origin pulls = %d, want %d (err=%v)", got, tc.wantOrigin, err)
			}
			if got := rejected.Load(); got != 1 {
				t.Fatalf("matched proxy requests = %d, want 1", got)
			}
			if tc.originFailure == "stall" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expected shared preparation deadline, got %v", err)
				}
				return
			}
			if tc.wantOrigin == 0 || tc.originFailure == "429" {
				var limited *imageregistry.RateLimitError
				if !errors.As(err, &limited) || limited.Proxy || limited.RetryAfter != "30" {
					t.Fatalf("expected upstream rate limit with Retry-After, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "valid-bootstrap" {
				t.Fatalf("bootstrap = %q, error = %v", data, err)
			}
			if tc.stall || tc.hold429Body {
				select {
				case <-requestCanceled:
				case <-ctx.Done():
					t.Fatal("proxy did not observe cancellation of the stalled layer read")
				}
			}
		})
	}
}

func seedNydusRegistry(t *testing.T, origin *httptest.Server, imageURL string) string {
	t.Helper()
	const content = "valid-bootstrap"
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: BootstrapFileNameInLayer, Mode: 0644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layer, err := tarball.LayerFromReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer, Annotations: map[string]string{LayerAnnotationNydusBootstrap: "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(imageURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img, remote.WithTransport(origin.Client().Transport)); err != nil {
		t.Fatal(err)
	}
	digest, err := layer.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest.String()
}

func TestBootstrapExtractionPreservesOutputOnShortRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: BootstrapFileNameInLayer, Mode: 0644, Size: 10}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&buf)
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	if err := extractFile(context.Background(), tr, path); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("extractFile error = %v, want unexpected EOF", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
		t.Fatalf("output after failure = %q, error = %v", data, err)
	}
	if files, err := os.ReadDir(dir); err != nil || len(files) != 1 {
		t.Fatalf("unexpected leftover entries %v, error = %v", files, err)
	}
}

func TestNydusBootstrapCallerDeadlineDoesNotFallback(t *testing.T) {
	client := &RegistryClient{fetchImageFn: func(ctx context.Context, _ string, proxyURL string, _ bool) (v1.Image, error) {
		if proxyURL == "" {
			t.Fatal("unexpected fallback after caller deadline")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _, _, err := client.FetchAndExtractBootstrapWithImageConfig(ctx, "registry.example/test:nydus", filepath.Join(t.TempDir(), "daemon"), "http://proxy.local")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected caller deadline, got %v", err)
	}
}

func TestNydusBootstrapLegacyCachePreservesRateLimit(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "31")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(origin.Close)

	host := strings.TrimPrefix(origin.URL, "https://")
	shared, err := imageregistry.NewClientWithRegistrySchemes("", map[string]string{host: "https"})
	if err != nil {
		t.Fatal(err)
	}
	client := NewRegistryClientFromShared(shared)
	imageURL := host + "/test/legacy:latest"
	outputDir := filepath.Join(t.TempDir(), "mount")
	path := writeBootstrapForTest(t, outputDir, "cached-bootstrap")
	cache := client.getBootstrapCache()
	if err := cache.Store(imageURL, outputDir, path, []string{}, testImageProcess); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cache.rootForOutput(outputDir).processPath(bootstrapCacheKey(imageURL))); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _, err = client.FetchAndExtractBootstrapWithImageConfig(ctx, imageURL, outputDir, "http://127.0.0.1:1")
	var limited *imageregistry.RateLimitError
	if !errors.As(err, &limited) || limited.Proxy || limited.RetryAfter != "31" {
		t.Fatalf("expected origin rate limit with Retry-After, got %v", err)
	}
}

func TestNydusBootstrapProxyDeadlineInterruptsRetryBackoff(t *testing.T) {
	oldTimeout, oldDelay := nydusProxyTimeout, nydusFetchRetryDelay
	nydusProxyTimeout, nydusFetchRetryDelay = 100*time.Millisecond, 5*time.Second
	t.Cleanup(func() { nydusProxyTimeout, nydusFetchRetryDelay = oldTimeout, oldDelay })

	var proxyPulls, originPulls int
	client := &RegistryClient{
		fetchImageFn: func(_ context.Context, _ string, proxy string, _ bool) (v1.Image, error) {
			if proxy != "" {
				proxyPulls++
				return nil, &remoteTransport.Error{StatusCode: http.StatusInternalServerError}
			}
			originPulls++
			return empty.Image, nil
		},
		isNydusImageFn: func(v1.Image) (bool, error) { return true, nil },
		extractBootstrapFn: func(_ context.Context, _ v1.Image, outputDir string) (string, error) {
			return writeBootstrapForTest(t, outputDir, "fallback"), nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _, err := client.FetchAndExtractBootstrapWithImageConfig(ctx, "registry.example/test:nydus", filepath.Join(t.TempDir(), "daemon"), "http://proxy.local")
	if err != nil || proxyPulls != 1 || originPulls != 1 {
		t.Fatalf("proxy pulls = %d, origin pulls = %d, error = %v", proxyPulls, originPulls, err)
	}
}

func TestRetryableProxyStatusAllowsFallback(t *testing.T) {
	err := &remoteTransport.Error{StatusCode: 499}
	if !shouldRetryNydusFetch(err) || !shouldFallbackFromProxy(err) {
		t.Fatal("proxy 499 should allow fallback after retries")
	}
}
