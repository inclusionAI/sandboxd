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
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
)

var testImageProcess = &imageconfig.Process{}

func TestFetchAndExtractBootstrapReusesCachedBootstrap(t *testing.T) {
	rootDir := t.TempDir()
	imageURL := "registry.example/test:nydus"
	firstOutputDir := filepath.Join(rootDir, "daemon-1")
	secondOutputDir := filepath.Join(rootDir, "daemon-2")

	var proxyFetches int
	var extractCalls int

	client := &RegistryClient{
		bootstrapCache: newBootstrapCache(),
		fetchImageFn: func(context.Context, string, string, bool) (v1.Image, error) {
			proxyFetches++
			return empty.Image, nil
		},
		isNydusImageFn: func(v1.Image) (bool, error) {
			return true, nil
		},
		extractBootstrapFn: func(_ context.Context, _ v1.Image, outputDir string) (string, error) {
			extractCalls++
			outputPath := bootstrapOutputPath(outputDir)
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return "", err
			}
			if err := os.WriteFile(outputPath, []byte("cached-bootstrap"), 0644); err != nil {
				return "", err
			}
			return outputPath, nil
		},
	}

	firstPath, _, _, err := client.FetchAndExtractBootstrapWithImageConfig(context.Background(), imageURL, firstOutputDir, "http://proxy.local")
	if err != nil {
		t.Fatalf("first FetchAndExtractBootstrap() error = %v", err)
	}

	cachePath := filepath.Join(rootDir, bootstrapCacheDirName, bootstrapCacheKey(imageURL)+bootstrapCacheFileExt)
	assertSameFile(t, firstPath, cachePath)

	secondPath, _, _, err := client.FetchAndExtractBootstrapWithImageConfig(context.Background(), imageURL, secondOutputDir, "http://proxy.local")
	if err != nil {
		t.Fatalf("second FetchAndExtractBootstrap() error = %v", err)
	}

	if proxyFetches != 1 {
		t.Fatalf("proxy fetch count = %d, want 1", proxyFetches)
	}
	if extractCalls != 1 {
		t.Fatalf("extract call count = %d, want 1", extractCalls)
	}
	assertSameFile(t, secondPath, cachePath)
	assertSameFile(t, firstPath, secondPath)
}

func TestBootstrapCacheEvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Unix(1710000000, 0)
	cache := newBootstrapCacheWithCapacity(2)
	cache.now = func() time.Time {
		return now
	}

	rootDir := t.TempDir()
	firstOutputDir := filepath.Join(rootDir, "daemon-1")
	secondOutputDir := filepath.Join(rootDir, "daemon-2")
	thirdOutputDir := filepath.Join(rootDir, "daemon-3")
	hitOutputDir := filepath.Join(rootDir, "daemon-hit")

	firstURL := "registry.example/test:first"
	secondURL := "registry.example/test:second"
	thirdURL := "registry.example/test:third"

	firstPath := writeBootstrapForTest(t, firstOutputDir, "first")
	if err := cache.Store(firstURL, firstOutputDir, firstPath, nil, testImageProcess); err != nil {
		t.Fatalf("Store(first) error = %v", err)
	}

	now = now.Add(time.Second)
	secondPath := writeBootstrapForTest(t, secondOutputDir, "second")
	if err := cache.Store(secondURL, secondOutputDir, secondPath, nil, testImageProcess); err != nil {
		t.Fatalf("Store(second) error = %v", err)
	}

	now = now.Add(time.Second)
	hitPath, _, _, hit, err := cache.Link(firstURL, hitOutputDir)
	if err != nil {
		t.Fatalf("Link(first) error = %v", err)
	}
	if !hit {
		t.Fatalf("Link(first) hit = false, want true")
	}
	assertSameFile(t, firstPath, hitPath)

	now = now.Add(time.Second)
	thirdPath := writeBootstrapForTest(t, thirdOutputDir, "third")
	if err := cache.Store(thirdURL, thirdOutputDir, thirdPath, nil, testImageProcess); err != nil {
		t.Fatalf("Store(third) error = %v", err)
	}

	firstCachePath := filepath.Join(rootDir, bootstrapCacheDirName, bootstrapCacheKey(firstURL)+bootstrapCacheFileExt)
	secondCachePath := filepath.Join(rootDir, bootstrapCacheDirName, bootstrapCacheKey(secondURL)+bootstrapCacheFileExt)
	thirdCachePath := filepath.Join(rootDir, bootstrapCacheDirName, bootstrapCacheKey(thirdURL)+bootstrapCacheFileExt)

	if !fileExists(firstCachePath) {
		t.Fatalf("first cache entry was evicted unexpectedly")
	}
	if fileExists(secondCachePath) {
		t.Fatalf("second cache entry still exists, want evicted")
	}
	if !fileExists(thirdCachePath) {
		t.Fatalf("third cache entry missing after store")
	}
}

func TestBootstrapCacheEnvSidecar(t *testing.T) {
	cache := newBootstrapCache()
	rootDir := t.TempDir()

	imageURL := "registry.example/test:v1"
	outputDir1 := filepath.Join(rootDir, "daemon-1")
	outputDir2 := filepath.Join(rootDir, "daemon-2")

	env := []string{"FOO=bar", "BAZ=qux"}
	process := &imageconfig.Process{
		Entrypoint: []string{"/entrypoint"},
		Cmd:        []string{"serve"},
		Cwd:        "/app",
		User:       "1000:1000",
	}

	// Store with env
	bsPath := writeBootstrapForTest(t, outputDir1, "bootstrap-data")
	if err := cache.Store(imageURL, outputDir1, bsPath, env, process); err != nil {
		t.Fatalf("Store error = %v", err)
	}

	// Link should return cached env
	_, cachedEnv, cachedProcess, hit, err := cache.Link(imageURL, outputDir2)
	if err != nil {
		t.Fatalf("Link error = %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit")
	}
	if len(cachedEnv) != 2 || cachedEnv[0] != "FOO=bar" || cachedEnv[1] != "BAZ=qux" {
		t.Fatalf("expected cached env [FOO=bar BAZ=qux], got %v", cachedEnv)
	}
	if !reflect.DeepEqual(cachedProcess, process) {
		t.Fatalf("cached process = %#v, want %#v", cachedProcess, process)
	}
}

func TestBootstrapCacheEnvSidecar_OldEntryWithoutEnv(t *testing.T) {
	cache := newBootstrapCache()
	rootDir := t.TempDir()

	imageURL := "registry.example/test:old"
	outputDir1 := filepath.Join(rootDir, "daemon-1")
	outputDir2 := filepath.Join(rootDir, "daemon-2")

	// Simulate old cache entry: store bootstrap, then delete env sidecar
	bsPath := writeBootstrapForTest(t, outputDir1, "old-bootstrap")
	if err := cache.Store(imageURL, outputDir1, bsPath, []string{"OLD=val"}, testImageProcess); err != nil {
		t.Fatalf("Store error = %v", err)
	}
	key := bootstrapCacheKey(imageURL)
	envPath := filepath.Join(rootDir, bootstrapCacheDirName, key+bootstrapCacheEnvExt)
	os.Remove(envPath) // simulate old entry without sidecar

	// Link should return nil env (not cached)
	_, cachedEnv, _, hit, err := cache.Link(imageURL, outputDir2)
	if err != nil {
		t.Fatalf("Link error = %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit")
	}
	if cachedEnv != nil {
		t.Fatalf("expected nil env for old entry, got %v", cachedEnv)
	}
}

func TestBootstrapCacheEnvSidecar_EmptyEnv(t *testing.T) {
	cache := newBootstrapCache()
	rootDir := t.TempDir()

	imageURL := "registry.example/test:noenv"
	outputDir1 := filepath.Join(rootDir, "daemon-1")
	outputDir2 := filepath.Join(rootDir, "daemon-2")

	// Store with nil env (image has no env vars)
	bsPath := writeBootstrapForTest(t, outputDir1, "bootstrap-noenv")
	if err := cache.Store(imageURL, outputDir1, bsPath, nil, testImageProcess); err != nil {
		t.Fatalf("Store error = %v", err)
	}

	// Link should return non-nil empty slice (env was cached, just empty)
	_, cachedEnv, _, hit, err := cache.Link(imageURL, outputDir2)
	if err != nil {
		t.Fatalf("Link error = %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit")
	}
	if cachedEnv == nil {
		t.Fatal("expected non-nil env (empty slice), got nil")
	}
	if len(cachedEnv) != 0 {
		t.Fatalf("expected empty env, got %v", cachedEnv)
	}
}

func writeBootstrapForTest(t *testing.T, outputDir string, content string) string {
	t.Helper()

	outputPath := bootstrapOutputPath(outputDir)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", outputDir, err)
	}
	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", outputPath, err)
	}
	return outputPath
}

func assertSameFile(t *testing.T, pathA string, pathB string) {
	t.Helper()

	infoA, err := os.Stat(pathA)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", pathA, err)
	}
	infoB, err := os.Stat(pathB)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", pathB, err)
	}
	if !os.SameFile(infoA, infoB) {
		t.Fatalf("%s and %s are not hardlinked to the same file", pathA, pathB)
	}
}
