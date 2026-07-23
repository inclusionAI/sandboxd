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
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	remoteTransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sirupsen/logrus"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
)

const nydusFetchRetryAttempts = 3

var (
	nydusFetchRetryDelay    = time.Second
	nydusFetchRetryMaxDelay = 5 * time.Second
)

// RegistryClient is the Nydus-facing wrapper over shared registry client.
type RegistryClient struct {
	shared *imageregistry.Client

	bootstrapCache     *bootstrapCache
	bootstrapCacheLock sync.Mutex

	// The following hooks are for unit tests only.
	fetchImageFn             func(context.Context, string, string, bool) (v1.Image, error)
	fetchImageWithFallbackFn func(context.Context, string, string) (v1.Image, error)
	isNydusImageFn           func(v1.Image) (bool, error)
	extractBootstrapFn       func(context.Context, v1.Image, string) (string, error)
}

// NewRegistryClientFromShared creates a Nydus registry client wrapper from an existing shared client.
func NewRegistryClientFromShared(shared *imageregistry.Client) *RegistryClient {
	if shared == nil {
		return nil
	}
	return &RegistryClient{
		shared:         shared,
		bootstrapCache: newBootstrapCache(),
	}
}

// FetchImage fetches an image from the registry with authentication and optional proxy.
func (c *RegistryClient) FetchImage(ctx context.Context, imageRef string, proxyURL string, useHTTP bool) (v1.Image, error) {
	if c != nil && c.fetchImageFn != nil {
		return c.fetchImageFn(ctx, imageRef, proxyURL, useHTTP)
	}
	if c == nil || c.shared == nil {
		return nil, fmt.Errorf("registry client is not initialized")
	}
	return c.shared.FetchImage(ctx, imageRef, proxyURL, useHTTP)
}

// FetchImageWithFallback fetches image through shared fallback strategy.
func (c *RegistryClient) FetchImageWithFallback(ctx context.Context, imageRef string, proxyURL string) (v1.Image, error) {
	if c != nil && c.fetchImageWithFallbackFn != nil {
		return c.fetchImageWithFallbackFn(ctx, imageRef, proxyURL)
	}
	if c == nil || c.shared == nil {
		return nil, fmt.Errorf("registry client is not initialized")
	}
	return c.shared.FetchImageWithFallback(ctx, imageRef, proxyURL)
}

// bootstrapResult holds the output of a fetch+check+extract pipeline.
type bootstrapResult struct {
	Path            string
	Env             []string
	FetchDuration   time.Duration
	CheckDuration   time.Duration
	ExtractDuration time.Duration
}

// FetchAndExtractBootstrap fetches a Nydus image from registry and extracts bootstrap to outputDir.
// It also extracts environment variables from the image config.
func (c *RegistryClient) FetchAndExtractBootstrap(ctx context.Context, imageURL string, outputDir string, proxyURL string) (string, []string, error) {
	timing, ctx := StartNydusTimedOperation(ctx, "nydus.FetchAndExtractBootstrap", imageURL)
	defer timing.End()

	cache := c.getBootstrapCache()
	var result bootstrapResult
	var attemptCount int
	var lastAttemptErr error

	stageStart := time.Now()
	if cachePath, cachedEnv, hit, err := cache.Link(imageURL, outputDir); err != nil {
		logrus.WithError(err).Warnf("failed to reuse cached Nydus bootstrap for %s", imageURL)
	} else if hit {
		result.Path = cachePath
		timing.Stage("bootstrap_cache_hit", time.Since(stageStart))

		if cachedEnv != nil {
			// Env was cached alongside bootstrap — no registry call needed.
			return result.Path, cachedEnv, nil
		}

		// Old cache entry without env sidecar — fall back to registry fetch.
		var env []string
		stageStart = time.Now()
		if img, fetchErr := c.FetchImage(ctx, imageURL, "", false); fetchErr != nil {
			logrus.WithError(fetchErr).Debugf("bootstrap cache hit but failed to fetch image config for env: %s", imageURL)
		} else if img != nil {
			if cfg, cfgErr := img.ConfigFile(); cfgErr == nil && cfg != nil {
				env = cfg.Config.Env
			} else if cfgErr != nil {
				logrus.WithError(cfgErr).Debugf("bootstrap cache hit but failed to parse image config for env: %s", imageURL)
			}
		}
		timing.Stage("fetch_env_on_cache_hit", time.Since(stageStart))

		return result.Path, env, nil
	}

	fetchAndExtract := func(useProxyFetch bool) (bootstrapResult, error) {
		var r bootstrapResult

		stageStart := time.Now()
		var (
			img v1.Image
			err error
		)
		if useProxyFetch {
			img, err = c.FetchImageWithFallback(ctx, imageURL, proxyURL)
		} else {
			img, err = c.FetchImage(ctx, imageURL, "", false)
		}
		if err != nil {
			return r, fmt.Errorf("failed to fetch image %s: %w", imageURL, err)
		}
		r.FetchDuration = time.Since(stageStart)

		// Extract env from image config
		if img != nil {
			if cfg, cfgErr := img.ConfigFile(); cfgErr == nil && cfg != nil {
				r.Env = cfg.Config.Env
				if len(r.Env) == 0 {
					logrus.Debugf("image config has no env vars: %s", imageURL)
				}
			} else if cfgErr != nil {
				logrus.WithError(cfgErr).Warnf("failed to read image config for env extraction: %s", imageURL)
			}
		}

		stageStart = time.Now()
		isNydus, err := c.isNydusImage(img)
		if err != nil {
			return r, fmt.Errorf("failed to check if image is Nydus: %w", err)
		}
		if !isNydus {
			return r, fmt.Errorf("image %s is not a Nydus image", imageURL)
		}
		r.CheckDuration = time.Since(stageStart)

		stageStart = time.Now()
		r.Path, err = c.extractBootstrap(ctx, img, outputDir)
		if err != nil {
			return r, fmt.Errorf("failed to extract bootstrap: %w", err)
		}
		r.ExtractDuration = time.Since(stageStart)

		return r, nil
	}

	err := retry.Do(
		func() error {
			attemptCount++
			r, err := fetchAndExtract(true)
			if err != nil {
				lastAttemptErr = err
				return err
			}
			result = r
			lastAttemptErr = nil
			return nil
		},
		retry.Attempts(nydusFetchRetryAttempts),
		retry.Delay(nydusFetchRetryDelay),
		retry.MaxDelay(nydusFetchRetryMaxDelay),
		retry.RetryIf(shouldRetryNydusFetch),
		retry.OnRetry(func(n uint, err error) {
			logrus.Warnf("Retry attempt %d for image %s: %v", n+1, imageURL, err)
		}),
		retry.Context(ctx),
	)

	if err != nil && proxyURL != "" && attemptCount >= nydusFetchRetryAttempts && shouldRetryNydusFetch(lastAttemptErr) {
		logrus.Warnf("proxy retries exhausted for image %s, retry once without proxy: %v", imageURL, err)
		r, directErr := fetchAndExtract(false)
		if directErr == nil {
			result = r
			err = nil
		} else {
			err = fmt.Errorf("proxy retries exhausted for image %s: %v; final non-proxy attempt failed: %w", imageURL, err, directErr)
		}
	}

	if err != nil {
		timing.Fail(err)
		return "", nil, err
	}

	if cacheErr := cache.Store(imageURL, outputDir, result.Path, result.Env); cacheErr != nil {
		logrus.WithError(cacheErr).Warnf("failed to cache Nydus bootstrap for %s", imageURL)
	}

	timing.Stage("fetch_image", result.FetchDuration)
	timing.Stage("check_nydus_format", result.CheckDuration)
	timing.Stage("extract_bootstrap", result.ExtractDuration)

	return result.Path, result.Env, nil
}

func shouldRetryNydusFetch(err error) bool {
	if err == nil {
		return false
	}

	var transportErr *remoteTransport.Error
	if errors.As(err, &transportErr) && transportErr.StatusCode == http.StatusInternalServerError {
		return true
	}

	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	return false
}

func (c *RegistryClient) isNydusImage(img v1.Image) (bool, error) {
	if c != nil && c.isNydusImageFn != nil {
		return c.isNydusImageFn(img)
	}
	return IsNydusImage(img)
}

func (c *RegistryClient) extractBootstrap(ctx context.Context, img v1.Image, outputDir string) (string, error) {
	if c != nil && c.extractBootstrapFn != nil {
		return c.extractBootstrapFn(ctx, img, outputDir)
	}
	return ExtractBootstrap(ctx, img, outputDir)
}

func (c *RegistryClient) getBootstrapCache() *bootstrapCache {
	if c == nil {
		return newBootstrapCache()
	}

	c.bootstrapCacheLock.Lock()
	defer c.bootstrapCacheLock.Unlock()

	if c.bootstrapCache == nil {
		c.bootstrapCache = newBootstrapCache()
	}
	return c.bootstrapCache
}
