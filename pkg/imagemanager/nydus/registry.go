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
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/avast/retry-go/v4"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	remoteTransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sirupsen/logrus"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
)

const nydusFetchRetryAttempts = 3

var (
	nydusPrepareTimeout     = 45 * time.Second
	nydusProxyTimeout       = 15 * time.Second
	nydusFetchRetryDelay    = time.Second
	nydusFetchRetryMaxDelay = 5 * time.Second
)

// RegistryClient is the Nydus-facing wrapper over shared registry client.
type RegistryClient struct {
	shared *imageregistry.Client

	bootstrapCache     *bootstrapCache
	bootstrapCacheLock sync.Mutex

	// The following hooks are for unit tests only.
	fetchImageFn       func(context.Context, string, string, bool) (v1.Image, error)
	isNydusImageFn     func(v1.Image) (bool, error)
	extractBootstrapFn func(context.Context, v1.Image, string) (string, error)
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

// RegistryScheme exposes the shared operator policy to the actual ROFS backend.
func (c *RegistryClient) RegistryScheme(imageRef string) (string, bool) {
	if c == nil {
		return "", false
	}
	return c.shared.RegistryScheme(imageRef)
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
	if c == nil || c.shared == nil {
		return nil, fmt.Errorf("registry client is not initialized")
	}
	return c.shared.FetchImageWithFallback(ctx, imageRef, proxyURL)
}

// bootstrapResult holds the output of a fetch+check+extract pipeline.
type bootstrapResult struct {
	Path            string
	Env             []string
	ImageProcess    *imageconfig.Process
	FetchDuration   time.Duration
	CheckDuration   time.Duration
	ExtractDuration time.Duration
}

// FetchAndExtractBootstrap fetches a Nydus image and returns its bootstrap and
// environment, preserving the original API for existing callers.
func (c *RegistryClient) FetchAndExtractBootstrap(ctx context.Context, imageURL string, outputDir string, proxyURL string) (string, []string, error) {
	path, env, _, err := c.FetchAndExtractBootstrapWithImageConfig(ctx, imageURL, outputDir, proxyURL)
	return path, env, err
}

// FetchAndExtractBootstrapWithImageConfig also returns process metadata from
// the OCI image config.
func (c *RegistryClient) FetchAndExtractBootstrapWithImageConfig(ctx context.Context, imageURL string, outputDir string, proxyURL string) (string, []string, *imageconfig.Process, error) {
	timing, ctx := StartNydusTimedOperation(ctx, "nydus.FetchAndExtractBootstrap", imageURL)
	defer timing.End()

	ctx, cancel := context.WithTimeout(ctx, nydusPrepareTimeout)
	defer cancel()

	cache := c.getBootstrapCache()
	imageRef := imageregistry.NormalizeImageRef(imageURL)
	var result bootstrapResult

	stageStart := time.Now()
	if cachePath, cachedEnv, cachedProcess, hit, err := cache.Link(imageURL, outputDir); err != nil {
		logrus.WithError(err).Warnf("failed to reuse cached Nydus bootstrap for %s", imageURL)
	} else if hit {
		result.Path = cachePath
		timing.Stage("bootstrap_cache_hit", time.Since(stageStart))

		if cachedEnv != nil && cachedProcess != nil {
			// Image config was cached alongside bootstrap — no registry call needed.
			return result.Path, cachedEnv, cachedProcess, nil
		}

		// Old cache entry without complete image config — fall back to registry fetch.
		stageStart = time.Now()
		var env []string
		var process *imageconfig.Process
		err := retryNydusFetch(ctx, imageURL, shouldRetryDirectNydusFetch, func() error {
			var err error
			env, process, err = c.fetchImageProcess(ctx, imageRef)
			return err
		})
		timing.Stage("fetch_env_on_cache_hit", time.Since(stageStart))
		if err != nil {
			err = fmt.Errorf("failed to resolve image config for %s: %w", imageURL, err)
			timing.Fail(err)
			return "", nil, nil, err
		}
		if cacheErr := cache.Store(imageURL, outputDir, result.Path, env, process); cacheErr != nil {
			logrus.WithError(cacheErr).Warnf("failed to refresh Nydus image config cache for %s", imageURL)
		}
		return result.Path, env, process, nil
	}

	fetchAndExtract := func(parent context.Context, proxy string) (r bootstrapResult, retErr error) {
		ctx, stop := imageregistry.WithRateLimitCancellation(parent)
		defer stop()
		defer func() {
			if cause := context.Cause(ctx); cause != nil {
				retErr = cause
			}
		}()

		stageStart := time.Now()
		img, err := c.FetchImage(ctx, imageRef, proxy, proxy != "")
		if err != nil {
			return r, fmt.Errorf("failed to fetch image %s: %w", imageURL, err)
		}
		r.FetchDuration = time.Since(stageStart)

		r.Env, r.ImageProcess, err = readImageProcess(img)
		if err != nil {
			return r, err
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
			return r, fmt.Errorf("failed to extract bootstrap: %w", imageregistry.ClassifyError(err))
		}
		r.ExtractDuration = time.Since(stageStart)
		return r, nil
	}

	attemptCtx := ctx
	shouldRetry := shouldRetryDirectNydusFetch
	if proxyURL != "" {
		var stopProxy context.CancelFunc
		attemptCtx, stopProxy = context.WithTimeout(ctx, nydusProxyTimeout)
		defer stopProxy()
		shouldRetry = shouldRetryNydusFetch
	}
	attemptStart := time.Now()
	err := retryNydusFetch(attemptCtx, imageURL, shouldRetry, func() error {
		var err error
		result, err = fetchAndExtract(attemptCtx, proxyURL)
		return err
	})

	if err != nil && proxyURL != "" && ctx.Err() == nil && shouldFallbackFromProxy(err) {
		logrus.WithFields(logrus.Fields{
			"image": imageURL, "proxy_elapsed_ms": time.Since(attemptStart).Milliseconds(),
		}).WithError(err).Warn("Nydus bootstrap proxy failed, fallback to origin")
		proxyErr := err
		result, err = fetchAndExtract(ctx, "")
		if err != nil {
			err = fmt.Errorf("Nydus bootstrap proxy failed (%v); origin failed: %w", proxyErr, err)
		}
	}

	if err != nil {
		timing.Fail(err)
		return "", nil, nil, err
	}

	if cacheErr := cache.Store(imageURL, outputDir, result.Path, result.Env, result.ImageProcess); cacheErr != nil {
		logrus.WithError(cacheErr).Warnf("failed to cache Nydus bootstrap for %s", imageURL)
	}

	timing.Stage("fetch_image", result.FetchDuration)
	timing.Stage("check_nydus_format", result.CheckDuration)
	timing.Stage("extract_bootstrap", result.ExtractDuration)

	return result.Path, result.Env, imageconfig.Clone(result.ImageProcess), nil
}

func (c *RegistryClient) fetchImageProcess(ctx context.Context, imageRef string) ([]string, *imageconfig.Process, error) {
	ctx, stop := imageregistry.WithRateLimitCancellation(ctx)
	defer stop()
	img, err := c.FetchImage(ctx, imageRef, "", false)
	var env []string
	var process *imageconfig.Process
	if err == nil {
		env, process, err = readImageProcess(img)
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, nil, cause
	}
	return env, process, err
}

func readImageProcess(img v1.Image) ([]string, *imageconfig.Process, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read image config: %w", imageregistry.ClassifyError(err))
	}
	if cfg == nil {
		return nil, nil, fmt.Errorf("empty image config")
	}
	return cfg.Config.Env, imageconfig.FromOCI(cfg.Config), nil
}

func retryNydusFetch(ctx context.Context, imageURL string, shouldRetry func(error) bool, fetch func() error) error {
	return retry.Do(
		func() error {
			if err := context.Cause(ctx); err != nil {
				return err
			}
			return fetch()
		},
		retry.Attempts(nydusFetchRetryAttempts),
		retry.Delay(nydusFetchRetryDelay),
		retry.MaxDelay(nydusFetchRetryMaxDelay),
		retry.RetryIf(shouldRetry),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			logrus.Warnf("Retry attempt %d for image %s: %v", n+1, imageURL, err)
		}),
		retry.Context(ctx),
	)
}

func shouldRetryDirectNydusFetch(err error) bool {
	if shouldRetryNydusFetch(err) {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Temporary()
}

func shouldFallbackFromProxy(err error) bool {
	var rateLimit *imageregistry.RateLimitError
	if errors.As(err, &rateLimit) {
		return rateLimit.Proxy
	}
	if shouldRetryNydusFetch(err) {
		return true
	}
	var response *remoteTransport.Error
	if errors.As(err, &response) {
		return response.StatusCode >= http.StatusInternalServerError
	}
	var networkErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.As(err, &networkErr)
}

func shouldRetryNydusFetch(err error) bool {
	if err == nil {
		return false
	}

	var transportErr *remoteTransport.Error
	if errors.As(err, &transportErr) {
		switch transportErr.StatusCode {
		case http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway,
			http.StatusServiceUnavailable, http.StatusGatewayTimeout, 499, 522:
			return true
		}
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
