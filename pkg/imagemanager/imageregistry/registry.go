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

package imageregistry

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/registryauth"
)

// RegistryAuthEntry represents authentication credentials for a registry.
type RegistryAuthEntry = registryauth.Entry

// RegistryAuthsConfig maps registry hosts/repos to their authentication credentials.
type RegistryAuthsConfig = registryauth.Config

const (
	maxRegistryConnsPerHost     = 32
	maxRegistryIdleConnsPerHost = 32
	maxRegistryIdleConns        = maxRegistryIdleConnsPerHost * 2
)

// Client handles image fetching from container registries with authentication.
type Client struct {
	keychain           authn.Keychain
	transportCache     map[string]*registryTransport
	transportCacheLock sync.RWMutex
}

// NewClient creates a registry client by loading credentials from registry_auths.json.
func NewClient(registryAuthsPath string) (*Client, error) {
	if registryAuthsPath == "" {
		return &Client{
			keychain:       &registryKeychain{},
			transportCache: make(map[string]*registryTransport),
		}, nil
	}

	auths, err := registryauth.Load(registryAuthsPath)
	if err != nil {
		return nil, err
	}

	return &Client{
		keychain:       &registryKeychain{auths: auths},
		transportCache: make(map[string]*registryTransport),
	}, nil
}

// NormalizeImageRef removes protocol prefixes and returns a canonical image reference.
func NormalizeImageRef(imageRef string) string {
	ref := strings.TrimPrefix(imageRef, "https://")
	ref = strings.TrimPrefix(ref, "http://")
	return ref
}

// FetchImageWithFallback fetches image with optional HTTP proxy and HTTPS fallback.
func (c *Client) FetchImageWithFallback(ctx context.Context, imageRef string, proxyURL string) (v1.Image, error) {
	normalized := NormalizeImageRef(imageRef)

	if proxyURL != "" {
		img, err := c.FetchImage(ctx, normalized, proxyURL, true)
		if err == nil {
			return img, nil
		}
		logrus.Warnf("failed to fetch image %s via HTTP proxy, fallback to HTTPS: %v", imageRef, err)
	}

	return c.FetchImage(ctx, normalized, "", false)
}

// FetchImage fetches an image from the registry with authentication and optional proxy.
func (c *Client) FetchImage(ctx context.Context, imageRef string, proxyURL string, useHTTP bool) (v1.Image, error) {
	if c == nil {
		return nil, fmt.Errorf("registry client is nil")
	}

	stageStart := time.Now()
	parseOpts := []name.Option{}
	if useHTTP {
		parseOpts = append(parseOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageRef, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %s: %w", imageRef, err)
	}
	parseDuration := time.Since(stageStart)

	stageStart = time.Now()
	options := []remote.Option{remote.WithAuthFromKeychain(c.keychain)}
	transport := c.getOrCreateTransport(proxyURL)
	options = append(options, remote.WithTransport(transport))
	transportDuration := time.Since(stageStart)

	stageStart = time.Now()
	img, err := remote.Image(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image %s: %w", imageRef, err)
	}
	fetchDuration := time.Since(stageStart)

	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("fetch_image_details",
			trace.WithAttributes(
				attribute.Int64("parse_reference_ms", parseDuration.Milliseconds()),
				attribute.Int64("setup_transport_ms", transportDuration.Milliseconds()),
				attribute.Int64("registry_fetch_ms", fetchDuration.Milliseconds()),
			),
		)
	}

	return img, nil
}

func (c *Client) getOrCreateTransport(proxyURL string) *registryTransport {
	cacheKey := proxyURL

	c.transportCacheLock.RLock()
	if transport, exists := c.transportCache[cacheKey]; exists {
		c.transportCacheLock.RUnlock()
		return transport
	}
	c.transportCacheLock.RUnlock()

	c.transportCacheLock.Lock()
	defer c.transportCacheLock.Unlock()

	if transport, exists := c.transportCache[cacheKey]; exists {
		return transport
	}

	transport := &registryTransport{base: newRegistryBaseTransport(proxyURL)}
	c.transportCache[cacheKey] = transport
	return transport
}

func newRegistryBaseTransport(proxyURL string) *http.Transport {
	transport := remote.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = maxRegistryConnsPerHost
	transport.MaxIdleConnsPerHost = maxRegistryIdleConnsPerHost
	transport.MaxIdleConns = maxRegistryIdleConns
	// TODO: honor the registry skip_verify setting instead of applying this
	// behavior to every HTTPS registry.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if proxyURL == "" {
		return transport
	}

	proxyURLParsed, err := url.Parse(proxyURL)
	if err != nil {
		logrus.Warnf("Failed to parse proxy URL %s: %v", proxyURL, err)
		return transport
	}

	transport.Proxy = http.ProxyURL(proxyURLParsed)
	return transport
}

type registryTransport struct {
	base         *http.Transport
	roundTripper http.RoundTripper
}

func (t *registryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var conn net.Conn
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			conn = info.Conn
		},
	}
	req = req.Clone(httptrace.WithClientTrace(req.Context(), trace))

	roundTripper := t.roundTripper
	if roundTripper == nil {
		roundTripper = t.base
	}

	resp, err := roundTripper.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}

	if shouldCloseConnOnServerError(resp) && conn != nil {
		resp.Body = &closeConnBody{
			ReadCloser: resp.Body,
			conn:       conn,
		}
		resp.Close = true
	}

	return resp, nil
}

func shouldCloseConnOnServerError(resp *http.Response) bool {
	return resp != nil &&
		resp.StatusCode >= http.StatusInternalServerError &&
		resp.ProtoMajor == 1
}

type closeConnBody struct {
	io.ReadCloser
	conn      net.Conn
	closeOnce sync.Once
}

func (b *closeConnBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.closeConn()
	}
	return n, err
}

func (b *closeConnBody) Close() error {
	err := b.ReadCloser.Close()
	b.closeConn()
	return err
}

func (b *closeConnBody) closeConn() {
	b.closeOnce.Do(func() {
		_ = b.conn.Close()
	})
}

type registryKeychain struct {
	auths RegistryAuthsConfig
}

func (k *registryKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	host := res.RegistryStr()
	candidates := []string{host}
	if host == name.DefaultRegistry {
		candidates = append(candidates, "docker.io")
	}

	for _, candidate := range candidates {
		if entry, ok := k.auths[candidate]; ok && entry.Auth != "" {
			return authn.FromConfig(authn.AuthConfig{Auth: entry.Auth}), nil
		}
		for key, entry := range k.auths {
			if strings.HasPrefix(key, candidate+"/") && entry.Auth != "" {
				return authn.FromConfig(authn.AuthConfig{Auth: entry.Auth}), nil
			}
		}
	}

	return authn.Anonymous, nil
}
