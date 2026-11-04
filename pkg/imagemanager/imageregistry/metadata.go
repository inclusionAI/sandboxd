package imageregistry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	registrytransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const MaxMetadataBytes = 16 << 20

// Metadata returns bounded, digest-verified OCI JSON through the same node
// credential/keychain and standard Registry challenge protocol as image pulls.
// Runtime adapters never receive passwords or implement Bearer token exchange.
func (c *Client) Metadata(ctx context.Context, reference, kind string, insecure bool) ([]byte, string, error) {
	if c == nil {
		return nil, "", fmt.Errorf("Registry metadata client is unavailable")
	}
	if kind != "manifests" && kind != "blobs" {
		return nil, "", fmt.Errorf("invalid Registry metadata kind")
	}
	opts := []name.Option{}
	if scheme, ok := c.RegistryScheme(reference); ok && scheme == "http" {
		insecure = true
	}
	if insecure {
		opts = append(opts, name.Insecure)
	}
	ref, err := name.NewDigest(reference, opts...)
	if err != nil || !strings.HasPrefix(ref.DigestStr(), "sha256:") {
		return nil, "", fmt.Errorf("immutable sha256 metadata reference required")
	}
	repo := ref.Context()
	key := repo.Scheme() + "://" + repo.Name()
	c.metadataMu.Lock()
	transport := c.metadataAuth[key]
	c.metadataMu.Unlock()
	if transport == nil {
		auth, err := c.keychain.Resolve(repo)
		if err != nil {
			return nil, "", fmt.Errorf("resolve Registry metadata credentials: %w", err)
		}
		// Network I/O must not hold the cache lock. A concurrent first miss may
		// authenticate twice; later requests reuse the standard refreshable token.
		created, err := registrytransport.NewWithContext(ctx, repo.Registry, auth, c.getOrCreateTransport(""), []string{repo.Scope(registrytransport.PullScope)})
		if err != nil {
			return nil, "", fmt.Errorf("authenticate Registry metadata: %w", err)
		}
		c.metadataMu.Lock()
		if c.metadataAuth == nil {
			c.metadataAuth = make(map[string]http.RoundTripper)
		}
		transport = c.metadataAuth[key]
		if transport == nil {
			// Eviction only drops a cache reference. In-flight users retain their
			// transport; all entries share the existing bounded connection pool.
			if len(c.metadataAuth) >= 1024 {
				for old := range c.metadataAuth {
					delete(c.metadataAuth, old)
					break
				}
			}
			c.metadataAuth[key] = created
			transport = created
		}
		c.metadataMu.Unlock()
	}
	url := repo.Scheme() + "://" + repo.RegistryStr() + "/v2/" + repo.RepositoryStr() + "/" + kind + "/" + ref.DigestStr()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/octet-stream")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("Registry metadata returned HTTP %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, MaxMetadataBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(payload) > MaxMetadataBytes || fmt.Sprintf("sha256:%x", sha256.Sum256(payload)) != ref.DigestStr() {
		return nil, "", fmt.Errorf("Registry metadata size or digest mismatch")
	}
	return payload, strings.Split(response.Header.Get("Content-Type"), ";")[0], nil
}
