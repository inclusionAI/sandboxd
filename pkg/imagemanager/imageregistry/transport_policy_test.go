package imageregistry

import (
	"context"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Exercise the real Registry client, including lazy config and metadata reads.
// Private IPs and loopback are HTTP-capable in the upstream name library even
// without name.Insecure; an explicit operator policy must override that hint.
func TestExplicitRegistrySchemeOverridesHeuristics(t *testing.T) {
	for _, tlsEnabled := range []bool{false, true} {
		t.Run("tls="+strconv.FormatBool(tlsEnabled), func(t *testing.T) {
			server := httptest.NewUnstartedServer(registry.New())
			if tlsEnabled {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			port := strings.Split(server.Listener.Addr().String(), ":")[1]
			for _, hostname := range []string{"127.0.0.1", "172.20.0.2", "registry-policy.test"} {
				t.Run(hostname, func(t *testing.T) {
					host := hostname + ":" + port
					transport := server.Client().Transport.(*http.Transport).Clone()
					transport.Proxy = nil
					if tlsEnabled {
						transport.TLSClientConfig.ServerName = "127.0.0.1" // Alias routes to the fixture's certified address.
					}
					transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
					}
					defer transport.CloseIdleConnections()
					tag, err := name.NewTag(host+"/probe:latest", name.Insecure)
					if err != nil {
						t.Fatal(err)
					}
					if err := remote.Write(tag, empty.Image, remote.WithTransport(transport)); err != nil {
						t.Fatal(err)
					}
					digest, _ := empty.Image.Digest()
					ref := host + "/probe@" + digest.String()
					for _, scheme := range []string{"", "http", "https"} {
						for _, insecure := range []bool{false, true} {
							t.Run("policy="+scheme+"/insecure="+strconv.FormatBool(insecure), func(t *testing.T) {
								policy := map[string]string{}
								if scheme != "" {
									policy[host] = scheme
								}
								client, err := NewClientWithRegistrySchemes("", policy)
								if err != nil {
									t.Fatal(err)
								}
								client.getOrCreateTransport("").base = transport
								wantFetch := (scheme == "https" && tlsEnabled) || (scheme == "http" && !tlsEnabled)
								if scheme == "" {
									wantFetch = tlsEnabled || hostname != "registry-policy.test" || insecure
								}
								image, err := client.FetchImage(context.Background(), ref, "", insecure)
								if (err == nil) != wantFetch {
									t.Fatalf("fetch success=%t, want %t: %v", err == nil, wantFetch, err)
								}
								if err == nil {
									if _, err = image.RawConfigFile(); err != nil {
										t.Fatal(err)
									}
								}
								// Unconfigured metadata retains its legacy URL behavior;
								// the explicit operator choices are authoritative for both APIs.
								if scheme != "" || !tlsEnabled {
									body, _, err := client.Metadata(context.Background(), ref, "manifests", insecure)
									if (err == nil) != wantFetch || (err == nil && len(body) == 0) {
										t.Fatalf("metadata success=%t, want %t: %v", err == nil, wantFetch, err)
									}
								}
							})
						}
					}
				})
			}
		})
	}
}

func TestOperatorHTTPRegistryTransport(t *testing.T) {
	server := httptest.NewServer(registry.New())
	defer server.Close()
	host := "registry-http.test:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	transport := remote.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	defer transport.CloseIdleConnections()
	tag, _ := name.NewTag(host+"/managed/probe:latest", name.Insecure)
	if err := remote.Write(tag, empty.Image, remote.WithTransport(transport)); err != nil {
		t.Fatal(err)
	}
	digest, _ := empty.Image.Digest()
	reference := host + "/managed/probe@" + digest.String()
	for _, enabled := range []bool{false, true} {
		policy := map[string]string{}
		if enabled {
			policy[host] = "http"
		}
		client, err := NewClientWithRegistrySchemes("", policy)
		if err != nil {
			t.Fatal(err)
		}
		client.getOrCreateTransport("").base = transport
		policy[host] = "https" // Caller mutation must not change the client's policy.
		image, err := client.FetchImage(context.Background(), reference, "", false)
		if !enabled {
			if err == nil {
				t.Fatal("unconfigured HTTP hostname accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := image.ConfigFile(); err != nil {
			t.Fatal(err)
		}
		data, _, err := client.Metadata(context.Background(), reference, "manifests", false)
		if err != nil || len(data) == 0 {
			t.Fatalf("metadata: %v", err)
		}
		// Failed proxy must fall back to the configured HTTP origin, not HTTPS.
		image, err = client.FetchImageWithFallback(context.Background(), reference, "http://127.0.0.1:1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := image.RawConfigFile(); err != nil {
			t.Fatal(err)
		}
	}
}
func TestUnconfiguredRegistryStillUsesHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(registry.New())
	defer server.Close()
	host := "registry-tls.test:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	transport.TLSClientConfig.InsecureSkipVerify = true // Fixture certificate does not name the test alias.
	defer transport.CloseIdleConnections()
	tag, _ := name.NewTag(host + "/probe:latest")
	if err := remote.Write(tag, empty.Image, remote.WithTransport(transport)); err != nil {
		t.Fatal(err)
	}
	client, err := NewClientWithRegistrySchemes("", map[string]string{"another.test:5000": "http"})
	if err != nil {
		t.Fatal(err)
	}
	client.getOrCreateTransport("").base = transport
	image, err := client.FetchImage(context.Background(), tag.Name(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := image.RawManifest()
	if err != nil || len(body) == 0 {
		t.Fatal(err)
	}
}
func TestRejectInvalidRegistryTransportPolicy(t *testing.T) {
	for _, policy := range []map[string]string{{"https://registry.test": "http"}, {"registry.test/repo": "http"}, {"": "http"}, {"registry.test": "ftp"}, {"docker.io": "http", "index.docker.io": "https"}} {
		if _, err := NewClientWithRegistrySchemes("", policy); err == nil {
			t.Fatalf("accepted %v", policy)
		}
	}
}
