package distillfs

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/nydus"
	"github.com/stretchr/testify/require"
)

func TestNydusBackendUsesOperatorRegistryTransport(t *testing.T) {
	client, err := imageregistry.NewClientWithRegistrySchemes("", map[string]string{"registry-http.test:5000": "http", "172.20.0.2:5000": "https"})
	if err != nil {
		t.Fatal(err)
	}
	mgr := &manager{ctx: context.Background(), root: t.TempDir(), nydusClient: nydus.NewRegistryClientFromShared(client), nydusCfgTemplate: BackendConfig{BackendType: "registry", Registry: &RegistryConfig{Scheme: "https"}}}
	for _, tc := range []struct{ host, want string }{{"registry-http.test:5000", "http"}, {"unconfigured.test:5000", "https"}, {"registry-http.test:5001", "https"}, {"172.20.0.2:5000", "https"}} {
		d, err := mgr.setupNydusDaemon(&DaemonCreateOpt{ID: tc.host, ImageURL: tc.host + "/image:latest"})
		if err != nil {
			t.Fatal(err)
		}
		if d.config.Registry.Scheme != tc.want {
			t.Fatalf("%s scheme %s, want %s", tc.host, d.config.Registry.Scheme, tc.want)
		}
	}
	if mgr.nydusCfgTemplate.Registry.Scheme != "https" {
		t.Fatal("shared template mutated")
	}
	mgr.nydusCfgTemplate.Registry.Scheme = "http"
	d, err := mgr.setupNydusDaemon(&DaemonCreateOpt{ID: "tls-overrides-template", ImageURL: "172.20.0.2:5000/image:latest"})
	if err != nil {
		t.Fatal(err)
	}
	if d.config.Registry.Scheme != "https" || mgr.nydusCfgTemplate.Registry.Scheme != "http" {
		t.Fatal("explicit HTTPS must override HTTP template without mutating it")
	}
}

func TestCheckpointArchiveNydusPullUsesExactTLSAuthority(t *testing.T) {
	const host = "archive.example.test:5443"
	client, err := imageregistry.NewClientWithRegistrySchemes("", map[string]string{host: "https"})
	require.NoError(t, err)
	auth := base64.StdEncoding.EncodeToString([]byte("akernel-checkpoint:fixture"))
	require.NoError(t, validateCheckpointRegistryAuth(auth))
	require.Error(t, validateCheckpointRegistryAuth("malformed"))
	proxy := "http://proxy.example.test:65001"
	mgr := &manager{
		ctx:                       context.Background(),
		root:                      t.TempDir(),
		nydusClient:               nydus.NewRegistryClientFromShared(client),
		checkpointArchiveRegistry: host,
		registryAuths:             RegistryAuthsConfig{host: {Auth: auth}},
		nydusCfgTemplate: BackendConfig{
			BackendType: "registry",
			Registry: &RegistryConfig{
				Scheme: "http", BlobUrlScheme: "http", SkipVerify: true,
				BlobRedirectedHost: "cache.example.test", RegistryToken: "unused",
				Proxy: &ProxyConfig{Url: proxy},
			},
		},
	}
	daemon, err := mgr.setupNydusDaemon(&DaemonCreateOpt{ID: "archive", ImageURL: host + "/akernel-checkpoint/lease:v1"})
	require.NoError(t, err)
	settings := daemon.config.Registry
	require.Equal(t, "https", settings.Scheme)
	require.Equal(t, "https", settings.BlobUrlScheme)
	require.Equal(t, auth, settings.Auth)
	require.False(t, settings.SkipVerify)
	require.Empty(t, settings.BlobRedirectedHost)
	require.Empty(t, settings.RegistryToken)
	require.Nil(t, settings.Proxy)
	require.Empty(t, daemon.proxyURL)

	ordinary, err := mgr.setupNydusDaemon(&DaemonCreateOpt{ID: "ordinary", ImageURL: "ordinary.example.test/image:v1"})
	require.NoError(t, err)
	require.Equal(t, proxy, ordinary.proxyURL)
	require.True(t, ordinary.config.Registry.SkipVerify)
}
