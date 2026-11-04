package distillfs

import (
	"context"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/nydus"
	"testing"
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
