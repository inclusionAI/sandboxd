package config

import "testing"

func TestManagedRegistryTransportConflict(t *testing.T) {
	c := ManagedRuntimeConfig{ManagedRuntimeProfiles: map[string]ManagedRuntimeProfile{
		"a": {Registry: "registry.test:5000", RegistryInsecure: true},
		"b": {Registry: "registry.test:5000", RegistryInsecure: true},
	}}
	s, err := c.RegistrySchemes()
	if err != nil || s["registry.test:5000"] != "http" {
		t.Fatal(s, err)
	}
	c.ManagedRuntimeProfiles["b"] = ManagedRuntimeProfile{Registry: "registry.test:5000"}
	if _, err = c.RegistrySchemes(); err == nil {
		t.Fatal("conflicting policy accepted")
	}
}
