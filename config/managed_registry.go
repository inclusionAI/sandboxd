package config

import "fmt"

// RegistrySchemes derives node-owned transport from the configured profiles.
// A shared registry authority cannot simultaneously use incompatible transports.
func (c ManagedRuntimeConfig) RegistrySchemes() (map[string]string, error) {
	schemes := make(map[string]string)
	for _, profile := range c.ManagedRuntimeProfiles {
		scheme := "https"
		if profile.RegistryInsecure {
			scheme = "http"
		}
		if previous, ok := schemes[profile.Registry]; ok && previous != scheme {
			return nil, fmt.Errorf("conflicting managed Registry transport for %s", profile.Registry)
		}
		schemes[profile.Registry] = scheme
	}
	return schemes, nil
}
