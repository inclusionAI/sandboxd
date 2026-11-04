// Copyright (c) 2026 Ant Group Corporation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package runtime

import (
	"fmt"
	"path"
	"strings"
)

// ValidateMountDestinations validates one configuration layer. Cross-layer
// overrides are resolved separately; duplicates within a layer are errors.
// Only container destinations are subject to this canonical-path contract. Host source
// paths retain their original resolution, including symlinks and trailing '/'.
func ValidateMountDestinations(destinations []string) error {
	seen := make(map[string]struct{}, len(destinations))
	for _, destination := range destinations {
		if !path.IsAbs(destination) || path.Clean(destination) != destination || strings.ContainsRune(destination, '\x00') {
			return fmt.Errorf("mount destination %q must be a canonical absolute container path", destination)
		}
		if _, exists := seen[destination]; exists {
			return fmt.Errorf("duplicate mount destination %q in one configuration layer", destination)
		}
		seen[destination] = struct{}{}
	}
	return nil
}

func validateOCIMountDestinations(mounts []Mount) error {
	destinations := make([]string, len(mounts))
	for i := range mounts {
		destinations[i] = mounts[i].Destination
	}
	return ValidateMountDestinations(destinations)
}

// mergeOCIMounts treats each layer as a declaration of distinct mounts, not an
// ordered mount/remount program. An override replaces the complete base entry.
// Parents are emitted before the first retained descendant; independent entries
// otherwise retain their declaration order. Explicit children survive a parent
// replacement on runtimes that mount in OCI order as well as on runsc.
func mergeOCIMounts(base, overrides []Mount) ([]Mount, error) {
	if err := validateOCIMountDestinations(base); err != nil {
		return nil, fmt.Errorf("base mounts: %w", err)
	}
	if err := validateOCIMountDestinations(overrides); err != nil {
		return nil, fmt.Errorf("sandbox mounts: %w", err)
	}
	replaced := make(map[string]struct{}, len(overrides))
	for _, mount := range overrides {
		replaced[mount.Destination] = struct{}{}
	}
	var retained []Mount
	for _, mount := range base {
		if _, exists := replaced[mount.Destination]; !exists {
			retained = append(retained, *mount.DeepCopy())
		}
	}
	for _, mount := range overrides {
		retained = append(retained, *mount.DeepCopy())
	}
	byDestination := make(map[string]int, len(retained))
	for i := range retained {
		byDestination[retained[i].Destination] = i
	}
	var ordered []Mount
	emitted := make([]bool, len(retained))
	var emit func(int)
	emit = func(i int) {
		if emitted[i] {
			return
		}
		destination := retained[i].Destination
		for parent := path.Dir(destination); parent != destination; parent = path.Dir(parent) {
			if ancestor, exists := byDestination[parent]; exists {
				emit(ancestor)
				break
			}
			if parent == "/" {
				break
			}
		}
		emitted[i] = true
		ordered = append(ordered, retained[i])
	}
	for i := range retained {
		emit(i)
	}
	return ordered, nil
}
