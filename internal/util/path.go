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

package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// JoinWithinRoot joins path elements while ensuring the result remains below
// root. It is a defense-in-depth guard for paths derived from sandbox IDs.
func JoinWithinRoot(root string, elements ...string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root %q: %w", root, err)
	}
	targetAbs, err := filepath.Abs(filepath.Join(append([]string{rootAbs}, elements...)...))
	if err != nil {
		return "", fmt.Errorf("resolve path below %q: %w", root, err)
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return "", fmt.Errorf("compare path %q with root %q: %w", targetAbs, rootAbs, err)
	}
	if rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes root %q", targetAbs, rootAbs)
	}
	return targetAbs, nil
}

// ValidateRestoreDirectorySeparation prevents target preparation or rollback
// from overwriting the input checkpoint. Existing symlink ancestors are resolved
// even when the target directory has not been created yet.
func ValidateRestoreDirectorySeparation(checkpointDir, targetDir string) error {
	if checkpointDir == "" || targetDir == "" {
		return errors.New("checkpoint and target directories are required")
	}
	checkpoint, err := canonicalProspectivePath(checkpointDir)
	if err != nil {
		return fmt.Errorf("resolve checkpoint directory: %w", err)
	}
	target, err := canonicalProspectivePath(targetDir)
	if err != nil {
		return fmt.Errorf("resolve restore target directory: %w", err)
	}
	separator := string(filepath.Separator)
	if checkpoint == target || strings.HasPrefix(checkpoint, strings.TrimSuffix(target, separator)+separator) || strings.HasPrefix(target, strings.TrimSuffix(checkpoint, separator)+separator) {
		return errors.New("checkpoint directory must not overlap the sandbox target directory")
	}
	return nil
}

func canonicalProspectivePath(value string) (string, error) {
	current, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if info, statErr := os.Lstat(current); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("unresolved symbolic link %q", current)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}
