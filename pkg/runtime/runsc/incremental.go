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

package runsc

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed filestore_publish.py
var filestorePublisher string

func (c *Client) generationState(id string) string {
	// Hash the whole identifier to keep the cache within the operator-owned XFS.
	return filepath.Join(c.Options.FilestoreDir, ".generations", fmt.Sprintf("%x", sha256.Sum256([]byte(id))))
}

func (c *Client) createGenerationState(id, origin string) error {
	if !filepath.IsAbs(c.Options.FilestoreDir) {
		return fmt.Errorf("incremental filestore directory must be absolute")
	}
	if origin != "" {
		if !filepath.IsAbs(origin) {
			return fmt.Errorf("incremental restore requires an absolute shared origin")
		}
		data, err := os.ReadFile(filepath.Join(origin, filestoreManifestName))
		if err != nil {
			return err
		}
		var manifest struct{ Filestores []struct{ File string } }
		if err := json.Unmarshal(data, &manifest); err != nil {
			return err
		}
		if len(manifest.Filestores) != 1 || manifest.Filestores[0].File != "filestore-0" {
			return fmt.Errorf("incremental restore requires a single root filestore")
		}
	}
	dir := c.generationState(id)
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if origin != "" {
		if err := os.WriteFile(filepath.Join(dir, "origin"), []byte(origin), 0600); err != nil {
			os.RemoveAll(dir)
			return err
		}
	}
	return nil
}

func (c *Client) removeGenerationState(id string) error {
	if !filepath.IsAbs(c.Options.FilestoreDir) {
		return nil
	}
	return os.RemoveAll(c.generationState(id))
}

func (c *Client) hasGenerationState(id string) (bool, error) {
	if !filepath.IsAbs(c.Options.FilestoreDir) {
		return false, nil
	}
	_, err := os.Stat(c.generationState(id))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (c *Client) captureGeneration(ctx context.Context, id, destination string, args []string) error {
	if !filepath.IsAbs(destination) {
		return fmt.Errorf("incremental checkpoint destination must be absolute")
	}
	state := c.generationState(id)
	frozen, err := os.MkdirTemp(state, "frozen-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			// Publication can commit just before cancellation or an fsync error.
			data, err := os.ReadFile(filepath.Join(state, "latest.json"))
			var head struct{ Frozen string }
			if os.IsNotExist(err) || (err == nil && json.Unmarshal(data, &head) == nil && head.Frozen != filepath.Base(frozen)) {
				os.RemoveAll(frozen)
			}
		}
	}()
	image, err := os.MkdirTemp(state, "images-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(image)
	if _, err := os.Stat(filepath.Join(state, "origin")); err == nil {
		args = append(args, "--filestore-extent-snapshot")
	} else if !os.IsNotExist(err) {
		return err
	}
	args = append(args, "--skip-filestore-pages", "--filestore-snapshot-dir="+frozen, "--image-path", image, id)
	if out, err := exec.CommandContext(ctx, c.Binary, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("freeze incremental capture: %w: %s", err, out)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", filestorePublisher, state, frozen, image, destination)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("publish incremental capture: %w: %s", err, out)
	}
	committed = true
	return nil
}
