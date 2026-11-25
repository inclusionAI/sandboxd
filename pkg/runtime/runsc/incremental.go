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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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

// Use the cache directory inode as the lock. The publisher inherits the same
// open file description, so even a daemon crash cannot expose a live publisher
// to recovery. Closing (without LOCK_UN) releases the last holder's lock.
func lockGeneration(dir string) (*os.File, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		var opened, current os.FileInfo
		opened, err = f.Stat()
		if err == nil {
			current, err = os.Lstat(dir)
		}
		if err == nil && (!opened.IsDir() || !os.SameFile(opened, current)) {
			err = fmt.Errorf("generation directory replaced: %s", dir)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// The local head is the commit record. Never consult or delete shared output
// here: its lifetime and external visibility are controlled by the caller.
func sweepGeneration(dir string) error {
	var head struct{ Frozen, Generation, Remote string }
	p := filepath.Join(dir, "latest.json")
	data, err := os.ReadFile(p)
	if err == nil {
		if err := json.Unmarshal(data, &head); err != nil {
			return err
		}
		if filepath.Base(head.Frozen) != head.Frozen || !strings.HasPrefix(head.Frozen, "frozen-") || len(head.Frozen) == len("frozen-") || head.Generation == "" || !filepath.IsAbs(head.Remote) {
			return fmt.Errorf("invalid generation head in %s", dir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unreadable generation head in %s", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if name == head.Frozen {
			continue
		}
		if (e.IsDir() && (strings.HasPrefix(name, "frozen-") || strings.HasPrefix(name, "images-"))) || (name == "latest.tmp" && e.Type().IsRegular()) {
			if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func recoverGenerationCaches(filestore string) error {
	if !filepath.IsAbs(filestore) {
		return nil
	}
	root := filepath.Join(filestore, ".generations")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) != sha256.Size*2 {
			continue
		}
		if _, err := hex.DecodeString(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(root, e.Name())
		f, err := lockGeneration(dir)
		if err == nil {
			err = sweepGeneration(dir)
			f.Close()
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			logrus.WithError(err).Warnf("defer incremental cache recovery for %s", dir)
		}
	}
	return nil
}

func (c *Client) removeGenerationState(id string) error {
	if !filepath.IsAbs(c.Options.FilestoreDir) {
		return nil
	}
	dir := c.generationState(id)
	f, err := lockGeneration(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	return os.RemoveAll(dir)
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
	lock, err := lockGeneration(state)
	if err != nil {
		return fmt.Errorf("lock generation: %w", err)
	}
	defer lock.Close()
	// Retry startup cleanup that raced another holder or was interrupted.
	if err := sweepGeneration(state); err != nil {
		return fmt.Errorf("recover generation: %w", err)
	}
	frozen, err := os.MkdirTemp(state, "frozen-")
	if err != nil {
		return err
	}
	defer func() {
		if err := sweepGeneration(state); err != nil {
			logrus.WithError(err).Warnf("clean incremental capture in %s", state)
		}
	}()
	image, err := os.MkdirTemp(state, "images-")
	if err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(state, "origin")); err == nil {
		args = append(args, "--filestore-extent-snapshot")
	} else if !os.IsNotExist(err) {
		return err
	}
	args = append(args, "--skip-filestore-pages", "--filestore-snapshot-dir="+frozen, "--image-path", image, id)
	freeze := exec.CommandContext(ctx, c.Binary, args...)
	freeze.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if out, err := freeze.CombinedOutput(); err != nil {
		return fmt.Errorf("freeze incremental capture: %w: %s", err, out)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", filestorePublisher, state, frozen, image, destination)
	cmd.ExtraFiles = []*os.File{lock}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("publish incremental capture: %w: %s", err, out)
	}
	return nil
}
