// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/sirupsen/logrus"
)

type rebootFence struct {
	Attempt string `json:"attempt"`
	Closed  bool   `json:"closed"`
}

type rebootGate struct {
	mu        sync.Mutex
	path      string
	fence     rebootFence
	inFlight  int
	uncertain bool
}

func validRebootAttempt(attempt string) bool {
	stamp, id, ok := strings.Cut(attempt, "-")
	if !ok || len(stamp) != 20 || strings.Trim(stamp, "0123456789") != "" {
		return false
	}
	if _, err := strconv.ParseInt(stamp, 10, 64); err != nil {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && id == strings.ToLower(id)
}

func loadRebootGate(path string, resetDirs ...string) (*rebootGate, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("reboot fence path must be absolute and clean")
	}
	resolved, err := util.CanonicalProspectivePath(path)
	if err != nil {
		return nil, err
	}
	for _, dir := range resetDirs {
		if dir == "" {
			continue
		}
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		resolvedDir, err := util.CanonicalProspectivePath(absDir)
		if err != nil {
			return nil, err
		}
		if pathAtOrBelow(path, absDir) || pathAtOrBelow(resolved, resolvedDir) {
			return nil, fmt.Errorf("reboot fence path %q would be cleared with %q on Pod replacement", path, dir)
		}
	}
	g := &rebootGate{path: path}
	stat, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// A missing fence is meaningful only on an available persistent directory.
		dir, err := os.Stat(filepath.Dir(path))
		if err != nil || !dir.IsDir() {
			return nil, fmt.Errorf("reboot fence directory unavailable")
		}
		return g, nil
	}
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 256 {
		return nil, fmt.Errorf("invalid reboot fence file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record struct {
		Attempt string `json:"attempt"`
		Closed  *bool  `json:"closed"`
	}
	if err := json.Unmarshal(raw, &record); err != nil || record.Closed == nil || !validRebootAttempt(record.Attempt) {
		return nil, fmt.Errorf("invalid reboot fence record")
	}
	g.fence = rebootFence{Attempt: record.Attempt, Closed: *record.Closed}
	return g, nil
}

func pathAtOrBelow(path, dir string) bool {
	sep := string(filepath.Separator)
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, sep)+sep)
}

func (g *rebootGate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fence.Closed || g.uncertain {
		return false
	}
	g.inFlight++
	return true
}

func (g *rebootGate) leave() {
	g.mu.Lock()
	g.inFlight--
	g.mu.Unlock()
}

// Persist both the close and the release before acknowledging them. Keeping
// the last released attempt makes retries safe even after a process restart.
func (g *rebootGate) save(fence rebootFence) error {
	dir, err := os.Open(filepath.Dir(g.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	tmp, err := os.CreateTemp(dir.Name(), ".reboot-fence-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = json.NewEncoder(tmp).Encode(fence)
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), g.path); err != nil {
		return err
	}
	g.fence = fence
	err = dir.Sync()
	g.uncertain = err != nil
	return err
}

func (g *rebootGate) change(attempt string, closed bool) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if attempt < g.fence.Attempt || (g.fence.Closed || g.uncertain) && g.fence.Attempt != attempt ||
		closed && g.fence.Attempt == attempt && !g.fence.Closed {
		return http.StatusConflict
	}
	if !g.uncertain && g.fence == (rebootFence{Attempt: attempt, Closed: closed}) {
		return http.StatusNoContent
	}
	if err := g.save(rebootFence{Attempt: attempt, Closed: closed}); err != nil {
		logrus.WithError(err).Error("persist local reboot fence")
		return http.StatusServiceUnavailable
	}
	return http.StatusNoContent
}

func (g *rebootGate) closedAndIdle(attempt string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.uncertain && g.fence == (rebootFence{Attempt: attempt, Closed: true}) && g.inFlight == 0
}

func (g *rebootGate) handler(checkAvailable func() error, checkEmpty func(context.Context) error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /available", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.uncertain || g.fence.Closed {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if err := checkAvailable(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handleAttempt := func(pattern string, fn func(http.ResponseWriter, *http.Request, string)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			attempt := r.PathValue("attempt")
			if !validRebootAttempt(attempt) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fn(w, r, attempt)
		})
	}
	handleAttempt("PUT /close/{attempt}", func(w http.ResponseWriter, r *http.Request, attempt string) {
		w.WriteHeader(g.change(attempt, true))
	})
	handleAttempt("PUT /open/{attempt}", func(w http.ResponseWriter, r *http.Request, attempt string) {
		w.WriteHeader(g.change(attempt, false))
	})
	handleAttempt("GET /drained/{attempt}", func(w http.ResponseWriter, r *http.Request, attempt string) {
		if !g.closedAndIdle(attempt) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := checkEmpty(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		// A released attempt cannot close again, so the same closed
		// attempt proves the fence stayed in place during the inventory.
		if ctx.Err() != nil || !g.closedAndIdle(attempt) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
