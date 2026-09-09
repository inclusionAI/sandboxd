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

package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
)

const deleteIntentBucket = "sandbox_delete_intents_v1"

// The complete resource snapshot survives runtime deletion and partial removal
// of the bundle. Releasing is durable before any lease is returned to a pool.
type deleteIntent struct {
	Token     string                   `json:"token"`
	Runtime   string                   `json:"runtime"`
	Resource  sandbox.OccupiedResource `json:"resource"`
	Releasing bool                     `json:"releasing,omitempty"`
}

func (h *sandboxService) loadDeleteIntents() (map[string]deleteIntent, error) {
	h.deleteJournalMu.Lock()
	defer h.deleteJournalMu.Unlock()
	return h.readDeleteIntents()
}

// readDeleteIntents requires deleteJournalMu.
func (h *sandboxService) readDeleteIntents() (map[string]deleteIntent, error) {
	entries := make(map[string]deleteIntent)
	if h.store == nil {
		return nil, errors.New("sandbox deletion requires a state store")
	}
	data, err := h.store.LoadRaw(deleteIntentBucket)
	if errors.Is(err, errord.ErrNotFound) {
		return entries, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load deletion intents: %w", err)
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode deletion intents: %w", err)
	}
	if entries == nil {
		return nil, errors.New("invalid null deletion journal")
	}
	for id, entry := range entries {
		if !config.IsValidSandboxID(id) || entry.Token == "" || entry.Resource.ID != id || entry.Runtime == "" || entry.Resource.Resources == nil {
			return nil, fmt.Errorf("invalid deletion intent for %s", id)
		}
	}
	return entries, nil
}

func (h *sandboxService) saveDeleteIntent(id string, intent *deleteIntent) error {
	h.deleteJournalMu.Lock()
	defer h.deleteJournalMu.Unlock()
	entries, err := h.readDeleteIntents()
	if err != nil {
		return err
	}
	if intent == nil {
		delete(entries, id)
	} else {
		entries[id] = *intent
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := h.store.StoreRaw(deleteIntentBucket, data); err != nil {
		return fmt.Errorf("persist deletion intent for %s: %w", id, err)
	}
	return nil
}

func (h *sandboxService) beginDelete(id string) (*deleteIntent, error) {
	entries, err := h.loadDeleteIntents()
	if err != nil {
		return nil, err
	}
	if intent, ok := entries[id]; ok {
		return &intent, nil
	}
	current, err := h.sandboxManager.Get(id)
	if errors.Is(err, errord.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	resource, err := h.sandboxManager.CollectResourceByID(id)
	if err != nil {
		return nil, err
	}
	intent := &deleteIntent{Token: rand.Text(), Runtime: current.Metadata.RuntimeHandler, Resource: resource}
	if err := h.saveDeleteIntent(id, intent); err != nil {
		return nil, err
	}
	return intent, nil
}

// finishDelete requires resourceReuseMu. Retries must never signal or detach a
// lease already handed to a new sandbox, including after a failed journal write.
func (h *sandboxService) finishDelete(intent deleteIntent) error {
	if err := h.releaseStartResources(intent.Resource); err != nil {
		return err
	}
	if err := h.sandboxManager.Delete(intent.Resource.ID); err != nil {
		return err
	}
	return h.saveDeleteIntent(intent.Resource.ID, nil)
}

func sortedDeleteIDs(entries map[string]deleteIntent) []string {
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// finishReleasedDeletes requires resourceReuseMu and runs before allocation.
func (h *sandboxService) finishReleasedDeletes() error {
	entries, err := h.loadDeleteIntents()
	if err != nil {
		return err
	}
	for _, id := range sortedDeleteIDs(entries) {
		if entries[id].Releasing {
			if err := h.finishDelete(entries[id]); err != nil {
				return err
			}
		}
	}
	return nil
}

// recoverDeletes runs before restoring active ACL bindings or accepting RPCs.
// A failed runtime stop aborts recovery; missing ACL state is never ignored for
// a sandbox that could still be running.
func (h *sandboxService) recoverDeletes(ctx context.Context) error {
	entries, err := h.loadDeleteIntents()
	if err != nil {
		return err
	}
	for _, id := range sortedDeleteIDs(entries) {
		if err := h.deleteSandboxRuntime(ctx, id); err != nil {
			return fmt.Errorf("sandbox %s: %w", id, err)
		}
	}
	return nil
}

// Reserve IDs under the same barrier as final deletion so completing an old
// intent cannot release the reservation of a new sandbox with the same ID.
func (h *sandboxService) reserveSandboxID(requested string) (string, error) {
	h.resourceReuseMu.Lock()
	defer h.resourceReuseMu.Unlock()
	if err := h.finishReleasedDeletes(); err != nil {
		return "", err
	}
	pending, err := h.loadDeleteIntents()
	if err != nil {
		return "", err
	}
	if _, exists := pending[requested]; exists {
		return "", fmt.Errorf("sandbox %s has an unfinished deletion: %w", requested, errord.ErrAlreadyExists)
	}
	return h.sandboxManager.ReserveID(requested)
}
