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
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

const (
	maxIDGenerationAttempts = 1000
	idAlphabet              = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
)

// UniqueIDGenerator creates IDs and tracks the IDs that have not been
// released yet.
type UniqueIDGenerator interface {
	Next() (string, error)
	Reserve(id string) bool
	Release(id string)
	Len() int
}

// IDModifier transforms a newly generated ID before it is reserved.
type IDModifier func(id string) string

// PrefixID adds prefix to every generated ID.
func PrefixID(prefix string) IDModifier {
	return func(id string) string { return prefix + id }
}

type uniqueIDGenerator struct {
	mu        sync.Mutex
	ids       map[string]struct{}
	generate  func() (string, error)
	modifiers []IDModifier
}

// NewUUIDGenerator returns a generator for IDs in <prefix>-<UUID> form.
func NewUUIDGenerator(prefix string, existing []string) UniqueIDGenerator {
	return newUniqueIDGenerator(existing, func() (string, error) {
		return fmt.Sprintf("%s-%s", prefix, uuid.NewString()), nil
	})
}

// NewFixedLengthIDGenerator returns an alphanumeric ID generator. Modifiers
// are applied after generating the requested number of random characters.
func NewFixedLengthIDGenerator(length int, existing []string, modifiers ...IDModifier) UniqueIDGenerator {
	return newUniqueIDGenerator(existing, func() (string, error) {
		return randomID(length)
	}, modifiers...)
}

func newUniqueIDGenerator(existing []string, generate func() (string, error), modifiers ...IDModifier) *uniqueIDGenerator {
	ids := make(map[string]struct{}, len(existing))
	for _, id := range existing {
		ids[id] = struct{}{}
	}
	return &uniqueIDGenerator{ids: ids, generate: generate, modifiers: modifiers}
}

func (g *uniqueIDGenerator) Next() (string, error) {
	for range maxIDGenerationAttempts {
		id, err := g.generate()
		if err != nil {
			return "", err
		}
		for _, modify := range g.modifiers {
			id = modify(id)
		}

		g.mu.Lock()
		if _, exists := g.ids[id]; !exists {
			g.ids[id] = struct{}{}
			g.mu.Unlock()
			return id, nil
		}
		g.mu.Unlock()
	}
	return "", fmt.Errorf("failed to generate a unique ID after %d attempts", maxIDGenerationAttempts)
}

// Reserve marks a caller-provided ID as in use. It returns false when the ID
// was already reserved.
func (g *uniqueIDGenerator) Reserve(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.ids[id]; exists {
		return false
	}
	g.ids[id] = struct{}{}
	return true
}

func (g *uniqueIDGenerator) Release(id string) {
	g.mu.Lock()
	delete(g.ids, id)
	g.mu.Unlock()
}

func (g *uniqueIDGenerator) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.ids)
}

func randomID(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("ID length must be positive")
	}
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	id := make([]byte, length)
	for i, value := range random {
		id[i] = idAlphabet[int(value)%len(idAlphabet)]
	}
	return string(id), nil
}
