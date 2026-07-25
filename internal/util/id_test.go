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
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestUUIDGenerator(t *testing.T) {
	generator := NewUUIDGenerator("sbox", nil)
	id, err := generator.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "sbox-") {
		t.Fatalf("generated ID %q does not have the expected prefix", id)
	}
	if _, err := uuid.Parse(strings.TrimPrefix(id, "sbox-")); err != nil {
		t.Fatalf("generated ID %q does not contain a UUID: %v", id, err)
	}
	if generator.Len() != 1 {
		t.Fatalf("generator length = %d, want 1", generator.Len())
	}
	generator.Release(id)
	if generator.Len() != 0 {
		t.Fatalf("generator length after release = %d, want 0", generator.Len())
	}
}

func TestUniqueIDGeneratorReserve(t *testing.T) {
	generator := NewUUIDGenerator("sbox", nil)
	assert.True(t, generator.Reserve("sbox-explicit"))
	assert.False(t, generator.Reserve("sbox-explicit"))
	assert.Equal(t, 1, generator.Len())

	generator.Release("sbox-explicit")
	assert.True(t, generator.Reserve("sbox-explicit"))
}

func TestFixedLengthIDGenerator(t *testing.T) {
	const prefix = "/sandbox/"
	generator := NewFixedLengthIDGenerator(12, []string{"existing"}, PrefixID(prefix))
	seen := make(map[string]struct{})
	for range 1000 {
		id, err := generator.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, prefix) {
			t.Fatalf("generated ID %q does not have prefix %q", id, prefix)
		}
		if len(strings.TrimPrefix(id, prefix)) != 12 {
			t.Fatalf("generated ID %q does not contain 12 random characters", id)
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("generated duplicate ID %q", id)
		}
		seen[id] = struct{}{}
	}
	if generator.Len() != len(seen)+1 {
		t.Fatalf("generator length = %d, want %d", generator.Len(), len(seen)+1)
	}
}

func TestFixedLengthIDGeneratorRejectsInvalidLength(t *testing.T) {
	if _, err := NewFixedLengthIDGenerator(0, nil).Next(); err == nil {
		t.Fatal("expected an invalid length error")
	}
}
