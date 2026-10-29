// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
)

const entryStoreKey = "networkACLEntries.v1"

func encodeEntries(entries map[string]persistedEntry) (map[string][]byte, error) {
	out := make(map[string][]byte, len(entries))
	for id, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		out[id] = data
	}
	return out, nil
}

func (m *Manager) loadState() error {
	if m.store == nil {
		return nil
	}
	if records, ok := m.store.(store.RecordStore); ok {
		data, err := records.LoadRecords(entryStoreKey)
		if err == nil {
			for id, raw := range data {
				var entry persistedEntry
				if err := json.Unmarshal(raw, &entry); err != nil {
					return err
				}
				m.entries[id] = entry
			}
			return nil
		}
		if !errors.Is(err, errord.ErrNotFound) {
			return err
		}
	}
	raw, err := m.store.LoadRaw(stateStoreKey)
	if err != nil && !errors.Is(err, errord.ErrNotFound) {
		return fmt.Errorf("load network ACL state: %w", err)
	}
	if err == nil {
		var state persistedState
		if err := json.Unmarshal(raw, &state); err != nil {
			return fmt.Errorf("decode network ACL state: %w", err)
		}
		for id, entry := range state.Entries {
			m.entries[id] = entry
		}
	}
	if records, ok := m.store.(store.RecordStore); ok {
		data, err := encodeEntries(m.entries)
		if err != nil {
			return err
		}
		return records.InitRecords(entryStoreKey, stateStoreKey, data)
	}
	m.durable = make(map[string]persistedEntry, len(m.entries))
	for id, entry := range m.entries {
		m.durable[id] = entry
	}
	return nil
}

// persistLocked is only for exclusive Restore and test fixture setup. Hot-path
// writes use persistEntry, with no index lock and no whole-table serialization.
func (m *Manager) persistLocked() error {
	if m.store == nil {
		return nil
	}
	if records, ok := m.store.(store.RecordStore); ok {
		data, err := encodeEntries(m.entries)
		if err != nil {
			return err
		}
		previous, err := records.LoadRecords(entryStoreKey)
		if errors.Is(err, errord.ErrNotFound) {
			return records.InitRecords(entryStoreKey, stateStoreKey, data)
		}
		if err != nil {
			return err
		}
		for id := range previous {
			if _, ok := data[id]; !ok {
				data[id] = nil
			}
		}
		return records.StoreRecords(entryStoreKey, data)
	}
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	data, err := json.Marshal(persistedState{Entries: m.entries})
	if err != nil {
		return err
	}
	if err := m.store.StoreRaw(stateStoreKey, data); err != nil {
		return err
	}
	m.durable = make(map[string]persistedEntry, len(m.entries))
	for id, entry := range m.entries {
		m.durable[id] = entry
	}
	return nil
}

func (m *Manager) persistEntry(id string, entry *persistedEntry) error {
	if m.store == nil {
		return nil
	}
	if records, ok := m.store.(store.RecordStore); ok {
		var data []byte
		var err error
		if entry != nil {
			data, err = json.Marshal(entry)
			if err != nil {
				return err
			}
		}
		return records.StoreRecords(entryStoreKey, map[string][]byte{id: data})
	}
	// Compatibility for custom stores: serialize only the durable snapshot, not
	// the endpoint registry. Production bbolt uses independent batched records.
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if m.durable == nil {
		m.durable = make(map[string]persistedEntry)
		raw, err := m.store.LoadRaw(stateStoreKey)
		if err != nil && !errors.Is(err, errord.ErrNotFound) {
			return err
		}
		if err == nil {
			var state persistedState
			if err := json.Unmarshal(raw, &state); err != nil {
				return err
			}
			if state.Entries != nil {
				m.durable = state.Entries
			}
		}
	}
	old, present := m.durable[id]
	if entry == nil {
		delete(m.durable, id)
	} else {
		m.durable[id] = *entry
	}
	data, err := json.Marshal(persistedState{Entries: m.durable})
	if err == nil {
		err = m.store.StoreRaw(stateStoreKey, data)
	}
	if err != nil {
		if present {
			m.durable[id] = old
		} else {
			delete(m.durable, id)
		}
	}
	return err
}
