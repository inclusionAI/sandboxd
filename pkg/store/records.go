// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package store

import (
	"github.com/inclusionAI/sandboxd/pkg/errord"
	bolt "go.etcd.io/bbolt"
)

// RecordStore commits independent records without rewriting an entire object.
// Nil values delete records. Successful writes have crossed the durable commit
// barrier; callers must serialize mutations of the same record.
type RecordStore interface {
	LoadRecords(bucket string) (map[string][]byte, error)
	InitRecords(bucket, legacyKey string, records map[string][]byte) error
	StoreRecords(bucket string, records map[string][]byte) error
}

func (f *BboltStoreImp) LoadRecords(name string) (map[string][]byte, error) {
	records := make(map[string][]byte)
	err := f.view(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(name))
		if b == nil {
			return errord.ErrNotFound
		}
		return b.ForEach(func(k, v []byte) error { records[string(k)] = append([]byte(nil), v...); return nil })
	})
	return records, err
}

// InitRecords atomically replaces the legacy object with a record bucket.
// An existing bucket is authoritative, including an empty one after cleanup.
// The legacy marker makes old whole-object readers fail closed instead of
// starting a second, divergent history after a binary downgrade.
func (f *BboltStoreImp) InitRecords(name, legacyKey string, records map[string][]byte) error {
	return f.update(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(name)) != nil {
			return nil
		}
		b, err := tx.CreateBucket([]byte(name))
		if err != nil {
			return err
		}
		for k, v := range records {
			if err := b.Put([]byte(k), v); err != nil {
				return err
			}
		}
		legacy, err := tx.CreateBucketIfNotExists([]byte(legacyKey))
		if err != nil {
			return err
		}
		return legacy.Put([]byte(legacyKey), []byte("migrated-to-records:"+name))
	})
}

func (f *BboltStoreImp) StoreRecords(name string, records map[string][]byte) error {
	snapshot := make(map[string][]byte, len(records))
	for k, v := range records {
		if v == nil {
			snapshot[k] = nil
		} else {
			snapshot[k] = append([]byte{}, v...)
		}
	}
	records = snapshot
	// Bound pending batches independently of the database/index locks. Batch may
	// retry callbacks, so this closure has no side effects outside its transaction.
	f.batchOnce.Do(func() { f.batchSlots = make(chan struct{}, 128) })
	f.batchSlots <- struct{}{}
	defer func() { <-f.batchSlots }()
	return f.withDB(func(db *bolt.DB) error {
		return db.Batch(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(name))
			if b == nil {
				return errord.ErrNotFound
			}
			for k, v := range records {
				var err error
				if v == nil {
					err = b.Delete([]byte(k))
				} else {
					err = b.Put([]byte(k), v)
				}
				if err != nil {
					return err
				}
			}
			return nil
		})
	})
}
