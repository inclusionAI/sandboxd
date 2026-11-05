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

package oci

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	bolt "go.etcd.io/bbolt"
)

var (
	layerRecordsBucket    = []byte("layer_records")
	mountRecordsBucket    = []byte("mount_records")
	mountTxnBucket        = []byte("mount_txn_records")
	layerDirMapBucket     = []byte("layer_dir_map")
	chainRecordsBucket    = []byte("chain_records")
	chainDirMapBucket     = []byte("chain_dir_map")
	immutableImagesBucket = []byte("immutable_image_records")

	ErrLayerNotFound = errors.New("layer not found")
	ErrChainNotFound = errors.New("chain not found")
)

// LayerRecord stores local extracted layer metadata.
type LayerRecord struct {
	Digest        string `json:"digest"`
	Path          string `json:"path"`
	SizeBytes     int64  `json:"size_bytes"`
	RefCount      int    `json:"ref_count"`
	RefZeroAtUnix int64  `json:"ref_zero_at_unix"`
	LastUsedUnix  int64  `json:"last_used_unix"`
}

// ChainRecord stores local lowdir metadata keyed by Docker-style chainID.
type ChainRecord struct {
	ChainID       string `json:"chain_id"`
	Path          string `json:"path"`
	RefCount      int    `json:"ref_count"`
	RefZeroAtUnix int64  `json:"ref_zero_at_unix"`
	LastUsedUnix  int64  `json:"last_used_unix"`
}

// OciMountRecord stores mounted OCI image metadata.
type OciMountRecord struct {
	ImageURL      string               `json:"image_url"`
	MountID       string               `json:"mount_id"`
	MountPath     string               `json:"mount_path"`
	LayerDigests  []string             `json:"layer_digests"`
	ChainIDs      []string             `json:"chain_ids,omitempty"`
	LowerDirs     []string             `json:"lower_dirs"`
	Env           []string             `json:"env,omitempty"`
	ImageProcess  *imageconfig.Process `json:"image_process,omitempty"`
	CreatedAtUnix int64                `json:"created_at_unix"`
}

// OciMountTxnRecord stores in-progress mount transaction metadata.
type OciMountTxnRecord struct {
	ImageURL      string   `json:"image_url"`
	MountID       string   `json:"mount_id"`
	MountPath     string   `json:"mount_path"`
	LayerDigests  []string `json:"layer_digests"`
	ChainIDs      []string `json:"chain_ids,omitempty"`
	LowerDirs     []string `json:"lower_dirs"`
	CreatedAtUnix int64    `json:"created_at_unix"`
}

type metadataStore struct {
	db *bolt.DB
}

func openMetadataStore(dbPath string) (*metadataStore, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open oci metadata db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(immutableImagesBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(layerRecordsBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(layerDirMapBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(chainRecordsBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(chainDirMapBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(mountRecordsBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(mountTxnBucket); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init oci metadata db buckets: %w", err)
	}

	return &metadataStore{db: db}, nil
}

func (s *metadataStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *metadataStore) putLayer(record *LayerRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal layer record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(layerRecordsBucket).Put([]byte(record.Digest), data)
	})
}

func (s *metadataStore) getLayer(digest string) (*LayerRecord, error) {
	var record *LayerRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(layerRecordsBucket).Get([]byte(digest))
		if v == nil {
			return nil
		}
		record = &LayerRecord{}
		return json.Unmarshal(v, record)
	})
	return record, err
}

func (s *metadataStore) getLayerDir(digest string) (string, error) {
	var dir string
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(layerDirMapBucket).Get([]byte(digest))
		if v == nil {
			return nil
		}
		dir = string(v)
		return nil
	})
	return dir, err
}

func (s *metadataStore) getOrCreateLayerDir(digest string) (string, error) {
	var dir string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(layerDirMapBucket)
		if v := b.Get([]byte(digest)); v != nil {
			dir = string(v)
			return nil
		}

		seq, err := b.NextSequence()
		if err != nil {
			return fmt.Errorf("failed to allocate layer dir sequence: %w", err)
		}
		dir = fmt.Sprintf("l%d", seq)
		return b.Put([]byte(digest), []byte(dir))
	})
	if err != nil {
		return "", err
	}
	return dir, nil
}

func (s *metadataStore) incrementLayerRef(digest string, lastUsedUnix int64) (*LayerRecord, error) {
	var updated *LayerRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(layerRecordsBucket)
		v := b.Get([]byte(digest))
		if v == nil {
			return ErrLayerNotFound
		}
		rec := &LayerRecord{}
		if err := json.Unmarshal(v, rec); err != nil {
			return err
		}
		rec.RefCount++
		rec.RefZeroAtUnix = 0
		rec.LastUsedUnix = lastUsedUnix
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(digest), data); err != nil {
			return err
		}
		updated = rec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *metadataStore) decrementLayerRef(digest string, lastUsedUnix int64) (*LayerRecord, error) {
	var updated *LayerRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(layerRecordsBucket)
		v := b.Get([]byte(digest))
		if v == nil {
			return ErrLayerNotFound
		}
		rec := &LayerRecord{}
		if err := json.Unmarshal(v, rec); err != nil {
			return err
		}
		if rec.RefCount > 0 {
			rec.RefCount--
			if rec.RefCount == 0 {
				rec.RefZeroAtUnix = lastUsedUnix
			}
		} else if rec.RefZeroAtUnix == 0 {
			rec.RefZeroAtUnix = lastUsedUnix
		}
		rec.LastUsedUnix = lastUsedUnix
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(digest), data); err != nil {
			return err
		}
		updated = rec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *metadataStore) deleteLayer(digest string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(layerRecordsBucket).Delete([]byte(digest))
	})
}

func (s *metadataStore) listLayers() ([]*LayerRecord, error) {
	records := make([]*LayerRecord, 0, 32)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(layerRecordsBucket).ForEach(func(_, v []byte) error {
			r := &LayerRecord{}
			if err := json.Unmarshal(v, r); err != nil {
				return err
			}
			records = append(records, r)
			return nil
		})
	})
	return records, err
}

func (s *metadataStore) putChain(record *ChainRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal chain record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(chainRecordsBucket).Put([]byte(record.ChainID), data)
	})
}

func (s *metadataStore) getChain(chainID string) (*ChainRecord, error) {
	var record *ChainRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(chainRecordsBucket).Get([]byte(chainID))
		if v == nil {
			return nil
		}
		record = &ChainRecord{}
		return json.Unmarshal(v, record)
	})
	return record, err
}

func (s *metadataStore) getOrCreateChainDir(chainID string) (string, error) {
	var dir string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(chainDirMapBucket)
		if v := b.Get([]byte(chainID)); v != nil {
			dir = string(v)
			return nil
		}

		seq, err := b.NextSequence()
		if err != nil {
			return fmt.Errorf("failed to allocate chain dir sequence: %w", err)
		}
		dir = fmt.Sprintf("c%d", seq)
		return b.Put([]byte(chainID), []byte(dir))
	})
	if err != nil {
		return "", err
	}
	return dir, nil
}

func (s *metadataStore) incrementChainRef(chainID string, lastUsedUnix int64) (*ChainRecord, error) {
	var updated *ChainRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(chainRecordsBucket)
		v := b.Get([]byte(chainID))
		if v == nil {
			return ErrChainNotFound
		}
		rec := &ChainRecord{}
		if err := json.Unmarshal(v, rec); err != nil {
			return err
		}
		rec.RefCount++
		rec.RefZeroAtUnix = 0
		rec.LastUsedUnix = lastUsedUnix
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(chainID), data); err != nil {
			return err
		}
		updated = rec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *metadataStore) decrementChainRef(chainID string, lastUsedUnix int64) (*ChainRecord, error) {
	var updated *ChainRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(chainRecordsBucket)
		v := b.Get([]byte(chainID))
		if v == nil {
			return ErrChainNotFound
		}
		rec := &ChainRecord{}
		if err := json.Unmarshal(v, rec); err != nil {
			return err
		}
		if rec.RefCount > 0 {
			rec.RefCount--
			if rec.RefCount == 0 {
				rec.RefZeroAtUnix = lastUsedUnix
			}
		} else if rec.RefZeroAtUnix == 0 {
			rec.RefZeroAtUnix = lastUsedUnix
		}
		rec.LastUsedUnix = lastUsedUnix
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(chainID), data); err != nil {
			return err
		}
		updated = rec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *metadataStore) deleteChain(chainID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(chainRecordsBucket).Delete([]byte(chainID))
	})
}

func (s *metadataStore) listChains() ([]*ChainRecord, error) {
	records := make([]*ChainRecord, 0, 32)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(chainRecordsBucket).ForEach(func(_, v []byte) error {
			r := &ChainRecord{}
			if err := json.Unmarshal(v, r); err != nil {
				return err
			}
			records = append(records, r)
			return nil
		})
	})
	return records, err
}

func (s *metadataStore) putMount(record *OciMountRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal mount record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(mountRecordsBucket).Put([]byte(record.ImageURL), data)
	})
}

func (s *metadataStore) getMount(imageURL string) (*OciMountRecord, error) {
	var record *OciMountRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(mountRecordsBucket).Get([]byte(imageURL))
		if v == nil {
			return nil
		}
		record = &OciMountRecord{}
		return json.Unmarshal(v, record)
	})
	return record, err
}

func (s *metadataStore) deleteMount(imageURL string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(mountRecordsBucket).Delete([]byte(imageURL))
	})
}

func (s *metadataStore) listMounts() ([]*OciMountRecord, error) {
	records := make([]*OciMountRecord, 0, 16)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(mountRecordsBucket).ForEach(func(_, v []byte) error {
			r := &OciMountRecord{}
			if err := json.Unmarshal(v, r); err != nil {
				return err
			}
			records = append(records, r)
			return nil
		})
	})
	return records, err
}

func (s *metadataStore) putMountTxn(record *OciMountTxnRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal mount txn record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(mountTxnBucket).Put([]byte(record.ImageURL), data)
	})
}

func (s *metadataStore) getMountTxn(imageURL string) (*OciMountTxnRecord, error) {
	var record *OciMountTxnRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(mountTxnBucket).Get([]byte(imageURL))
		if v == nil {
			return nil
		}
		record = &OciMountTxnRecord{}
		return json.Unmarshal(v, record)
	})
	return record, err
}

func (s *metadataStore) deleteMountTxn(imageURL string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(mountTxnBucket).Delete([]byte(imageURL))
	})
}

func (s *metadataStore) listMountTxns() ([]*OciMountTxnRecord, error) {
	records := make([]*OciMountTxnRecord, 0, 16)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(mountTxnBucket).ForEach(func(_, v []byte) error {
			r := &OciMountTxnRecord{}
			if err := json.Unmarshal(v, r); err != nil {
				return err
			}
			records = append(records, r)
			return nil
		})
	})
	return records, err
}
