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

package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/typeurl/v2"
	"github.com/gogo/protobuf/types"
	"github.com/golang/protobuf/proto"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/types/known/anypb"
)

type DbStore interface {
	Store(key string, data interface{}) error
	Load(key string) (*types.Any, error)
	StoreRaw(key string, data []byte) error
	LoadRaw(key string) ([]byte, error)
}

var _ DbStore = &BboltStoreImp{}

type BboltStoreImp struct {
	path string
}

func NewStoreImp(path string) *BboltStoreImp {
	// check if parent dir exists, if not, create it
	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
			logrus.WithError(err).Fatalf("create parent dir for db file failed: %v", err)
		}
	}

	return &BboltStoreImp{
		path: path,
	}
}

func (f *BboltStoreImp) Store(key string, data interface{}) error {
	db, err := bolt.Open(f.path, 0777, nil)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(key))
		if err != nil {
			return err
		}
		dataAny, err := MarshalAnyToProto(data)
		if err != nil {
			return err
		}

		message := FromAny(dataAny)

		result, err := proto.Marshal(message)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), result)
	})
}

type DecodeType struct {
	Content []byte `json:"content"`
}

func (f *BboltStoreImp) StoreRaw(key string, data []byte) error {
	db, err := bolt.Open(f.path, 0777, nil)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(key))
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), append([]byte(nil), data...))
	})
}

func (f *BboltStoreImp) Load(key string) (*types.Any, error) {
	db, err := bolt.Open(f.path, 0666, nil)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	out := types.Any{}
	return &out, db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(key))
		if bucket == nil {
			return errord.ErrNotFound
		}

		bytes := bucket.Get([]byte(key))
		if bytes == nil {
			return nil
		}

		return proto.Unmarshal(bytes, &out)
	})
}

func (f *BboltStoreImp) LoadRaw(key string) ([]byte, error) {
	db, err := bolt.Open(f.path, 0666, nil)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var out []byte
	if err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(key))
		if bucket == nil {
			return errord.ErrNotFound
		}
		bytes := bucket.Get([]byte(key))
		if bytes == nil {
			return errord.ErrNotFound
		}
		out = append([]byte(nil), bytes...)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// FromAny converts typeurl.Any to anypb.Any.
func FromAny(from typeurl.Any) *anypb.Any {
	if from == nil {
		return nil
	}

	if pbany, ok := from.(*anypb.Any); ok {
		return pbany
	}

	return &anypb.Any{
		TypeUrl: from.GetTypeUrl(),
		Value:   from.GetValue(),
	}
}

func MarshalAnyToProto(from interface{}) (*anypb.Any, error) {
	any, err := typeurl.MarshalAny(from)
	if err != nil {
		return nil, err
	}
	return FromAny(any), nil
}

func NewMockStore() *MockStore {
	return &MockStore{
		data: make(map[string][]byte),
	}
}

type MockStore struct {
	data map[string][]byte
	sync.Mutex
}

func (m *MockStore) Store(key string, data interface{}) error {
	m.Lock()
	defer m.Unlock()

	dataAny, err := MarshalAnyToProto(data)
	if err != nil {
		return err
	}

	message := FromAny(dataAny)
	if strings.Contains(message.String(), "failed") {
		return errord.ErrInvalidArgument
	}

	result, err := proto.Marshal(message)
	if err != nil {
		return err
	}

	m.data[key] = result
	return nil
}

func (m *MockStore) StoreRaw(key string, data []byte) error {
	m.Lock()
	defer m.Unlock()

	if strings.Contains(string(data), "failed") {
		return errord.ErrInvalidArgument
	}
	m.data[key] = append([]byte(nil), data...)
	return nil
}

func (m *MockStore) Load(key string) (*types.Any, error) {
	m.Lock()
	defer m.Unlock()
	if data, ok := m.data[key]; ok {
		any := &types.Any{}
		return any, proto.Unmarshal(data, any)
	}
	return nil, errord.ErrNotFound
}

func (m *MockStore) LoadRaw(key string) ([]byte, error) {
	m.Lock()
	defer m.Unlock()
	if data, ok := m.data[key]; ok {
		return append([]byte(nil), data...), nil
	}
	return nil, errord.ErrNotFound
}

var _ DbStore = &MockStore{}
