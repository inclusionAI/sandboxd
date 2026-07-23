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
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestDataConvert(t *testing.T) {
	mockData := &anypb.Any{
		TypeUrl: "type.googleapis.com/sandboxd.test.Payload",
		Value:   []byte("key1=value1"),
	}
	mockDataAny, err := MarshalAnyToProto(mockData)
	if err != nil {
		t.Fatalf("MarshalAnyToProto() error = %v", err)
	}
	any := FromAny(mockDataAny)
	if any == nil {
		t.Fatalf("FromAny() error, result is nill")
	}

	if strings.Contains(any.String(), "key1") == false || strings.Contains(any.String(), "value1") == false {
		t.Fatalf("FromAny() error, result is not equal, got: %s", any.String())
	}
}

func TestStore(t *testing.T) {
	mockDB := NewMockStore()
	fooData := &anypb.Any{
		TypeUrl: "type.googleapis.com/sandboxd.test.Payload",
		Value:   []byte("payload"),
	}
	assert.Equal(t, nil, mockDB.Store("foo", fooData))
	_, err := mockDB.Load("x")
	assert.Equal(t, errord.ErrNotFound, err)
	FooData, err := mockDB.Load("foo")
	assert.Equal(t, nil, err)

	// check load result
	assert.Equal(t, fooData.GetTypeUrl(), FooData.GetTypeUrl())
	assert.Equal(t, fooData.GetValue(), FooData.GetValue())

	// mock struct with failed
	failedString := &anypb.Any{
		TypeUrl: "failed",
		Value:   []byte("failed"),
	}
	assert.NotNil(t, mockDB.Store("bar", failedString))

	// incorrect format of data
	badString := "xxx"
	assert.NotNil(t, mockDB.Store("bar", &badString))
}

func TestRawStore(t *testing.T) {
	mockDB := NewMockStore()
	raw := []byte(`{"items":["one","two"]}`)
	assert.Nil(t, mockDB.StoreRaw("foo", raw))

	got, err := mockDB.LoadRaw("foo")
	assert.Nil(t, err)
	assert.Equal(t, raw, got)

	got[0] = 'x'
	gotAgain, err := mockDB.LoadRaw("foo")
	assert.Nil(t, err)
	assert.Equal(t, raw, gotAgain)

	_, err = mockDB.LoadRaw("missing")
	assert.Equal(t, errord.ErrNotFound, err)
	assert.NotNil(t, mockDB.StoreRaw("bar", []byte("failed")))
}
