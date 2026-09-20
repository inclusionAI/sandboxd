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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequiredStartResourcesWithoutCgroup(t *testing.T) {
	resources, err := requiredStartResources(config.RuntimeNameRunsc, true)
	require.NoError(t, err)
	assert.Equal(t, []string{config.ResourceNameInterface}, resources)
}

func TestRequiredStartResourcesWithCgroup(t *testing.T) {
	resources, err := requiredStartResources(config.RuntimeNameRunsc, false)
	require.NoError(t, err)
	assert.Equal(t, config.RuntimeResources[config.RuntimeNameRunsc], resources)
}

func TestFirecrackerRequiresCgroup(t *testing.T) {
	_, err := requiredStartResources(config.RuntimeNameFirecracker, true)
	require.ErrorContains(t, err, "requires cgroup management")

	resources, err := requiredStartResources(config.RuntimeNameFirecracker, false)
	require.NoError(t, err)
	assert.Equal(t, config.RuntimeResources[config.RuntimeNameFirecracker], resources)
}

func TestPrepareRequiredStartResourcesReturnsErrorInDeclaredOrder(t *testing.T) {
	secondFinished := make(chan struct{})
	resultCh := make(chan error, 1)

	go func() {
		_, err := prepareRequiredStartResources(
			"sandbox-id",
			[]string{"first", "second"},
			func(name string) (string, *networkmanager.NetResource, error) {
				if name == "first" {
					<-secondFinished
					return "", nil, errors.New("first error")
				}
				close(secondFinished)
				return "", nil, errors.New("second error")
			},
			func(sandbox.OccupiedResource) error { return nil },
		)
		resultCh <- err
	}()

	select {
	case err := <-resultCh:
		require.ErrorContains(t, err, "allocate resource first failed: first error")
	case <-time.After(5 * time.Second):
		t.Fatal("resource allocations did not run concurrently")
	}
}

func TestPrepareRequiredStartResourcesRollsBackSuccessfulAllocations(t *testing.T) {
	var mu sync.Mutex
	allocated := make(map[string]struct{})
	var released sandbox.OccupiedResource

	resources, err := prepareRequiredStartResources(
		"sandbox-id",
		[]string{"successful", "broken"},
		func(name string) (string, *networkmanager.NetResource, error) {
			mu.Lock()
			allocated[name] = struct{}{}
			mu.Unlock()
			if name == "broken" {
				return "", nil, errors.New("allocation failed")
			}
			return "resource-value", nil, nil
		},
		func(resources sandbox.OccupiedResource) error {
			released = resources
			return nil
		},
	)

	require.ErrorContains(t, err, "allocate resource broken failed: allocation failed")
	assert.Nil(t, resources)
	assert.Equal(t, map[string]struct{}{
		"successful": {},
		"broken":     {},
	}, allocated)
	assert.Equal(t, "sandbox-id", released.ID)
	assert.Equal(t, map[string]string{"successful": "resource-value"}, released.Resources)
}
