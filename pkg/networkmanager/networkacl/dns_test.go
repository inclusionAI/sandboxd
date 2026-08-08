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

package networkacl

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSConcurrencyLimiterBoundsGlobalAndPerSandboxWork(t *testing.T) {
	limiter, err := newDNSConcurrencyLimiter(2, 1)
	require.NoError(t, err)

	releaseA, ok := limiter.tryAcquire(net.ParseIP("10.88.0.2"))
	require.True(t, ok)
	_, ok = limiter.tryAcquire(net.ParseIP("10.88.0.2"))
	assert.False(t, ok, "one sandbox must not exceed its share")

	releaseB, ok := limiter.tryAcquire(net.ParseIP("10.88.0.3"))
	require.True(t, ok)
	_, ok = limiter.tryAcquire(net.ParseIP("10.88.0.4"))
	assert.False(t, ok, "all sandboxes together must not exceed the global limit")

	releaseA()
	releaseC, ok := limiter.tryAcquire(net.ParseIP("10.88.0.4"))
	require.True(t, ok)
	releaseB()
	releaseC()
	assert.Empty(t, limiter.sandboxInFlight)
}

func TestDNSConcurrencyLimiterRejectsInvalidLimits(t *testing.T) {
	_, err := newDNSConcurrencyLimiter(0, 1)
	require.Error(t, err)
	_, err = newDNSConcurrencyLimiter(1, 0)
	require.Error(t, err)
	_, err = newDNSConcurrencyLimiter(1, 2)
	require.Error(t, err)
}

func TestDNSErrorResponseUsesServerFailureForOverload(t *testing.T) {
	name, err := dnsmessage.NewName("example.com.")
	require.NoError(t, err)
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}},
	}
	payload, err := message.Pack()
	require.NoError(t, err)

	response, err := dnsErrorResponse(payload, dnsmessage.RCodeServerFailure)
	require.NoError(t, err)
	header, questions, _, err := parseDNSQuestions(response)
	require.NoError(t, err)
	assert.True(t, header.Response)
	assert.Equal(t, dnsmessage.RCodeServerFailure, header.RCode)
	assert.Len(t, questions, 1)
}
