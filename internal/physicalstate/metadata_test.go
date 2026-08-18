// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package physicalstate

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// This fixture was encoded by the public runtime.v1.SandboxMetadata message
// before physical coordination state moved under internal/. Its field numbers
// and wire types are an on-disk upgrade contract even though they are not a
// remote API contract.
const legacyPhysicalIntentHex = "0a0d6c65676163792d696e74656e741a0572756e7363221e0a117461726765745f617474656d70745f69641209617474656d70742d6132082f746d702f6f75743a082f746d702f65727242120a0674656e616e74120874656e616e742d614a0e7463703a34313038303a3830383050015a140a0c636865636b706f696e742d61120461626364620e0a066367726f7570120463672d3162120a09696e7465726661636512056e65742d31"

func TestLegacyMetadataWireFormatRestoresPrivatePhysicalIntent(t *testing.T) {
	encoded, err := hex.DecodeString(legacyPhysicalIntentHex)
	require.NoError(t, err)

	var metadata SandboxMetadata
	require.NoError(t, proto.Unmarshal(encoded, &metadata))
	require.Equal(t, "legacy-intent", metadata.ID)
	require.Equal(t, "runsc", metadata.RuntimeHandler)
	require.Equal(t, PhysicalPhase_PHYSICAL_PHASE_INTENT, metadata.PhysicalPhase)
	require.Equal(t, []string{"tcp:41080:8080"}, metadata.Ports)
	require.Equal(t, "attempt-a", metadata.Labels["target_attempt_id"])
	require.Equal(t, "checkpoint-a", metadata.RestoreIdentity.GetCheckpointID())
	require.Equal(t, "abcd", metadata.RestoreIdentity.GetRequestSha256())
	require.Equal(t, "cg-1", metadata.ResourceFacts["cgroup"])
	require.Equal(t, "net-1", metadata.ResourceFacts["interface"])
}
