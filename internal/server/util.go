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
	"fmt"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

func (h *sandboxService) checkRuntime(requestRuntime string) error {
	if !h.serviceHandler.Has(requestRuntime) {
		return fmt.Errorf("runtime handler %q is not supported", requestRuntime)
	}
	return nil
}

// Admission is runtime-specific. Cleanup must still reach a degraded handler.
func (h *sandboxService) checkRuntimeAdmission(requestRuntime string) error {
	if err := h.checkRuntime(requestRuntime); err != nil {
		return err
	}
	if h.sandboxManager != nil {
		if err := h.sandboxManager.RuntimeHealthError(requestRuntime); err != nil {
			return errord.ToGRPCf(errord.ErrUnavailable, "runtime %q reconciliation unavailable: %v", requestRuntime, err)
		}
	}
	return nil
}
