// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package physicalstate

import "errors"

// ErrRestoreCleanupIncomplete marks an uncertain physical runtime deletion.
// The server must retain the corresponding INTENT and its prepared resources
// so startup reconciliation can locate and remove the exact runtime.
var ErrRestoreCleanupIncomplete = errors.New("restore runtime cleanup is incomplete")
