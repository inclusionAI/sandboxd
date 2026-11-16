// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// A successful reply covers this request's state in a completed synchronous
// transaction. New arrivals never borrow an already captured snapshot.
type fsCommit struct {
	id       string
	prepared *preparedFS
	state    sandboxFSState
	done     chan error
	queued   time.Time
}

const maxFSCommitBatch = 64

// One transient writer drains requests already waiting, without a batching
// timer. A separate goroutine prevents the first caller waiting for future
// batches. persistMu also orders releases and recovery snapshots.
func (m *fsManager) commitLoop() {
	for {
		m.persistMu.Lock()
		m.queueMu.Lock()
		n := min(len(m.pending), maxFSCommitBatch)
		if n == 0 {
			m.writing = false
			m.queueMu.Unlock()
			m.persistMu.Unlock()
			return
		}
		batch := append([]*fsCommit(nil), m.pending[:n]...)
		clear(m.pending[:n])
		m.pending = m.pending[n:]
		if len(m.pending) == 0 {
			m.pending = nil
		}
		m.queueMu.Unlock()
		start := time.Now()
		m.mu.Lock()
		items := make(map[string]sandboxFSState, len(m.sandboxState)+n)
		for id, state := range m.sandboxState {
			items[id] = cloneFSState(state)
		}
		m.mu.Unlock()
		accepted := make([]*fsCommit, 0, n)
		for _, request := range batch {
			if _, exists := items[request.id]; exists {
				request.done <- fmt.Errorf("filesystem state for sandbox %s already exists", request.id)
				continue
			}
			items[request.id] = request.state
			accepted = append(accepted, request)
		}
		copied := time.Now()
		var err error
		if len(accepted) > 0 {
			err = m.storeFSItems(items, start, copied, len(accepted))
		}
		if err == nil {
			m.mu.Lock()
			for _, request := range accepted {
				prepared := request.prepared
				m.sandboxRootfs[request.id] = prepared.rootfs
				if len(prepared.s3) > 0 {
					m.sandboxS3Mount[request.id] = cloneS3Configs(prepared.s3)
				}
				if len(prepared.oci) > 0 {
					m.sandboxOCIMount[request.id] = append([]string(nil), prepared.oci...)
				}
				m.sandboxState[request.id] = request.state
			}
			m.mu.Unlock()
		}
		m.persistMu.Unlock()
		for _, request := range accepted {
			logrus.WithFields(logrus.Fields{"sandbox": request.id, "lock_wait_ms": start.Sub(request.queued).Seconds() * 1000, "held_ms": time.Since(start).Seconds() * 1000, "batch": len(accepted), "success": err == nil}).Debug("filesystem commit phases")
			if err != nil {
				request.done <- fmt.Errorf("persist filesystem state for sandbox %s: %w", request.id, err)
			} else {
				request.done <- nil
			}
		}
	}
}
