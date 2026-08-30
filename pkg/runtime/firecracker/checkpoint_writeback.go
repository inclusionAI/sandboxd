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

package firecracker

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	checkpointWritebackWorkers = 4
	checkpointWritebackDepth   = 256
)

type checkpointWritebackFunc func(string) error

type checkpointWritebackScheduler struct {
	queue chan string
}

func newCheckpointWritebackScheduler() *checkpointWritebackScheduler {
	return newCheckpointWritebackSchedulerWith(
		checkpointWritebackWorkers,
		checkpointWritebackDepth,
		startCheckpointMemoryWriteback,
	)
}

func newCheckpointWritebackSchedulerWith(
	workers, depth int,
	writeback checkpointWritebackFunc,
) *checkpointWritebackScheduler {
	scheduler := &checkpointWritebackScheduler{queue: make(chan string, depth)}
	for range workers {
		go func() {
			for path := range scheduler.queue {
				started := time.Now()
				if err := writeback(path); err != nil {
					logrus.Warnf(
						"firecracker: start checkpoint memory writeback for %s: %v",
						path,
						err,
					)
					continue
				}
				logrus.Debugf(
					"firecracker: started checkpoint memory writeback for %s in %s",
					path,
					time.Since(started),
				)
			}
		}()
	}
	return scheduler
}

func (scheduler *checkpointWritebackScheduler) schedule(path string) bool {
	select {
	case scheduler.queue <- path:
		return true
	default:
		return false
	}
}

// startCheckpointMemoryWriteback asks Linux to begin writing dirty pages for
// the complete file, but deliberately does not wait for I/O completion.
func startCheckpointMemoryWriteback(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := unix.SyncFileRange(
		int(file.Fd()),
		0,
		0,
		unix.SYNC_FILE_RANGE_WRITE,
	); err != nil {
		return fmt.Errorf("sync_file_range(WRITE): %w", err)
	}
	return nil
}
