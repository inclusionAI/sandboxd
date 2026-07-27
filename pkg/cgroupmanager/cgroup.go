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

package cgroupmanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/metrics"
	"github.com/inclusionAI/sandboxd/internal/util"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/opencontainers/runtime-spec/specs-go"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/sirupsen/logrus"
)

const (
	storeInterval    = 5 * time.Second
	gcInitialBackoff = 100 * time.Millisecond
	gcMaxBackoff     = 10 * time.Second
)

var errCgroupManagerStopped = errors.New("cgroup manager is stopped")

type CgroupManager struct {
	// max is the pool ceiling: using + idle + in-flight creates never exceed it.
	max       int
	cacheSize int
	rootName  string
	pidsMax   int64

	usingID cmap.ConcurrentMap[string, struct{}]
	idleID  *util.Queue[string]

	// cgroups contains every physical child owned by this manager, including
	// active and cached cgroups.
	cgroups   cmap.ConcurrentMap[string, struct{}]
	generator util.UniqueIDGenerator

	// mu guards total and cache admission decisions.
	mu sync.Mutex
	// total = using + idle + in-flight creates. It does not include
	// cgroups already handed to the asynchronous deletion worker.
	total int

	createReqs chan *createRequest

	db         store.DbStore
	storeDirty atomic.Bool

	gcQueue *util.Queue[string]
	gcWake  chan struct{}

	ops cgroupOps
	oom oomWatcher

	stopCh       chan struct{}
	stopped      atomic.Bool
	shutdownOnce sync.Once
	shutdownErr  error
	wg           sync.WaitGroup
}

type createRequest struct {
	result chan createResult
}

type createResult struct {
	id  string
	err error
}

type storedCgroupIDs struct {
	Items []string `json:"items"`
}

// CacheSizeLimit exposes the configured cache target for metrics reporting.
func (c *CgroupManager) CacheSizeLimit() int { return c.cacheSize }

func (c *CgroupManager) gc() {
	defer c.wg.Done()
	attempts := make(map[string]int)
	for {
		select {
		case <-c.stopCh:
			return
		case <-c.gcWake:
		}

		for {
			name := c.gcQueue.Pop()
			metrics.RecordGcQueueLength(
				config.ResourceNameCgroup,
				float64(c.gcQueue.Length()),
			)
			if name == "" {
				break
			}
			if err := c.removeCgroupFromSystem(name); err == nil {
				delete(attempts, name)
				c.generator.Release(name)
				logrus.Debugf("delete cgroup %s from gc queue success", name)
				continue
			} else {
				attempts[name]++
				delay := gcBackoff(attempts[name])
				logrus.Warnf(
					"delete cgroup %s failed (attempt %d), retry in %s: %v",
					name,
					attempts[name],
					delay,
					err,
				)
				if killErr := c.ops.kill(name); killErr != nil {
					logrus.Warnf(
						"kill processes in cgroup %s before retry failed: %v",
						name,
						killErr,
					)
				}
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
					c.gcQueue.Push(name)
				case <-c.stopCh:
					if !timer.Stop() {
						<-timer.C
					}
					return
				}
			}
		}
	}
}

func gcBackoff(attempt int) time.Duration {
	delay := gcInitialBackoff
	for i := 1; i < attempt && delay < gcMaxBackoff; i++ {
		delay *= 2
	}
	if delay > gcMaxBackoff {
		return gcMaxBackoff
	}
	return delay
}

func (c *CgroupManager) ShutDown() error {
	c.shutdownOnce.Do(func() {
		c.stopped.Store(true)
		close(c.stopCh)
		c.wg.Wait()
		if err := c.oom.Close(); err != nil {
			c.shutdownErr = err
		}
		if c.storeDirty.Swap(false) {
			if err := c.store(); err != nil {
				c.storeDirty.Store(true)
				c.shutdownErr = errors.Join(c.shutdownErr, err)
			}
		}
	})
	return c.shutdownErr
}

func (c *CgroupManager) Status() ([]string, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usingID.Keys(), c.idleID.List()
}

// Recycle synchronously returns an active cgroup to the clean idle cache.
// Runtime teardown has already run, so draining and restoring the small set of
// controls managed by sandboxd belongs on this release path, not Start.
func (c *CgroupManager) Recycle(id string) error {
	if _, active := c.usingID.Pop(id); !active {
		return nil
	}
	c.storeDirty.Store(true)

	if !c.cgroups.Has(id) {
		c.mu.Lock()
		c.total--
		c.mu.Unlock()
		return nil
	}

	if err := c.cleanForReuse(id); err != nil {
		logrus.Warnf("clean cgroup %s for reuse failed; destroy it: %v", id, err)
		c.mu.Lock()
		c.total--
		c.mu.Unlock()
		c.deleteCgroup(id)
		return nil
	}

	c.mu.Lock()
	if c.idleID.Length() < c.cacheSize {
		c.idleID.Push(id)
		c.mu.Unlock()
		return nil
	}
	c.total--
	c.mu.Unlock()
	c.deleteCgroup(id)
	return nil
}

func (c *CgroupManager) cleanForReuse(name string) error {
	if err := c.ops.kill(name); err != nil {
		return fmt.Errorf("drain cgroup: %w", err)
	}
	if err := c.ops.reset(name); err != nil {
		return fmt.Errorf("reset managed controls: %w", err)
	}
	if err := c.oom.Reset(name); err != nil {
		return fmt.Errorf("reset OOM state: %w", err)
	}
	return nil
}

// Allocate hands out an idle cgroup name (e.g. "/sandbox/<id>"). On a cache
// miss, creation remains serialized by the maintenance goroutine.
func (c *CgroupManager) Allocate() (string, error) {
	if c.stopped.Load() {
		return "", errCgroupManagerStopped
	}
	if id := c.idleID.Pop(); id != "" {
		c.usingID.Set(id, struct{}{})
		c.storeDirty.Store(true)
		return id, nil
	}

	c.mu.Lock()
	if c.total >= c.max {
		c.mu.Unlock()
		return "", errord.ErrResourceExhausted
	}
	c.total++
	c.mu.Unlock()

	req := &createRequest{result: make(chan createResult, 1)}
	select {
	case c.createReqs <- req:
	case <-c.stopCh:
		c.mu.Lock()
		c.total--
		c.mu.Unlock()
		return "", errCgroupManagerStopped
	}

	select {
	case res := <-req.result:
		if res.err != nil {
			return "", res.err
		}
		c.usingID.Set(res.id, struct{}{})
		c.storeDirty.Store(true)
		return res.id, nil
	case <-c.stopCh:
		return "", errCgroupManagerStopped
	}
}

func (c *CgroupManager) run() {
	defer c.wg.Done()
	c.fillToCacheSize()
	for {
		select {
		case <-c.stopCh:
			return
		case req := <-c.createReqs:
			id, err := c.doCreate()
			if err != nil {
				logrus.Errorf("create cgroup on demand failed: %v", err)
				c.mu.Lock()
				c.total--
				c.mu.Unlock()
				req.result <- createResult{err: err}
				continue
			}
			req.result <- createResult{id: id}
		}
	}
}

func (c *CgroupManager) fillToCacheSize() {
	for !c.stopped.Load() {
		c.mu.Lock()
		if c.idleID.Length() >= c.cacheSize || c.total >= c.max {
			c.mu.Unlock()
			return
		}
		c.total++
		c.mu.Unlock()

		id, err := c.doCreate()
		if err != nil {
			logrus.Errorf("fill cgroup pool failed: %v", err)
			c.mu.Lock()
			c.total--
			c.mu.Unlock()
			return
		}
		c.idleID.Push(id)
	}
}

func (c *CgroupManager) doCreate() (string, error) {
	newID, err := c.generator.Next()
	if err != nil {
		return "", err
	}
	if err = c.ops.create(newID, c.cgroupResources()); err != nil {
		c.generator.Release(newID)
		return "", err
	}
	if err = c.oom.Add(newID); err != nil {
		if deleteErr := c.ops.delete(newID); deleteErr != nil {
			logrus.Warnf(
				"delete cgroup %s after OOM watcher setup failed: %v",
				newID,
				deleteErr,
			)
		}
		c.generator.Release(newID)
		return "", fmt.Errorf("register OOM watcher for cgroup %s: %w", newID, err)
	}
	c.cgroups.Set(newID, struct{}{})
	return newID, nil
}

func (c *CgroupManager) cgroupResources() *specs.LinuxResources {
	resources := &specs.LinuxResources{}
	if c.pidsMax > 0 {
		resources.Pids = &specs.LinuxPids{Limit: c.pidsMax}
	}
	return resources
}

func (c *CgroupManager) deleteCgroup(id string) {
	if !belongsToRoot(id, c.rootName) {
		logrus.Warnf(
			"refusing to delete cgroup %s outside owned root %s",
			id,
			c.rootName,
		)
		return
	}
	if _, exists := c.cgroups.Pop(id); !exists {
		return
	}
	c.oom.Remove(id)
	c.gcQueue.Push(id)
	metrics.RecordGcQueueLength(
		config.ResourceNameCgroup,
		float64(c.gcQueue.Length()),
	)
	select {
	case c.gcWake <- struct{}{}:
	default:
	}
}

func NewCgroupManager(
	db store.DbStore,
	cfg config.ResourceConfig,
	max int,
) (*CgroupManager, error) {
	if cfg.PidsMax < 0 {
		return nil, fmt.Errorf("pids_max must be non-negative")
	}

	configuredRoot := cfg.CgroupRootName
	if configuredRoot == "" {
		configuredRoot = config.DefaultCgroupRoot
	}
	rootName, err := normalizeCgroupRoot(configuredRoot)
	if err != nil {
		return nil, err
	}

	ops, err := newCgroupOps()
	if err != nil {
		return nil, err
	}
	if err := ops.prepareRoot(rootName, cfg.PidsMax); err != nil {
		return nil, err
	}
	oom, err := ops.newOOMWatcher()
	if err != nil {
		return nil, err
	}
	closeOOMOnError := true
	defer func() {
		if closeOOMOnError {
			_ = oom.Close()
		}
	}()

	logrus.Infof(
		"detected cgroup mode %s; using transparent cgroup v%d operations under %s",
		cgroupModeName(ops.mode()),
		cgroupVersion(ops.mode()),
		rootName,
	)

	idData, err := db.LoadRaw(config.CgroupBucket)
	if err != nil && !errord.IsNotFound(err) {
		return nil, err
	}
	var persisted storedCgroupIDs
	if idData != nil {
		if err = json.Unmarshal(idData, &persisted); err != nil {
			return nil, err
		}
		logrus.Infof("load cgroup using id num: %d", len(persisted.Items))
	}

	cgroups, err := loadAllCgroups(ops, rootName)
	if err != nil {
		return nil, err
	}
	if cgroups.Count() > 0 {
		logrus.Infof("load existing cgroup num: %d", cgroups.Count())
	}

	usingIDs := cmap.New[struct{}]()
	recoveryDirty := false
	for _, id := range persisted.Items {
		if !belongsToRoot(id, rootName) || !cgroups.Has(id) {
			logrus.Warnf("drop stale persisted cgroup id %s during recovery", id)
			recoveryDirty = true
			continue
		}
		usingIDs.Set(id, struct{}{})
	}

	c := &CgroupManager{
		max:        max,
		cacheSize:  cfg.CgroupCacheSize,
		rootName:   rootName,
		pidsMax:    cfg.PidsMax,
		usingID:    usingIDs,
		idleID:     util.New(""),
		cgroups:    cgroups,
		generator:  util.NewFixedLengthIDGenerator(12, cgroups.Keys(), util.PrefixID(filepath.Join("/", rootName)+"/")),
		createReqs: make(chan *createRequest, max),
		db:         db,
		gcQueue:    util.New(""),
		gcWake:     make(chan struct{}, 1),
		ops:        ops,
		oom:        oom,
		stopCh:     make(chan struct{}),
	}

	for id := range cgroups.Items() {
		if err := ops.setPidsLimit(id, cfg.PidsMax); err != nil {
			return nil, fmt.Errorf("restore pids limit for cgroup %s: %w", id, err)
		}
		if err := oom.Add(id); err != nil {
			return nil, fmt.Errorf("restore OOM watcher for cgroup %s: %w", id, err)
		}
	}

	for id := range cgroups.Items() {
		if usingIDs.Has(id) {
			continue
		}
		if c.idleID.Length() < c.cacheSize {
			if err := c.cleanForReuse(id); err == nil {
				c.idleID.Push(id)
				continue
			} else {
				logrus.Warnf(
					"clean recovered cgroup %s failed; destroy it: %v",
					id,
					err,
				)
			}
		}
		c.deleteCgroup(id)
	}
	c.total = c.usingID.Count() + c.idleID.Length()
	c.storeDirty.Store(recoveryDirty)

	c.wg.Add(3)
	go c.run()
	go c.gc()
	go c.keepStoring()
	closeOOMOnError = false
	return c, nil
}

func (c *CgroupManager) keepStoring() {
	defer c.wg.Done()
	ticker := time.NewTicker(storeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if !c.storeDirty.Swap(false) {
				continue
			}
			if err := c.store(); err != nil {
				c.storeDirty.Store(true)
				logrus.Warnf("store cgroup using IDs failed: %v", err)
			}
		}
	}
}

func (c *CgroupManager) store() error {
	start := time.Now()
	defer func() {
		logrus.Debugf(
			"store cgroup %d using ids cost: %d ms",
			c.usingID.Count(),
			time.Since(start).Milliseconds(),
		)
	}()
	data, err := json.Marshal(storedCgroupIDs{Items: c.usingID.Keys()})
	if err != nil {
		return fmt.Errorf("encode cgroup using IDs: %w", err)
	}
	if err := c.db.StoreRaw(config.CgroupBucket, data); err != nil {
		return fmt.Errorf("store cgroup using IDs: %w", err)
	}
	return nil
}

func loadAllCgroups(
	ops cgroupOps,
	rootName string,
) (cmap.ConcurrentMap[string, struct{}], error) {
	groupDirs, err := ops.list(rootName)
	if err != nil {
		return cmap.New[struct{}](), err
	}
	cgroups := cmap.New[struct{}]()
	for _, name := range groupDirs {
		if belongsToRoot(name, rootName) {
			cgroups.Set(name, struct{}{})
		}
	}
	return cgroups, nil
}

func (c *CgroupManager) removeCgroupFromSystem(name string) error {
	if !belongsToRoot(name, c.rootName) {
		return fmt.Errorf(
			"refusing to remove cgroup %s outside owned root %s",
			name,
			c.rootName,
		)
	}
	return c.ops.delete(name)
}
