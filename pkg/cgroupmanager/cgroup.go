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
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	runtime "github.com/akernel-dev/sandboxd/api/runtime/v1"
	"github.com/akernel-dev/sandboxd/config"
	"github.com/akernel-dev/sandboxd/internal/metrics"
	"github.com/akernel-dev/sandboxd/internal/util"
	"github.com/akernel-dev/sandboxd/pkg/errord"
	"github.com/akernel-dev/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/sirupsen/logrus"
)

type CgroupManager struct {
	// max is the pool ceiling: using + idle + in-flight creates never exceed it.
	max       int
	cacheSize int
	rootName  string
	pidsMax   int64

	usingID cmap.ConcurrentMap[string, struct{}]
	idleID  *util.Queue[string]

	// It maintains all cgroups under /huse before sandboxd starts and all cgroups created by sandboxd
	// All used/reused cgroups must be in this list.
	cgroups   cmap.ConcurrentMap[string, struct{}]
	generator util.UniqueIDGenerator
	// if enableDestroyRecycle is true, the cgroup will be destroyed when be recycled.
	enableDestroyRecycle bool

	// mu guards total and the slow-path pool decisions (reserve / fill /
	// shrink). The fast paths (Allocate hit, Recycle) only touch the
	// self-locking idleID queue and usingID map and do not take mu.
	mu sync.Mutex
	// total = usingID.Count() + idleID.Length() + in-flight creates. It is the
	// authoritative count checked against max. Guarded by mu.
	total int
	// createReqs delivers on-demand create requests to the single maintenance
	// goroutine. Buffered to max so a reserved Allocate never blocks on submit.
	createReqs chan *createRequest

	db store.DbStore

	// storeMark is used to mark whether the cgroup id need to be stored.
	// If it's true, manager should not exit.
	storeMark atomic.Bool

	gcQueue *util.Queue[string]

	// driver owns all cgroup-version-specific kernel operations.
	driver driver
}

const RetryGenIdTimes = 100

// shrinkInterval is how often the maintenance goroutine checks whether the pool
// holds more idle cgroups than cacheSize and trims the excess. The periodic
// timer ONLY shrinks — growth is demand-driven (init fill + on-demand create),
// never timer-driven.
const shrinkInterval = 30 * time.Second

// createRequest is submitted by Allocate when the idle pool is empty but the
// pool is still below max. It asks the single maintenance goroutine to create
// one cgroup on demand; the result is delivered back on result.
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
	for {
		metrics.RecordGcQueueLength(config.ResourceNameCgroup, float64(c.gcQueue.Length()))
		cg := c.gcQueue.Pop()
		if cg == "" {
			time.Sleep(1 * time.Second)
			continue
		}
		if c.removeCgroupFromSystem(cg) != nil {
			logrus.Debugf("delete cgroup %v from gc queue failed, put it back to queue", cg)
			_ = c.driver.Kill(cg)
			c.gcQueue.Push(cg)
		} else {
			logrus.Debugf("delete cgroup %v from gc queue success", cg)
			c.generator.Release(cg)
		}
	}
}

func (c *CgroupManager) ShutDown() error {
	if c.storeMark.Load() {
		c.store()
	}
	return nil
}

func (c *CgroupManager) Status() ([]string, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usingID.Keys(), c.idleID.List()
}

func (c *CgroupManager) Update(name string, resources *runtime.LinuxSandboxResources) error {
	return c.driver.Update(name, resources)
}

func (c *CgroupManager) Stats(name string) (Stats, error) {
	return c.driver.Stats(name)
}

func (c *CgroupManager) WatchOOM(name string, onOOM func()) (func(), error) {
	return c.driver.WatchOOM(name, onOOM)
}

func (c *CgroupManager) Recycle(id string) error {
	c.usingID.Remove(id)
	defer c.storeMark.Store(true)
	if c.enableDestroyRecycle {
		// The cgroup is torn down on recycle, so it leaves the pool entirely.
		if c.cgroups.Has(id) {
			c.mu.Lock()
			c.total--
			c.mu.Unlock()
		}
		c.deleteCgroup(id)
		return nil
	}
	return c.recycleWithReuse(id)
}

func (c *CgroupManager) recycleWithReuse(id string) error {
	// Never recycle cgroups which aren't in c.cgroups. Such ids were never
	// counted in total either, so leave total untouched.
	if !c.cgroups.Has(id) {
		return nil
	}
	// using -> idle, total unchanged.
	c.idleID.Push(id)
	return nil
}

// Allocate hands out an idle cgroup name (e.g. "/sandbox/<id>"). The caller
// is expected to bake the result into the sandbox's OCI Linux.CgroupsPath.
//
// Fast path: pop the idle queue. On a miss it either reserves a slot and waits
// for the maintenance goroutine to create one on demand (when below max), or
// fails fast with ErrResourceExhausted (at max, no blocking, no timeout).
func (c *CgroupManager) Allocate() (string, error) {
	if id := c.idleID.Pop(); id != "" {
		// idle -> using, total unchanged.
		c.usingID.Set(id, struct{}{})
		c.storeMark.Store(true)
		return id, nil
	}

	c.mu.Lock()
	if c.total >= c.max {
		c.mu.Unlock()
		return "", errord.ErrResourceExhausted
	}
	c.total++ // reserve a slot for the about-to-be-created cgroup
	c.mu.Unlock()

	req := &createRequest{result: make(chan createResult, 1)}
	c.createReqs <- req
	res := <-req.result
	if res.err != nil {
		// total was already decremented by the maintenance goroutine.
		return "", res.err
	}
	c.usingID.Set(res.id, struct{}{})
	c.storeMark.Store(true)
	return res.id, nil
}

// run is the single maintenance goroutine: it performs all create/destroy
// serially. It fills the idle pool to cacheSize once at startup, then serves
// on-demand create requests and periodically shrinks excess idle back to
// cacheSize.
func (c *CgroupManager) run() {
	c.fillToCacheSize()
	ticker := time.NewTicker(shrinkInterval)
	defer ticker.Stop()
	for {
		select {
		case req := <-c.createReqs:
			id, err := c.doCreate()
			if err != nil {
				logrus.Errorf("create cgroup on demand failed: %v", err)
				c.mu.Lock()
				c.total-- // release the reservation
				c.mu.Unlock()
				req.result <- createResult{err: err}
				continue
			}
			// Hand the new cgroup straight to the waiting Allocate; it goes to
			// using (the reservation already accounts for it in total).
			req.result <- createResult{id: id}
		case <-ticker.C:
			c.shrink()
		}
	}
}

// fillToCacheSize creates idle cgroups until idle reaches cacheSize (or max).
func (c *CgroupManager) fillToCacheSize() {
	for {
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

// shrink trims idle cgroups down to cacheSize. cgroup teardown is cheap (it is
// enqueued to the async gc queue), so no pacing is needed.
func (c *CgroupManager) shrink() {
	for {
		c.mu.Lock()
		if c.idleID.Length() <= c.cacheSize {
			c.mu.Unlock()
			return
		}
		id := c.idleID.Pop()
		if id == "" {
			c.mu.Unlock()
			return
		}
		c.total--
		c.mu.Unlock()
		c.deleteCgroup(id)
	}
}

// doCreate creates one cgroup and returns its id. Called only by run().
func (c *CgroupManager) doCreate() (string, error) {
	newID, err := c.generator.Next()
	if err != nil {
		return "", err
	}
	if err = c.driver.Create(newID, c.pidsMax); err != nil {
		c.generator.Release(newID)
		return "", err
	}
	c.cgroups.Set(newID, struct{}{})
	c.storeMark.Store(true)
	return newID, nil
}

func (c *CgroupManager) deleteCgroup(id string) {
	if !strings.Contains(id, c.rootName) {
		logrus.Debugf("cgroup %s is legal, does not belong to %s", id, c.rootName)
		return
	}

	c.cgroups.Remove(id)
	c.gcQueue.Push(id)
	c.storeMark.Store(true)
}

func (c *CgroupManager) cacheNum() int {
	return c.idleID.Length()
}

func NewCgroupManager(
	db store.DbStore,
	cfg config.ResourceConfig,
	max int,
) (*CgroupManager, error) {
	if cfg.PidsMax < 0 {
		return nil, fmt.Errorf("pids_max must be non-negative")
	}

	rootName, err := resolvedCgroupRoot(cfg)
	if err != nil {
		return nil, err
	}
	drv, err := newDriver(cfg)
	if err != nil {
		return nil, err
	}
	if err = drv.PrepareRoot(rootName); err != nil {
		return nil, err
	}
	normalizedVersion, _ := config.NormalizeCgroupVersion(cfg.CgroupVersion)
	// load using id from db
	idData, err := db.LoadRaw(config.CgroupBucket)
	if err != nil && !errord.IsNotFound(err) {
		return nil, err
	}
	var usingID storedCgroupIDs
	if idData != nil {
		if err = json.Unmarshal(idData, &usingID); err != nil {
			return nil, err
		} else {
			logrus.Infof("load cgroup using id num: %v", len(usingID.Items))
		}
	}

	// Load all cgroups under rootName through the selected kernel driver.
	groups, err := drv.List(rootName)
	if err != nil {
		return nil, err
	}
	cgs := cmap.New[struct{}]()
	for _, group := range groups {
		cgs.Set(group, struct{}{})
	}
	if cgs.Count() > 0 {
		logrus.Infof("load existsing cgroup num: %v", cgs.Count())
	}
	idleIDs := util.New[string]("")
	usingIDs := cmap.New[struct{}]()
	for _, id := range usingID.Items {
		if normalizedVersion == config.CgroupVersionV2 && !cgs.Has(id) {
			logrus.Warnf("ignore stale persisted cgroup v2 id %s because it does not exist", id)
			continue
		}
		usingIDs.Set(id, struct{}{})
	}

	c := &CgroupManager{
		max:                  max,
		cacheSize:            cfg.CgroupCacheSize,
		rootName:             rootName,
		pidsMax:              cfg.PidsMax,
		usingID:              usingIDs,
		idleID:               idleIDs,
		createReqs:           make(chan *createRequest, max),
		gcQueue:              util.New[string](""),
		generator:            util.NewFixedLengthIDGenerator(12, cgs.Keys(), util.PrefixID(filepath.Join("/", rootName)+"/")),
		db:                   db,
		cgroups:              cgs,
		storeMark:            atomic.Bool{},
		enableDestroyRecycle: cfg.RecyclePolicy == config.RecyclePolicyDestroy,
		driver:               drv,
	}

	// Adopt existing non-using cgroups into the idle pool (up to cacheSize) so a
	// restart reuses them instead of destroying then recreating; delete the
	// excess. The maintenance goroutine then tops idle up to cacheSize.
	for id := range cgs.Items() {
		if usingIDs.Has(id) {
			continue
		}
		if !c.enableDestroyRecycle && c.idleID.Length() < c.cacheSize {
			c.idleID.Push(id)
		} else {
			c.deleteCgroup(id)
		}
	}
	c.total = c.usingID.Count() + c.idleID.Length()
	c.keepStoring()
	go c.run()
	go c.gc()

	return c, nil
}

func (c *CgroupManager) keepStoring() {
	go func() {
		for {
			select {
			case <-time.After(5 * time.Second):
				if c.storeMark.Load() {
					c.storeMark.Store(false)
					c.store()
				}
			}
		}
	}()
}

func (c *CgroupManager) store() {
	start := time.Now()
	defer func() {
		logrus.Debugf("store cgroup %v using id cost: %v ms", c.usingID.Count(), time.Since(start).Milliseconds())
	}()
	dataToStore, err := json.Marshal(storedCgroupIDs{Items: c.usingID.Keys()})
	if err != nil {
		logrus.Warnf("encode cgroup using id failed: %v", err)
		return
	}
	if err := c.db.StoreRaw(config.CgroupBucket, dataToStore); err != nil {
		logrus.Warnf("store cgroup using id failed: %v", err)
	}
}

func (c *CgroupManager) removeCgroupFromSystem(name string) error {
	return c.driver.Delete(name)
}
