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

package oci

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/sys/mountinfo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/diskusage"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageregistry"
)

const (
	containerNamePrefix = "akernel-oci-"

	// PruneInterval is the interval between background disk-pressure GC checks.
	PruneInterval = 2 * time.Minute
	// defaultGlobalLayerWorkers limits global concurrent layer extraction.
	defaultGlobalLayerWorkers = 4
	// defaultLayerZeroRefTTL is the default TTL for unreferenced layers.
	defaultLayerZeroRefTTL = 30 * time.Minute

	diskUsageGCStart = 0.85
	diskUsageGCStop  = 0.75
)

// Config holds the OCI configuration parsed from config file.
type Config struct {
	Proxy *ProxyConfig `json:"proxy,omitempty"`
}

// ProxyConfig mirrors distillfs.ProxyConfig for config parsing.
type ProxyConfig struct {
	Url string `json:"url"`
}

// Manager manages local OCI layer extraction and readonly overlay mounts.
type Manager struct {
	root      string
	layersDir string
	chainsDir string
	mountsDir string
	proxy     string

	registry *imageregistry.Client
	store    *metadataStore

	mutex sync.Mutex
	// image_url -> container info
	containers map[string]*ContainerInfo
	imageLocks map[string]*imageLockEntry
	layerLocks map[string]*imageLockEntry
	chainLocks map[string]*imageLockEntry

	stopOnce sync.Once
	stopCh   chan struct{}

	now       func() time.Time
	mountFn   func(target string, lowerDirs []string) error
	unmountFn func(target string) error
	diskUsage func(path string) (float64, error)
	readMnts  func() (map[string]struct{}, bool, error)

	layerWorkers  int
	layerJobs     chan layerExtractJob
	layerPoolWG   sync.WaitGroup
	layerPoolOnce sync.Once
	layerPoolMu   sync.Mutex
	layerTTL      time.Duration
}

type imageLockEntry struct {
	mu   sync.Mutex
	refs int
}

// ContainerInfo stores mount-related information.
type ContainerInfo struct {
	MountID      string
	ImageURL     string
	MountPath    string
	LayerDigests []string
	ChainIDs     []string
	LowerDirs    []string
	Env          []string
}

// NewManager creates a new OCI manager.
// sharedRegistryClient is optional. If nil, an anonymous registry client is used.
func NewManager(rootWorkDir string, cfgTempPath string, sharedRegistryClient ...*imageregistry.Client) (*Manager, error) {
	root := filepath.Join(rootWorkDir, "oci")
	layersDir := filepath.Join(root, "layers")
	chainsDir := filepath.Join(root, "lowerdirs")
	mountsDir := filepath.Join(root, "mounts")
	dbPath := filepath.Join(root, "metadata.db")

	var proxy string
	if cfgTempPath != "" {
		cfg, err := loadConfig(cfgTempPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		if cfg.Proxy != nil {
			proxy = cfg.Proxy.Url
			logrus.Infof("OCI manager HTTP proxy: %s", proxy)
		}
	}

	if err := os.MkdirAll(layersDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create layers dir %s: %w", layersDir, err)
	}
	if err := os.MkdirAll(chainsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create lowerdirs dir %s: %w", chainsDir, err)
	}
	if err := os.MkdirAll(mountsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create mounts dir %s: %w", mountsDir, err)
	}

	store, err := openMetadataStore(dbPath)
	if err != nil {
		return nil, err
	}

	var registryClient *imageregistry.Client
	if len(sharedRegistryClient) > 0 && sharedRegistryClient[0] != nil {
		registryClient = sharedRegistryClient[0]
	} else {
		registryClient, err = imageregistry.NewClient("")
		if err != nil {
			store.close()
			return nil, fmt.Errorf("failed to create registry client: %w", err)
		}
	}

	mgr := &Manager{
		root:       root,
		layersDir:  layersDir,
		chainsDir:  chainsDir,
		mountsDir:  mountsDir,
		proxy:      proxy,
		registry:   registryClient,
		store:      store,
		containers: make(map[string]*ContainerInfo),
		imageLocks: make(map[string]*imageLockEntry),
		layerLocks: make(map[string]*imageLockEntry),
		chainLocks: make(map[string]*imageLockEntry),
		stopCh:     make(chan struct{}),
		now:        time.Now,
		mountFn:    defaultOverlayMount,
		unmountFn:  defaultOverlayUnmount,
		diskUsage:  defaultDiskUsage,
		readMnts: func() (map[string]struct{}, bool, error) {
			return readManagedMounts(mountsDir)
		},
		layerWorkers: defaultGlobalLayerWorkers,
		layerTTL:     defaultLayerZeroRefTTL,
	}

	if err := mgr.reconcileState(); err != nil {
		logrus.Warnf("failed to reconcile OCI metadata at startup: %v", err)
	}

	go mgr.pruneImagesLoop()
	return mgr, nil
}

// loadConfig loads the configuration from the given file path.
func loadConfig(cfgPath string) (*Config, error) {
	file, err := os.Open(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var cfg Config
	if err = json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	return &cfg, nil
}

// pruneImagesLoop runs GC checks on interval.
func (m *Manager) pruneImagesLoop() {
	ticker := time.NewTicker(PruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.gcLayers(); err != nil {
				logrus.Warnf("OCI GC check failed: %v", err)
			}
		case <-m.stopCh:
			return
		}
	}
}

func (m *Manager) gcLayers() error {
	return m.gcLayersWithContext(context.Background())
}

func (m *Manager) gcLayersWithContext(ctx context.Context) error {
	timing, _ := StartOCITimedOperation(ctx, "oci.GCLayers", m.root)
	defer timing.End()

	stageStart := time.Now()
	if err := m.gcChainsByTTL(); err != nil {
		timing.RecordError(err)
		return err
	}
	timing.Stage("chain_ttl_gc", time.Since(stageStart))

	stageStart = time.Now()
	if err := m.gcLayersByTTL(); err != nil {
		timing.RecordError(err)
		return err
	}
	timing.Stage("ttl_gc", time.Since(stageStart))

	stageStart = time.Now()
	if err := m.gcChainsByDiskPressure(); err != nil {
		timing.RecordError(err)
		return err
	}
	timing.Stage("chain_disk_pressure_gc", time.Since(stageStart))

	stageStart = time.Now()
	if err := m.gcLayersByDiskPressure(); err != nil {
		timing.RecordError(err)
		return err
	}
	timing.Stage("disk_pressure_gc", time.Since(stageStart))

	return nil
}

// MountImage pulls and extracts OCI layers, then mounts a readonly overlay rootfs.
func (m *Manager) MountImage(imageURL string) (string, []string, error) {
	return m.MountImageWithContext(context.Background(), imageURL)
}

// MountImageWithContext pulls and extracts OCI layers, then mounts a readonly overlay rootfs.
// Returns the mount path, environment variables from the image config, and any error.
func (m *Manager) MountImageWithContext(ctx context.Context, imageURL string) (mountPath string, envVars []string, retErr error) {
	timing, ctx := StartOCITimedOperation(ctx, "oci.MountImage", imageURL)
	defer timing.End()
	opStart := time.Now()
	logrus.Infof("OCI mount start: image=%s", imageURL)
	defer func() {
		if retErr != nil {
			logrus.Warnf("OCI mount failed: image=%s cost=%s err=%v", imageURL, time.Since(opStart), retErr)
		}
	}()

	stageStart := time.Now()
	if imageURL == "" {
		err := fmt.Errorf("imageURL is required")
		timing.RecordError(err)
		return "", nil, err
	}
	timing.Stage("validate_request", time.Since(stageStart))

	unlockImage := m.acquireImageLock(imageURL)
	defer unlockImage()

	var (
		txn               *OciMountTxnRecord
		reservedDigests   []string
		reservedChainIDs  []string
		rollbackResources = true
	)
	defer func() {
		if rollbackResources {
			m.rollbackMountTransaction(txn, reservedDigests, reservedChainIDs)
		}
	}()

	stageStart = time.Now()
	if info := m.getContainer(imageURL); info != nil {
		timing.Stage("reuse_in_memory_mount", time.Since(stageStart))
		logrus.Infof("OCI mount reuse in-memory: image=%s mount_path=%s cost=%s", imageURL, info.MountPath, time.Since(opStart))
		return info.MountPath, info.Env, nil
	}

	// Reuse mounted state restored from BoltDB after restart.
	if rec, err := m.store.getMount(imageURL); err == nil && rec != nil {
		info := &ContainerInfo{
			MountID:      rec.MountID,
			ImageURL:     rec.ImageURL,
			MountPath:    rec.MountPath,
			LayerDigests: append([]string(nil), rec.LayerDigests...),
			ChainIDs:     append([]string(nil), rec.ChainIDs...),
			LowerDirs:    append([]string(nil), rec.LowerDirs...),
			Env:          append([]string(nil), rec.Env...),
		}
		m.setContainer(imageURL, info)
		timing.Stage("reuse_persisted_mount", time.Since(stageStart))
		logrus.Infof("OCI mount reuse persisted: image=%s mount_path=%s cost=%s", imageURL, rec.MountPath, time.Since(opStart))
		return rec.MountPath, rec.Env, nil
	}
	timing.Stage("check_existing_mount", time.Since(stageStart))

	stageStart = time.Now()
	mountID := generateContainerID(imageURL)
	timing.Stage("prepare_mount_id", time.Since(stageStart))

	stageStart = time.Now()
	img, err := m.fetchImage(ctx, imageURL)
	if err != nil {
		timing.RecordError(err)
		return "", nil, err
	}
	timing.Stage("fetch_image", time.Since(stageStart))

	// Extract environment variables from image config
	if cfg, cfgErr := img.ConfigFile(); cfgErr == nil && cfg != nil {
		envVars = cfg.Config.Env
		if len(envVars) == 0 {
			logrus.Debugf("image config has no env vars: %s", imageURL)
		}
	} else if cfgErr != nil {
		logrus.Warnf("failed to read image config for env extraction: %s: %v", imageURL, cfgErr)
	}

	stageStart = time.Now()
	layers, err := img.Layers()
	if err != nil {
		err = fmt.Errorf("failed to get image layers for %s: %w", imageURL, err)
		timing.RecordError(err)
		return "", nil, err
	}
	if len(layers) == 0 {
		err = fmt.Errorf("image %s has no layers", imageURL)
		timing.RecordError(err)
		return "", nil, err
	}
	timing.Stage("list_layers", time.Since(stageStart))
	logrus.Infof("OCI mount fetched manifest: image=%s layer_count=%d", imageURL, len(layers))

	stageStart = time.Now()
	diffIDs, err := resolveImageLayerDiffIDs(img, layers)
	if err != nil {
		timing.RecordError(err)
		return "", nil, err
	}
	chainIDs, err := buildChainIDs(diffIDs)
	if err != nil {
		timing.RecordError(err)
		return "", nil, err
	}
	timing.Stage("build_chain_ids", time.Since(stageStart))

	stageStart = time.Now()
	layerDigests, layerPaths, err := m.extractLayersWithWorkers(ctx, layers)
	if err != nil {
		timing.RecordError(err)
		return "", nil, err
	}
	timing.Stage("extract_layers", time.Since(stageStart))
	reservedDigests = append(reservedDigests, layerDigests...)

	stageStart = time.Now()
	chainPaths, err := m.ensureChainLowerDirs(chainIDs, layerPaths)
	if err != nil {
		timing.RecordError(err)
		return "", nil, err
	}
	timing.Stage("prepare_lowerdirs", time.Since(stageStart))
	reservedChainIDs = append(reservedChainIDs, chainIDs...)

	lowerDirs := reverseCopy(chainPaths)
	mountPath = filepath.Join(m.mountsDir, mountID, "merged")
	txn = &OciMountTxnRecord{
		ImageURL:      imageURL,
		MountID:       mountID,
		MountPath:     mountPath,
		LayerDigests:  append([]string(nil), layerDigests...),
		ChainIDs:      append([]string(nil), chainIDs...),
		LowerDirs:     append([]string(nil), lowerDirs...),
		CreatedAtUnix: m.now().Unix(),
	}
	stageStart = time.Now()
	if err := m.store.putMountTxn(txn); err != nil {
		err = fmt.Errorf("failed to persist mount transaction for %s: %w", imageURL, err)
		timing.RecordError(err)
		return "", nil, err
	}
	timing.Stage("persist_mount_txn", time.Since(stageStart))

	stageStart = time.Now()
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		err = fmt.Errorf("failed to create mount path %s: %w", mountPath, err)
		timing.RecordError(err)
		return "", nil, err
	}

	if err := m.mountFn(mountPath, lowerDirs); err != nil {
		err = fmt.Errorf("failed to mount overlay rootfs for %s: %w", imageURL, err)
		timing.RecordError(err)
		return "", nil, err
	}
	timing.Stage("overlay_mount", time.Since(stageStart))

	record := &OciMountRecord{
		ImageURL:      imageURL,
		MountID:       mountID,
		MountPath:     mountPath,
		LayerDigests:  append([]string(nil), layerDigests...),
		ChainIDs:      append([]string(nil), chainIDs...),
		LowerDirs:     append([]string(nil), lowerDirs...),
		Env:           append([]string(nil), envVars...),
		CreatedAtUnix: m.now().Unix(),
	}
	stageStart = time.Now()
	if err := m.store.putMount(record); err != nil {
		err = fmt.Errorf("failed to persist oci mount metadata: %w", err)
		timing.RecordError(err)
		return "", nil, err
	}
	if err := m.store.deleteMountTxn(imageURL); err != nil {
		logrus.Warnf("failed to finalize mount transaction for %s: %v", imageURL, err)
	}
	timing.Stage("persist_mount_record", time.Since(stageStart))

	m.setContainer(imageURL, &ContainerInfo{
		MountID:      mountID,
		ImageURL:     imageURL,
		MountPath:    mountPath,
		LayerDigests: append([]string(nil), layerDigests...),
		ChainIDs:     append([]string(nil), chainIDs...),
		LowerDirs:    append([]string(nil), lowerDirs...),
		Env:          append([]string(nil), envVars...),
	})
	rollbackResources = false
	logrus.Infof("OCI mount success: image=%s mount_id=%s mount_path=%s layers=%d cost=%s", imageURL, mountID, mountPath, len(layerDigests), time.Since(opStart))

	return mountPath, envVars, nil
}

type layerExtractJob struct {
	index    int
	layer    v1.Layer
	resultCh chan<- layerExtractResult
}

type layerExtractResult struct {
	index int
	rec   *LayerRecord
	err   error
}

func (m *Manager) extractLayersWithWorkers(ctx context.Context, layers []v1.Layer) ([]string, []string, error) {
	if len(layers) == 0 {
		return nil, nil, nil
	}
	m.ensureLayerWorkerPool()
	batchStart := time.Now()
	logrus.Infof("OCI layer extraction start: layers=%d workers=%d", len(layers), m.layerWorkers)

	results := make(chan layerExtractResult, len(layers))
	submitted := 0
	var submitErr error
submitLoop:
	for i, layer := range layers {
		select {
		case <-ctx.Done():
			submitErr = fmt.Errorf("layer extraction canceled: %w", ctx.Err())
			logrus.Warnf("OCI layer extraction canceled before submit: submitted=%d/%d cost=%s err=%v", submitted, len(layers), time.Since(batchStart), submitErr)
			break submitLoop
		case <-m.stopCh:
			err := fmt.Errorf("oci manager is closing")
			logrus.Warnf("OCI layer extraction interrupted before submit: submitted=%d/%d cost=%s err=%v", submitted, len(layers), time.Since(batchStart), err)
			return nil, nil, err
		case m.layerJobs <- layerExtractJob{
			index:    i,
			layer:    layer,
			resultCh: results,
		}:
			submitted++
		}
	}

	layerDigests := make([]string, len(layers))
	layerPaths := make([]string, len(layers))
	firstErr := submitErr
	success := 0
	for i := 0; i < submitted; i++ {
		var res layerExtractResult
		select {
		case <-m.stopCh:
			err := fmt.Errorf("oci manager is closing")
			logrus.Warnf("OCI layer extraction interrupted while waiting results: received=%d/%d cost=%s err=%v", i, submitted, time.Since(batchStart), err)
			return nil, nil, err
		case res = <-results:
		}
		if ctx.Err() != nil && firstErr == nil {
			firstErr = fmt.Errorf("layer extraction canceled: %w", ctx.Err())
		}
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		layerDigests[res.index] = res.rec.Digest
		layerPaths[res.index] = res.rec.Path
		success++
	}
	if firstErr != nil {
		m.rollbackReservedLayerRefs(layerDigests)
		logrus.Warnf("OCI layer extraction failed: submitted=%d success=%d cost=%s err=%v", submitted, success, time.Since(batchStart), firstErr)
		return nil, nil, firstErr
	}
	logrus.Infof("OCI layer extraction finished: submitted=%d success=%d cost=%s", submitted, success, time.Since(batchStart))
	return layerDigests, layerPaths, nil
}

func (m *Manager) ensureLayerWorkerPool() {
	m.layerPoolMu.Lock()
	defer m.layerPoolMu.Unlock()

	m.layerPoolOnce.Do(func() {
		workers := m.layerWorkers
		if workers <= 0 {
			workers = 1
		}
		m.layerWorkers = workers

		queueSize := workers * 4
		if queueSize < workers {
			queueSize = workers
		}
		m.layerJobs = make(chan layerExtractJob, queueSize)

		for i := 0; i < workers; i++ {
			m.layerPoolWG.Add(1)
			go func() {
				defer m.layerPoolWG.Done()
				for {
					select {
					case <-m.stopCh:
						return
					case job := <-m.layerJobs:
						rec, err := m.ensureLayerExtracted(job.layer)
						job.resultCh <- layerExtractResult{
							index: job.index,
							rec:   rec,
							err:   err,
						}
					}
				}
			}()
		}
	})
}

func (m *Manager) UnmountImage(imageURL string) error {
	return m.UnmountImageWithContext(context.Background(), imageURL)
}

// ListMountedImageURLs returns all currently mounted OCI image URLs.
func (m *Manager) ListMountedImageURLs() ([]string, error) {
	details, err := m.ListMountedDetails()
	if err != nil {
		return nil, err
	}
	imageURLs := make([]string, 0, len(details))
	for _, rec := range details {
		imageURLs = append(imageURLs, rec.ImageURL)
	}
	return imageURLs, nil
}

// ListMountedDetails returns detailed metadata of all currently mounted OCI images.
func (m *Manager) ListMountedDetails() ([]OciMountRecord, error) {
	records, err := m.store.listMounts()
	if err != nil {
		return nil, fmt.Errorf("failed to list oci mounts: %w", err)
	}
	details := make([]OciMountRecord, 0, len(records))
	for _, rec := range records {
		if rec == nil || rec.ImageURL == "" {
			continue
		}
		details = append(details, OciMountRecord{
			ImageURL:      rec.ImageURL,
			MountID:       rec.MountID,
			MountPath:     rec.MountPath,
			LayerDigests:  append([]string(nil), rec.LayerDigests...),
			ChainIDs:      append([]string(nil), rec.ChainIDs...),
			LowerDirs:     append([]string(nil), rec.LowerDirs...),
			CreatedAtUnix: rec.CreatedAtUnix,
		})
	}
	sort.Slice(details, func(i, j int) bool {
		return details[i].ImageURL < details[j].ImageURL
	})
	return details, nil
}

// UnmountImageWithContext unmounts an OCI overlay mount and updates layer references.
func (m *Manager) UnmountImageWithContext(ctx context.Context, imageURL string) (retErr error) {
	timing, _ := StartOCITimedOperation(ctx, "oci.UnmountImage", imageURL)
	defer timing.End()
	opStart := time.Now()
	logrus.Infof("OCI unmount start: image=%s", imageURL)
	defer func() {
		if retErr != nil {
			logrus.Warnf("OCI unmount failed: image=%s cost=%s err=%v", imageURL, time.Since(opStart), retErr)
		}
	}()

	stageStart := time.Now()
	if imageURL == "" {
		err := fmt.Errorf("imageURL is required")
		timing.RecordError(err)
		return err
	}
	timing.Stage("validate_request", time.Since(stageStart))

	unlockImage := m.acquireImageLock(imageURL)
	defer unlockImage()

	stageStart = time.Now()
	info := m.getContainer(imageURL)
	if info == nil {
		rec, err := m.store.getMount(imageURL)
		if err != nil {
			err = fmt.Errorf("failed to query mount metadata for %s: %w", imageURL, err)
			timing.RecordError(err)
			return err
		}
		if rec == nil {
			err = fmt.Errorf("image %s is not mounted", imageURL)
			timing.RecordError(err)
			return err
		}
		info = &ContainerInfo{
			MountID:      rec.MountID,
			ImageURL:     rec.ImageURL,
			MountPath:    rec.MountPath,
			LayerDigests: append([]string(nil), rec.LayerDigests...),
			ChainIDs:     append([]string(nil), rec.ChainIDs...),
			LowerDirs:    append([]string(nil), rec.LowerDirs...),
		}
	}
	timing.Stage("lookup_mount", time.Since(stageStart))

	stageStart = time.Now()
	if err := m.unmountFn(info.MountPath); err != nil && !isNotMountedError(err) {
		err = fmt.Errorf("failed to unmount overlay at %s: %w", info.MountPath, err)
		timing.RecordError(err)
		return err
	}
	timing.Stage("overlay_unmount", time.Since(stageStart))

	stageStart = time.Now()
	if err := m.store.deleteMount(imageURL); err != nil {
		err = fmt.Errorf("failed to delete mount metadata for %s: %w", imageURL, err)
		timing.RecordError(err)
		return err
	}
	timing.Stage("delete_mount_record", time.Since(stageStart))

	stageStart = time.Now()
	for _, digest := range info.LayerDigests {
		if _, err := m.store.decrementLayerRef(digest, m.now().Unix()); err != nil && !errors.Is(err, ErrLayerNotFound) {
			logrus.Warnf("failed to update layer refcount for %s: %v", digest, err)
		}
	}
	timing.Stage("decrement_layer_refs", time.Since(stageStart))

	stageStart = time.Now()
	for _, chainID := range info.ChainIDs {
		if _, err := m.store.decrementChainRef(chainID, m.now().Unix()); err != nil && !errors.Is(err, ErrChainNotFound) {
			logrus.Warnf("failed to update chain refcount for %s: %v", chainID, err)
		}
	}
	timing.Stage("decrement_chain_refs", time.Since(stageStart))

	m.deleteContainer(imageURL)
	_ = os.RemoveAll(filepath.Dir(info.MountPath))
	logrus.Infof("OCI unmount success: image=%s mount_path=%s layers=%d cost=%s", imageURL, info.MountPath, len(info.LayerDigests), time.Since(opStart))

	return nil
}

// Close stops background workers and releases resources.
func (m *Manager) Close() error {
	m.layerPoolMu.Lock()
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
	m.layerPoolWG.Wait()
	m.layerPoolMu.Unlock()

	m.mutex.Lock()
	images := make([]string, 0, len(m.containers))
	for imageURL := range m.containers {
		images = append(images, imageURL)
	}
	m.mutex.Unlock()

	for _, imageURL := range images {
		if err := m.UnmountImage(imageURL); err != nil {
			logrus.Warnf("failed to unmount image %s during shutdown: %v", imageURL, err)
		}
	}

	return m.store.close()
}

func (m *Manager) fetchImage(ctx context.Context, imageURL string) (v1.Image, error) {
	img, err := m.registry.FetchImageWithFallback(ctx, imageURL, m.proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCI image %s: %w", imageURL, err)
	}
	return img, nil
}

func (m *Manager) ensureLayerExtracted(layer v1.Layer) (*LayerRecord, error) {
	start := time.Now()
	digest, err := layer.Digest()
	if err != nil {
		return nil, fmt.Errorf("failed to get layer digest: %w", err)
	}
	digestStr := digest.String()
	unlockLayer := m.acquireLayerLock(digestStr)
	defer unlockLayer()

	rec, err := m.store.getLayer(digestStr)
	if err != nil {
		return nil, fmt.Errorf("failed to read layer metadata %s: %w", digestStr, err)
	}
	layerDir, err := m.store.getOrCreateLayerDir(digestStr)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate layer dir for %s: %w", digestStr, err)
	}
	layerRoot := filepath.Join(m.layersDir, layerDir)
	layerPath := filepath.Join(layerRoot, "fs")

	if rec != nil && rec.Path != "" && pathExists(rec.Path) {
		rec, err = m.store.incrementLayerRef(digestStr, m.now().Unix())
		if err != nil {
			return nil, fmt.Errorf("failed to reserve layer metadata %s: %w", digestStr, err)
		}
		logrus.Infof("OCI layer cache hit: digest=%s path=%s ref_count=%d cost=%s", digestStr, rec.Path, rec.RefCount, time.Since(start))
		return rec, nil
	}

	// Recovery for crash window: extracted layer exists but metadata was not persisted.
	if pathExists(layerPath) {
		size, err := dirSizeBytes(layerPath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat recovered layer path %s: %w", layerPath, err)
		}
		recoveredRefCount := 1
		if rec != nil {
			recoveredRefCount = rec.RefCount + 1
		}
		rec = &LayerRecord{
			Digest:        digestStr,
			Path:          layerPath,
			SizeBytes:     size,
			RefCount:      recoveredRefCount,
			RefZeroAtUnix: 0,
			LastUsedUnix:  m.now().Unix(),
		}
		if err := m.store.putLayer(rec); err != nil {
			return nil, fmt.Errorf("failed to recover layer metadata %s: %w", digestStr, err)
		}
		logrus.Infof("OCI layer cache recovered: digest=%s path=%s size_bytes=%d cost=%s", digestStr, layerPath, size, time.Since(start))
		return rec, nil
	}
	logrus.Infof("OCI layer cache miss: digest=%s action=download_extract", digestStr)

	tmpDir := filepath.Join(layerRoot, fmt.Sprintf("tmp-%d", m.now().UnixNano()))
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp layer dir %s: %w", tmpDir, err)
	}
	defer os.RemoveAll(tmpDir)

	rc, err := layer.Uncompressed()
	if err != nil {
		logrus.Warnf("OCI layer download failed: digest=%s cost=%s err=%v", digestStr, time.Since(start), err)
		return nil, fmt.Errorf("failed to open uncompressed layer %s: %w", digestStr, err)
	}
	defer rc.Close()

	size, err := extractLayerTar(rc, tmpDir)
	if err != nil {
		logrus.Warnf("OCI layer extract failed: digest=%s tmp_dir=%s cost=%s err=%v", digestStr, tmpDir, time.Since(start), err)
		return nil, fmt.Errorf("failed to extract layer %s: %w", digestStr, err)
	}

	if err := os.MkdirAll(layerRoot, 0755); err != nil {
		return nil, fmt.Errorf("failed to create layer root %s: %w", layerRoot, err)
	}
	if err := os.RemoveAll(layerPath); err != nil {
		return nil, fmt.Errorf("failed to cleanup old layer path %s: %w", layerPath, err)
	}
	if err := os.Rename(tmpDir, layerPath); err != nil {
		return nil, fmt.Errorf("failed to place extracted layer %s: %w", digestStr, err)
	}

	rec = &LayerRecord{
		Digest:        digestStr,
		Path:          layerPath,
		SizeBytes:     size,
		RefCount:      1,
		RefZeroAtUnix: 0,
		LastUsedUnix:  m.now().Unix(),
	}
	if err := m.store.putLayer(rec); err != nil {
		return nil, fmt.Errorf("failed to persist layer metadata %s: %w", digestStr, err)
	}
	logrus.Infof("OCI layer download/extract success: digest=%s path=%s size_bytes=%d cost=%s", digestStr, layerPath, size, time.Since(start))
	return rec, nil
}

func resolveImageLayerDiffIDs(img v1.Image, layers []v1.Layer) ([]v1.Hash, error) {
	cfg, err := img.ConfigFile()
	if err == nil {
		if len(cfg.RootFS.DiffIDs) != len(layers) {
			return nil, fmt.Errorf("image config diff_ids length %d does not match layer count %d", len(cfg.RootFS.DiffIDs), len(layers))
		}
		diffIDs := make([]v1.Hash, len(cfg.RootFS.DiffIDs))
		copy(diffIDs, cfg.RootFS.DiffIDs)
		return diffIDs, nil
	}

	diffIDs := make([]v1.Hash, len(layers))
	for i, layer := range layers {
		diffID, diffErr := layer.DiffID()
		if diffErr != nil {
			return nil, fmt.Errorf("failed to resolve diffID for layer %d: %w", i, diffErr)
		}
		diffIDs[i] = diffID
	}
	return diffIDs, nil
}

func buildChainIDs(diffIDs []v1.Hash) ([]string, error) {
	if len(diffIDs) == 0 {
		return nil, fmt.Errorf("diffIDs is empty")
	}

	chainIDs := make([]string, len(diffIDs))
	parent := ""
	for i, diffID := range diffIDs {
		if diffID.String() == "" {
			return nil, fmt.Errorf("diffID at index %d is empty", i)
		}
		if parent == "" {
			parent = diffID.String()
		} else {
			sum := sha256.Sum256([]byte(parent + " " + diffID.String()))
			parent = "sha256:" + hex.EncodeToString(sum[:])
		}
		chainIDs[i] = parent
	}
	return chainIDs, nil
}

func (m *Manager) ensureChainLowerDirs(chainIDs []string, layerPaths []string) ([]string, error) {
	if len(chainIDs) != len(layerPaths) {
		return nil, fmt.Errorf("chain count mismatch: chainIDs=%d paths=%d", len(chainIDs), len(layerPaths))
	}

	paths := make([]string, len(chainIDs))
	reservedChainIDs := make([]string, 0, len(chainIDs))
	for i, chainID := range chainIDs {
		if chainID == "" {
			m.rollbackReservedChainRefs(reservedChainIDs)
			return nil, fmt.Errorf("chainID at index %d is empty", i)
		}
		if layerPaths[i] == "" {
			m.rollbackReservedChainRefs(reservedChainIDs)
			return nil, fmt.Errorf("layer path at index %d is empty", i)
		}
		path, err := m.getOrCreateChainLowerDir(chainID, layerPaths[i])
		if err != nil {
			m.rollbackReservedChainRefs(reservedChainIDs)
			return nil, err
		}
		paths[i] = path
		reservedChainIDs = append(reservedChainIDs, chainID)
	}
	return paths, nil
}

func (m *Manager) getOrCreateChainLowerDir(chainID string, layerPath string) (string, error) {
	unlock := m.acquireChainLock(chainID)
	defer unlock()

	record, err := m.store.getChain(chainID)
	if err != nil {
		return "", fmt.Errorf("failed to query chain metadata %s: %w", chainID, err)
	}
	if record != nil && record.Path != "" && pathExists(record.Path) {
		record, err = m.store.incrementChainRef(chainID, m.now().Unix())
		if err != nil {
			return "", fmt.Errorf("failed to reserve chain metadata %s: %w", chainID, err)
		}
		return record.Path, nil
	}

	chainDir, err := m.store.getOrCreateChainDir(chainID)
	if err != nil {
		return "", fmt.Errorf("failed to allocate lowerdir for chain %s: %w", chainID, err)
	}
	targetPath := filepath.Join(m.chainsDir, chainDir, "fs")
	if pathExists(targetPath) {
		recoveredRefCount := 1
		if record == nil {
			record = &ChainRecord{ChainID: chainID}
		} else {
			recoveredRefCount = record.RefCount + 1
		}
		record.Path = targetPath
		record.RefCount = recoveredRefCount
		record.RefZeroAtUnix = 0
		record.LastUsedUnix = m.now().Unix()
		if err := m.store.putChain(record); err != nil {
			return "", fmt.Errorf("failed to persist recovered chain metadata %s: %w", chainID, err)
		}
		return targetPath, nil
	}

	if err := m.materializeChainLowerDir(layerPath, targetPath); err != nil {
		return "", fmt.Errorf("failed to build lowerdir for chain %s from %s: %w", chainID, layerPath, err)
	}

	if record == nil {
		record = &ChainRecord{
			ChainID:       chainID,
			Path:          targetPath,
			RefCount:      1,
			RefZeroAtUnix: 0,
			LastUsedUnix:  m.now().Unix(),
		}
	} else {
		record.Path = targetPath
		record.RefCount++
		record.LastUsedUnix = m.now().Unix()
		record.RefZeroAtUnix = 0
	}
	if err := m.store.putChain(record); err != nil {
		return "", fmt.Errorf("failed to persist chain metadata %s: %w", chainID, err)
	}
	return targetPath, nil
}

func (m *Manager) materializeChainLowerDir(sourcePath string, targetPath string) error {
	parentDir := filepath.Dir(targetPath)
	tmpDir := filepath.Join(parentDir, fmt.Sprintf("tmp-%d", m.now().UnixNano()))

	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create chain lowerdir parent %s: %w", parentDir, err)
	}
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("failed to cleanup chain lowerdir temp dir %s: %w", tmpDir, err)
	}
	if err := buildHardlinkTree(sourcePath, tmpDir); err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := os.RemoveAll(targetPath); err != nil {
		return fmt.Errorf("failed to cleanup chain lowerdir target %s: %w", targetPath, err)
	}
	if err := os.Rename(tmpDir, targetPath); err != nil {
		return fmt.Errorf("failed to place chain lowerdir at %s: %w", targetPath, err)
	}
	return nil
}

func buildHardlinkTree(sourceRoot string, targetRoot string) error {
	info, err := os.Lstat(sourceRoot)
	if err != nil {
		return fmt.Errorf("failed to stat source lowerdir %s: %w", sourceRoot, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source lowerdir %s is not a directory", sourceRoot)
	}
	if err := os.MkdirAll(targetRoot, info.Mode().Perm()); err != nil {
		return fmt.Errorf("failed to create target lowerdir root %s: %w", targetRoot, err)
	}

	entries, err := os.ReadDir(sourceRoot)
	if err != nil {
		return fmt.Errorf("failed to read source lowerdir %s: %w", sourceRoot, err)
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(sourceRoot, entry.Name())
		targetPath := filepath.Join(targetRoot, entry.Name())

		entryInfo, err := os.Lstat(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to stat source entry %s: %w", sourcePath, err)
		}

		switch {
		case entryInfo.IsDir():
			if err := buildHardlinkTree(sourcePath, targetPath); err != nil {
				return err
			}
			if err := copyDirectoryMetadata(sourcePath, targetPath, entryInfo); err != nil {
				return err
			}
		case entryInfo.Mode()&os.ModeSymlink != 0:
			linkTarget, err := os.Readlink(sourcePath)
			if err != nil {
				return fmt.Errorf("failed to read symlink %s: %w", sourcePath, err)
			}
			if err := os.Symlink(linkTarget, targetPath); err != nil {
				return fmt.Errorf("failed to create symlink %s -> %s: %w", targetPath, linkTarget, err)
			}
		default:
			if err := os.Link(sourcePath, targetPath); err != nil {
				return fmt.Errorf("failed to hardlink %s -> %s: %w", sourcePath, targetPath, err)
			}
		}
	}

	return copyDirectoryMetadata(sourceRoot, targetRoot, info)
}

func copyDirectoryMetadata(sourcePath string, targetPath string, info os.FileInfo) error {
	if err := os.Chmod(targetPath, info.Mode().Perm()); err != nil {
		return fmt.Errorf("failed to copy mode for %s: %w", targetPath, err)
	}
	if err := copyOwnership(targetPath, info); err != nil {
		return err
	}
	if err := copyTimes(targetPath, info); err != nil {
		return err
	}
	if err := copyXattrs(sourcePath, targetPath); err != nil {
		return err
	}
	return nil
}

func copyOwnership(targetPath string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := os.Lchown(targetPath, int(stat.Uid), int(stat.Gid)); err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			var errno syscall.Errno
			if errors.As(pathErr.Err, &errno) && (errno == syscall.EPERM || errno == syscall.EINVAL) {
				return nil
			}
		}
		return fmt.Errorf("failed to copy ownership for %s: %w", targetPath, err)
	}
	return nil
}

func copyTimes(targetPath string, info os.FileInfo) error {
	mtime := info.ModTime()
	if err := os.Chtimes(targetPath, mtime, mtime); err != nil {
		return fmt.Errorf("failed to copy times for %s: %w", targetPath, err)
	}
	return nil
}

func copyXattrs(sourcePath string, targetPath string) error {
	names, err := listXattrs(sourcePath)
	if err != nil {
		if isIgnorableXattrErr(err) {
			return nil
		}
		return fmt.Errorf("failed to list xattrs for %s: %w", sourcePath, err)
	}
	for _, name := range names {
		value, err := getXattr(sourcePath, name)
		if err != nil {
			if isIgnorableXattrErr(err) {
				continue
			}
			return fmt.Errorf("failed to read xattr %s on %s: %w", name, sourcePath, err)
		}
		if err := unix.Setxattr(targetPath, name, value, 0); err != nil && !isIgnorableXattrErr(err) {
			return fmt.Errorf("failed to copy xattr %s to %s: %w", name, targetPath, err)
		}
	}
	return nil
}

func listXattrs(path string) ([]string, error) {
	size, err := unix.Listxattr(path, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	size, err = unix.Listxattr(path, buf)
	if err != nil {
		return nil, err
	}
	return splitNullTerminated(buf[:size]), nil
}

func getXattr(path string, name string) ([]byte, error) {
	size, err := unix.Getxattr(path, name, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, size)
	readSize, err := unix.Getxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:readSize], nil
}

func splitNullTerminated(buf []byte) []string {
	if len(buf) == 0 {
		return nil
	}
	names := make([]string, 0, 4)
	start := 0
	for i, b := range buf {
		if b != 0 {
			continue
		}
		if i > start {
			names = append(names, string(buf[start:i]))
		}
		start = i + 1
	}
	if start < len(buf) {
		names = append(names, string(buf[start:]))
	}
	return names
}

func isIgnorableXattrErr(err error) bool {
	return errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.ENODATA)
}

func extractLayerTar(r io.Reader, dst string) (int64, error) {
	tr := tar.NewReader(r)
	var totalSize int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("failed to read tar stream: %w", err)
		}

		relPath, err := cleanArchivePath(hdr.Name)
		if err != nil {
			return 0, err
		}
		if relPath == "" {
			continue
		}

		if isWhiteout(relPath) {
			if err := applyOCIWhiteout(dst, relPath); err != nil {
				return 0, err
			}
			continue
		}

		target := filepath.Join(dst, relPath)
		if err := ensureParent(target); err != nil {
			return 0, err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return 0, fmt.Errorf("failed to create dir %s: %w", target, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.RemoveAll(target); err != nil {
				return 0, fmt.Errorf("failed to replace file %s: %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return 0, fmt.Errorf("failed to create file %s: %w", target, err)
			}
			n, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			totalSize += n
			if copyErr != nil {
				return 0, fmt.Errorf("failed to write file %s: %w", target, copyErr)
			}
			if closeErr != nil {
				return 0, fmt.Errorf("failed to close file %s: %w", target, closeErr)
			}
		case tar.TypeSymlink:
			if err := os.RemoveAll(target); err != nil {
				return 0, fmt.Errorf("failed to replace symlink %s: %w", target, err)
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return 0, fmt.Errorf("failed to create symlink %s -> %s: %w", target, hdr.Linkname, err)
			}
		case tar.TypeLink:
			linkTarget, err := cleanArchivePath(hdr.Linkname)
			if err != nil {
				return 0, fmt.Errorf("invalid hardlink target %s: %w", hdr.Linkname, err)
			}
			if linkTarget == "" {
				return 0, fmt.Errorf("invalid hardlink target %s", hdr.Linkname)
			}
			absLinkTarget := filepath.Join(dst, linkTarget)
			if err := os.RemoveAll(target); err != nil {
				return 0, fmt.Errorf("failed to replace hardlink %s: %w", target, err)
			}
			if err := os.Link(absLinkTarget, target); err != nil {
				return 0, fmt.Errorf("failed to create hardlink %s -> %s: %w", target, absLinkTarget, err)
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			if err := os.RemoveAll(target); err != nil {
				return 0, fmt.Errorf("failed to replace special file %s: %w", target, err)
			}
			if err := createSpecialNode(target, hdr); err != nil {
				return 0, err
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		default:
			return 0, fmt.Errorf("unsupported tar entry type %d for %s", hdr.Typeflag, hdr.Name)
		}

		if err := applyMetadata(target, hdr); err != nil {
			return 0, err
		}
	}

	return totalSize, nil
}

func createSpecialNode(target string, hdr *tar.Header) error {
	mode := uint32(hdr.Mode)
	switch hdr.Typeflag {
	case tar.TypeChar:
		mode |= syscall.S_IFCHR
	case tar.TypeBlock:
		mode |= syscall.S_IFBLK
	case tar.TypeFifo:
		mode |= syscall.S_IFIFO
	default:
		return nil
	}

	if err := syscall.Mknod(target, mode, 0); err != nil {
		// Non-root fallback: keep an empty regular file so extraction continues.
		f, createErr := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(hdr.Mode))
		if createErr != nil {
			return fmt.Errorf("failed to create special node %s: %w", target, err)
		}
		_ = f.Close()
	}

	return nil
}

func applyMetadata(target string, hdr *tar.Header) error {
	if hdr.Typeflag != tar.TypeSymlink {
		if err := os.Chmod(target, os.FileMode(hdr.Mode)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to set mode for %s: %w", target, err)
		}
		if err := os.Chtimes(target, hdr.AccessTime, hdr.ModTime); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to set mtime for %s: %w", target, err)
		}
	}
	if err := os.Lchown(target, hdr.Uid, hdr.Gid); err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			var errno syscall.Errno
			if errors.As(pathErr.Err, &errno) && (errno == syscall.EPERM || errno == syscall.EINVAL) {
				return nil
			}
		}
	}
	return nil
}

func isWhiteout(relPath string) bool {
	base := filepath.Base(relPath)
	return strings.HasPrefix(base, ".wh.")
}

func applyOCIWhiteout(layerRoot string, relPath string) error {
	dir := filepath.Dir(relPath)
	if dir == "." {
		dir = ""
	}
	base := filepath.Base(relPath)
	parent := filepath.Join(layerRoot, dir)

	if err := os.MkdirAll(parent, 0755); err != nil {
		return fmt.Errorf("failed to ensure whiteout parent dir %s: %w", parent, err)
	}

	if base == ".wh..wh..opq" {
		if err := setOverlayXattr(parent, "opaque", []byte("y")); err != nil {
			logrus.Warnf("failed to set opaque xattr on %s: %v", parent, err)
		}
		return nil
	}

	whiteoutTarget := filepath.Join(parent, strings.TrimPrefix(base, ".wh."))
	if err := os.RemoveAll(whiteoutTarget); err != nil {
		return fmt.Errorf("failed to cleanup whiteout target %s: %w", whiteoutTarget, err)
	}

	if err := syscall.Mknod(whiteoutTarget, syscall.S_IFCHR|0600, 0); err == nil {
		return nil
	}

	// Non-root fallback: regular file plus overlay whiteout xattr when possible.
	f, err := os.OpenFile(whiteoutTarget, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create whiteout file %s: %w", whiteoutTarget, err)
	}
	_ = f.Close()
	if err := setOverlayXattr(whiteoutTarget, "whiteout", []byte("y")); err != nil {
		logrus.Warnf("failed to set whiteout xattr on %s: %v", whiteoutTarget, err)
	}

	return nil
}

func setOverlayXattr(target, key string, value []byte) error {
	trustedKey := fmt.Sprintf("trusted.overlay.%s", key)
	if err := unix.Setxattr(target, trustedKey, value, 0); err == nil {
		return nil
	}
	userKey := fmt.Sprintf("user.overlay.%s", key)
	if err := unix.Setxattr(target, userKey, value, 0); err == nil {
		return nil
	}
	return fmt.Errorf("unable to set overlay xattr %q", key)
}

func cleanArchivePath(raw string) (string, error) {
	cleaned := path.Clean("/" + raw)
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "", nil
	}
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", fmt.Errorf("invalid archive path %q", raw)
	}
	return cleaned, nil
}

func ensureParent(target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("failed to create parent dir for %s: %w", target, err)
	}
	return nil
}

func generateContainerID(imageURL string) string {
	cs := sha256.Sum256([]byte(imageURL))
	hash := hex.EncodeToString(cs[:])[:16]
	cleanName := strings.ReplaceAll(imageURL, "/", "-")
	cleanName = strings.ReplaceAll(cleanName, ":", "-")
	if len(cleanName) > 50 {
		cleanName = cleanName[:50]
	}
	return fmt.Sprintf("%s%s-%s", containerNamePrefix, cleanName, hash)
}

func reverseCopy(items []string) []string {
	out := make([]string, len(items))
	copy(out, items)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func defaultOverlayMount(target string, lowerDirs []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("overlay mount is only supported on linux")
	}
	if len(lowerDirs) == 1 {
		source := lowerDirs[0]
		logrus.Infof(
			"OCI mount params: type=bind target=%s source=%s readonly=true",
			target,
			source,
		)
		if err := mountReadonlyBind(source, target); err != nil {
			return fmt.Errorf("readonly bind mount failed: source=%s target=%s: %w", source, target, err)
		}
		return nil
	}

	mountData, err := buildOverlayMountData(lowerDirs)
	if err != nil {
		return err
	}
	logrus.Infof(
		"OCI overlay mount params: target=%s lowerdir_count=%d opts=%s",
		target,
		len(lowerDirs),
		mountData,
	)
	if err := mountReadonlyOverlay(target, mountData); err != nil {
		return fmt.Errorf("overlay mount failed: target=%s opts=%s: %w", target, mountData, err)
	}
	return nil
}

func buildOverlayMountData(lowerDirs []string) (string, error) {
	if len(lowerDirs) == 0 {
		return "", fmt.Errorf("lowerDirs is empty")
	}
	return "lowerdir=" + strings.Join(lowerDirs, ":"), nil
}

func defaultOverlayUnmount(target string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("overlay unmount is only supported on linux")
	}
	if err := unmountOverlay(target); err != nil {
		return fmt.Errorf("overlay unmount failed: target=%s: %w", target, err)
	}
	return nil
}

func readManagedMounts(mountsDir string) (map[string]struct{}, bool, error) {
	if runtime.GOOS != "linux" {
		return map[string]struct{}{}, false, nil
	}

	mountsRoot := filepath.Clean(mountsDir) + string(os.PathSeparator)
	mountsInfo, err := mountinfo.GetMounts(func(info *mountinfo.Info) (skip, stop bool) {
		cleanMP := filepath.Clean(info.Mountpoint)
		return !strings.HasPrefix(cleanMP, mountsRoot), false
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]struct{}{}, false, nil
		}
		return nil, true, err
	}

	mounts := make(map[string]struct{}, len(mountsInfo))
	for _, info := range mountsInfo {
		mounts[info.Mountpoint] = struct{}{}
	}
	return mounts, true, nil
}

func defaultDiskUsage(p string) (float64, error) {
	return diskusage.UsedRatioByAvailable(p)
}

func (m *Manager) reconcileState() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.containers = make(map[string]*ContainerInfo)

	m.cleanupStaleLayerTempDirs()
	m.cleanupStaleChainTempDirs()

	layers, err := m.store.listLayers()
	if err != nil {
		return fmt.Errorf("failed to list layers: %w", err)
	}
	layerMap := make(map[string]*LayerRecord, len(layers))
	for _, layer := range layers {
		if layer.Path == "" || !pathExists(layer.Path) {
			if err := m.store.deleteLayer(layer.Digest); err != nil {
				return fmt.Errorf("failed to delete stale layer %s: %w", layer.Digest, err)
			}
			continue
		}
		layerMap[layer.Digest] = layer
	}
	chains, err := m.store.listChains()
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}
	chainMap := make(map[string]*ChainRecord, len(chains))
	validChainPaths := make(map[string]struct{}, len(chains))
	for _, chain := range chains {
		if chain.Path == "" || !pathExists(chain.Path) {
			if err := m.store.deleteChain(chain.ChainID); err != nil {
				return fmt.Errorf("failed to delete stale chain %s: %w", chain.ChainID, err)
			}
			continue
		}
		chainMap[chain.ChainID] = chain
		validChainPaths[filepath.Clean(chain.Path)] = struct{}{}
	}
	m.cleanupOrphanChainDirs(validChainPaths)

	managedMounts, shouldCheckMounts, err := m.readMnts()
	if err != nil {
		return fmt.Errorf("failed to read /proc/mounts: %w", err)
	}

	if err := m.recoverMountTransactions(managedMounts, shouldCheckMounts); err != nil {
		return err
	}

	mounts, err := m.store.listMounts()
	if err != nil {
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	refCounts := make(map[string]int)
	chainRefCounts := make(map[string]int)
	validMountPoints := make(map[string]struct{}, len(mounts))
	for _, mount := range mounts {
		if mount.ImageURL == "" || mount.MountPath == "" || len(mount.LayerDigests) == 0 {
			_ = m.store.deleteMount(mount.ImageURL)
			continue
		}
		if shouldCheckMounts {
			if _, ok := managedMounts[mount.MountPath]; !ok {
				_ = m.store.deleteMount(mount.ImageURL)
				continue
			}
		}

		valid := true
		for _, digest := range mount.LayerDigests {
			layer, ok := layerMap[digest]
			if !ok || layer.Path == "" || !pathExists(layer.Path) {
				valid = false
				break
			}
		}
		if !valid {
			_ = m.store.deleteMount(mount.ImageURL)
			continue
		}
		if len(mount.ChainIDs) > 0 {
			validChains, err := m.validateChainIDs(mount.ChainIDs)
			if err != nil {
				return fmt.Errorf("failed to validate chain metadata for %s: %w", mount.ImageURL, err)
			}
			if !validChains {
				_ = m.store.deleteMount(mount.ImageURL)
				continue
			}
		}

		for _, digest := range mount.LayerDigests {
			refCounts[digest]++
		}
		for _, chainID := range mount.ChainIDs {
			chainRefCounts[chainID]++
		}
		validMountPoints[filepath.Clean(mount.MountPath)] = struct{}{}
		m.containers[mount.ImageURL] = &ContainerInfo{
			MountID:      mount.MountID,
			ImageURL:     mount.ImageURL,
			MountPath:    mount.MountPath,
			LayerDigests: append([]string(nil), mount.LayerDigests...),
			ChainIDs:     append([]string(nil), mount.ChainIDs...),
			LowerDirs:    append([]string(nil), mount.LowerDirs...),
		}
	}

	if shouldCheckMounts {
		m.cleanupOrphanManagedMounts(managedMounts, validMountPoints)
	}

	for digest, layer := range layerMap {
		want := refCounts[digest]
		if layer.RefCount != want {
			layer.RefCount = want
			layer.LastUsedUnix = m.now().Unix()
			if want == 0 {
				if layer.RefZeroAtUnix == 0 {
					layer.RefZeroAtUnix = m.now().Unix()
				}
			} else {
				layer.RefZeroAtUnix = 0
			}
			if err := m.store.putLayer(layer); err != nil {
				return fmt.Errorf("failed to fix layer refcount for %s: %w", digest, err)
			}
		}
	}
	for chainID, chain := range chainMap {
		want := chainRefCounts[chainID]
		if chain.RefCount != want {
			chain.RefCount = want
			chain.LastUsedUnix = m.now().Unix()
			if want == 0 {
				if chain.RefZeroAtUnix == 0 {
					chain.RefZeroAtUnix = m.now().Unix()
				}
			} else {
				chain.RefZeroAtUnix = 0
			}
			if err := m.store.putChain(chain); err != nil {
				return fmt.Errorf("failed to fix chain refcount for %s: %w", chainID, err)
			}
		}
	}

	return nil
}

func (m *Manager) rollbackMountTransaction(txn *OciMountTxnRecord, incrementedDigests []string, incrementedChains []string) {
	if txn != nil {
		if err := m.unmountFn(txn.MountPath); err != nil && !isNotMountedError(err) {
			logrus.Warnf("failed to rollback mount %s: %v", txn.MountPath, err)
		}
	}

	m.rollbackReservedLayerRefs(incrementedDigests)
	m.rollbackReservedChainRefs(incrementedChains)

	if txn != nil {
		if err := m.store.deleteMountTxn(txn.ImageURL); err != nil {
			logrus.Warnf("failed to delete rollback mount transaction for %s: %v", txn.ImageURL, err)
		}
		_ = os.RemoveAll(filepath.Dir(txn.MountPath))
	}
}

func (m *Manager) rollbackReservedLayerRefs(digests []string) {
	for _, digest := range digests {
		if digest == "" {
			continue
		}
		if _, err := m.store.decrementLayerRef(digest, m.now().Unix()); err != nil && !errors.Is(err, ErrLayerNotFound) {
			logrus.Warnf("failed to rollback refcount for layer %s: %v", digest, err)
		}
	}
}

func (m *Manager) rollbackReservedChainRefs(chainIDs []string) {
	for _, chainID := range chainIDs {
		if chainID == "" {
			continue
		}
		if _, err := m.store.decrementChainRef(chainID, m.now().Unix()); err != nil && !errors.Is(err, ErrChainNotFound) {
			logrus.Warnf("failed to rollback refcount for chain %s: %v", chainID, err)
		}
	}
}

func (m *Manager) recoverMountTransactions(managedMounts map[string]struct{}, shouldCheckMounts bool) error {
	txns, err := m.store.listMountTxns()
	if err != nil {
		return fmt.Errorf("failed to list mount transactions: %w", err)
	}

	for _, txn := range txns {
		if txn.ImageURL == "" || txn.MountPath == "" || len(txn.LayerDigests) == 0 {
			_ = m.store.deleteMountTxn(txn.ImageURL)
			continue
		}

		if rec, err := m.store.getMount(txn.ImageURL); err == nil && rec != nil {
			_ = m.store.deleteMountTxn(txn.ImageURL)
			continue
		}

		if shouldCheckMounts {
			if _, ok := managedMounts[txn.MountPath]; ok {
				validLayers, err := m.validateLayerDigests(txn.LayerDigests)
				if err != nil {
					return fmt.Errorf("failed to validate mount transaction layers for %s: %w", txn.ImageURL, err)
				}
				if !validLayers {
					logrus.Warnf("drop mount transaction for %s: missing layer metadata/path", txn.ImageURL)
					_ = m.store.deleteMountTxn(txn.ImageURL)
					continue
				}
				if len(txn.ChainIDs) > 0 {
					validChains, err := m.validateChainIDs(txn.ChainIDs)
					if err != nil {
						return fmt.Errorf("failed to validate mount transaction chains for %s: %w", txn.ImageURL, err)
					}
					if !validChains {
						logrus.Warnf("drop mount transaction for %s: missing chain metadata/path", txn.ImageURL)
						_ = m.store.deleteMountTxn(txn.ImageURL)
						continue
					}
				}
				rec := &OciMountRecord{
					ImageURL:      txn.ImageURL,
					MountID:       txn.MountID,
					MountPath:     txn.MountPath,
					LayerDigests:  append([]string(nil), txn.LayerDigests...),
					ChainIDs:      append([]string(nil), txn.ChainIDs...),
					LowerDirs:     append([]string(nil), txn.LowerDirs...),
					CreatedAtUnix: txn.CreatedAtUnix,
				}
				if err := m.store.putMount(rec); err != nil {
					return fmt.Errorf("failed to recover mount metadata for %s: %w", txn.ImageURL, err)
				}
			}
		}

		_ = m.store.deleteMountTxn(txn.ImageURL)
	}

	return nil
}

func (m *Manager) validateLayerDigests(digests []string) (bool, error) {
	for _, digest := range digests {
		layer, err := m.store.getLayer(digest)
		if err != nil {
			return false, err
		}
		if layer == nil || layer.Path == "" || !pathExists(layer.Path) {
			return false, nil
		}
	}
	return true, nil
}

func (m *Manager) validateChainIDs(chainIDs []string) (bool, error) {
	for _, chainID := range chainIDs {
		chain, err := m.store.getChain(chainID)
		if err != nil {
			return false, err
		}
		if chain == nil || chain.Path == "" || !pathExists(chain.Path) {
			return false, nil
		}
	}
	return true, nil
}

func (m *Manager) cleanupOrphanManagedMounts(managedMounts map[string]struct{}, validMountPoints map[string]struct{}) {
	mountsRoot := filepath.Clean(m.mountsDir) + string(os.PathSeparator)
	for mountPoint := range managedMounts {
		cleanMP := filepath.Clean(mountPoint)
		if !strings.HasPrefix(cleanMP, mountsRoot) {
			continue
		}
		if _, ok := validMountPoints[cleanMP]; ok {
			continue
		}
		if err := m.unmountFn(cleanMP); err != nil && !isNotMountedError(err) {
			logrus.Warnf("failed to cleanup orphan managed mount %s: %v", cleanMP, err)
			continue
		}
		_ = os.RemoveAll(filepath.Dir(cleanMP))
	}
}

func (m *Manager) cleanupStaleLayerTempDirs() {
	layerRoots, err := os.ReadDir(m.layersDir)
	if err != nil {
		return
	}
	for _, layerRoot := range layerRoots {
		if !layerRoot.IsDir() {
			continue
		}
		rootPath := filepath.Join(m.layersDir, layerRoot.Name())
		entries, err := os.ReadDir(rootPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "tmp-") {
				continue
			}
			_ = os.RemoveAll(filepath.Join(rootPath, entry.Name()))
		}
	}
}

func (m *Manager) cleanupStaleChainTempDirs() {
	chainRoots, err := os.ReadDir(m.chainsDir)
	if err != nil {
		return
	}
	for _, chainRoot := range chainRoots {
		if !chainRoot.IsDir() {
			continue
		}
		rootPath := filepath.Join(m.chainsDir, chainRoot.Name())
		entries, err := os.ReadDir(rootPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "tmp-") {
				continue
			}
			_ = os.RemoveAll(filepath.Join(rootPath, entry.Name()))
		}
	}
}

func (m *Manager) cleanupOrphanChainDirs(validChainPaths map[string]struct{}) {
	chainRoots, err := os.ReadDir(m.chainsDir)
	if err != nil {
		return
	}
	for _, chainRoot := range chainRoots {
		if !chainRoot.IsDir() {
			continue
		}
		chainPath := filepath.Join(m.chainsDir, chainRoot.Name(), "fs")
		if _, ok := validChainPaths[filepath.Clean(chainPath)]; ok {
			continue
		}
		_ = os.RemoveAll(filepath.Join(m.chainsDir, chainRoot.Name()))
	}
}

func (m *Manager) acquireImageLock(imageURL string) func() {
	m.mutex.Lock()
	entry, exists := m.imageLocks[imageURL]
	if !exists {
		entry = &imageLockEntry{}
		m.imageLocks[imageURL] = entry
	}
	entry.refs++
	m.mutex.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		m.mutex.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(m.imageLocks, imageURL)
		}
		m.mutex.Unlock()
	}
}

func (m *Manager) acquireLayerLock(layerDigest string) func() {
	m.mutex.Lock()
	entry, exists := m.layerLocks[layerDigest]
	if !exists {
		entry = &imageLockEntry{}
		m.layerLocks[layerDigest] = entry
	}
	entry.refs++
	m.mutex.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		m.mutex.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(m.layerLocks, layerDigest)
		}
		m.mutex.Unlock()
	}
}

func (m *Manager) acquireChainLock(chainID string) func() {
	m.mutex.Lock()
	entry, exists := m.chainLocks[chainID]
	if !exists {
		entry = &imageLockEntry{}
		m.chainLocks[chainID] = entry
	}
	entry.refs++
	m.mutex.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		m.mutex.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(m.chainLocks, chainID)
		}
		m.mutex.Unlock()
	}
}

func (m *Manager) getContainer(imageURL string) *ContainerInfo {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	info, exists := m.containers[imageURL]
	if !exists {
		return nil
	}
	return &ContainerInfo{
		MountID:      info.MountID,
		ImageURL:     info.ImageURL,
		MountPath:    info.MountPath,
		LayerDigests: append([]string(nil), info.LayerDigests...),
		ChainIDs:     append([]string(nil), info.ChainIDs...),
		LowerDirs:    append([]string(nil), info.LowerDirs...),
	}
}

func (m *Manager) setContainer(imageURL string, info *ContainerInfo) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.containers[imageURL] = info
}

func (m *Manager) deleteContainer(imageURL string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.containers, imageURL)
}

func (m *Manager) gcLayersByDiskPressure() error {
	m.mutex.Lock()
	root := m.root
	diskUsage := m.diskUsage
	m.mutex.Unlock()

	usage, err := diskUsage(root)
	if err != nil {
		return fmt.Errorf("failed to read disk usage: %w", err)
	}
	if usage < diskUsageGCStart {
		return nil
	}
	startUsage := usage

	candidates, err := m.snapshotUnusedLayerCandidates()
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		logrus.Infof("OCI GC (disk pressure): usage=%.4f >= %.2f but no unreferenced layers", usage, diskUsageGCStart)
		return nil
	}
	logrus.Infof("OCI GC (disk pressure) started: usage=%.4f target<=%.2f candidates=%d", usage, diskUsageGCStop, len(candidates))

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].LastUsedUnix < candidates[j].LastUsedUnix
	})

	removed := 0
	for _, layer := range candidates {
		deleted, err := m.tryDeleteLayerCandidate(layer, time.Time{}, 0, false, "during GC")
		if err != nil {
			return err
		}
		if deleted {
			removed++
		}

		usage, err = diskUsage(root)
		if err != nil {
			return fmt.Errorf("failed to refresh disk usage: %w", err)
		}
		if usage <= diskUsageGCStop {
			break
		}
	}
	logrus.Infof("OCI GC (disk pressure) finished: start_usage=%.4f end_usage=%.4f removed=%d", startUsage, usage, removed)

	return nil
}

func (m *Manager) gcChainsByDiskPressure() error {
	m.mutex.Lock()
	root := m.root
	diskUsage := m.diskUsage
	m.mutex.Unlock()

	usage, err := diskUsage(root)
	if err != nil {
		return fmt.Errorf("failed to read disk usage: %w", err)
	}
	if usage < diskUsageGCStart {
		return nil
	}
	startUsage := usage

	candidates, err := m.snapshotUnusedChainCandidates()
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		logrus.Infof("OCI chain GC (disk pressure): usage=%.4f >= %.2f but no unreferenced lowerdirs", usage, diskUsageGCStart)
		return nil
	}
	logrus.Infof("OCI chain GC (disk pressure) started: usage=%.4f target<=%.2f candidates=%d", usage, diskUsageGCStop, len(candidates))

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].LastUsedUnix < candidates[j].LastUsedUnix
	})

	removed := 0
	for _, chain := range candidates {
		deleted, err := m.tryDeleteChainCandidate(chain, time.Time{}, 0, false, "during GC")
		if err != nil {
			return err
		}
		if deleted {
			removed++
		}

		usage, err = diskUsage(root)
		if err != nil {
			return fmt.Errorf("failed to refresh disk usage: %w", err)
		}
		if usage <= diskUsageGCStop {
			break
		}
	}
	logrus.Infof("OCI chain GC (disk pressure) finished: start_usage=%.4f end_usage=%.4f removed=%d", startUsage, usage, removed)

	return nil
}

func (m *Manager) gcLayersByTTL() error {
	m.mutex.Lock()
	ttl := m.layerTTL
	now := m.now()
	m.mutex.Unlock()

	if ttl <= 0 {
		return nil
	}

	candidates, err := m.snapshotExpiredLayerCandidates(now, ttl)
	if err != nil {
		return err
	}

	removed := 0
	for _, layer := range candidates {
		deleted, err := m.tryDeleteLayerCandidate(layer, now, ttl, true, "during TTL GC")
		if err != nil {
			return err
		}
		if deleted {
			removed++
		}
	}
	if removed > 0 {
		logrus.Infof("OCI GC (ttl) finished: ttl=%s removed=%d", ttl, removed)
	}

	return nil
}

func (m *Manager) gcChainsByTTL() error {
	m.mutex.Lock()
	ttl := m.layerTTL
	now := m.now()
	m.mutex.Unlock()

	if ttl <= 0 {
		return nil
	}

	candidates, err := m.snapshotExpiredChainCandidates(now, ttl)
	if err != nil {
		return err
	}

	removed := 0
	for _, chain := range candidates {
		deleted, err := m.tryDeleteChainCandidate(chain, now, ttl, true, "during TTL GC")
		if err != nil {
			return err
		}
		if deleted {
			removed++
		}
	}
	if removed > 0 {
		logrus.Infof("OCI chain GC (ttl) finished: ttl=%s removed=%d", ttl, removed)
	}

	return nil
}

func (m *Manager) snapshotUnusedLayerCandidates() ([]*LayerRecord, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	layers, err := m.store.listLayers()
	if err != nil {
		return nil, fmt.Errorf("failed to list layers: %w", err)
	}

	candidates := make([]*LayerRecord, 0, len(layers))
	for _, layer := range layers {
		if layer.RefCount == 0 {
			candidates = append(candidates, layer)
		}
	}
	return candidates, nil
}

func (m *Manager) snapshotUnusedChainCandidates() ([]*ChainRecord, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	chains, err := m.store.listChains()
	if err != nil {
		return nil, fmt.Errorf("failed to list chains: %w", err)
	}

	candidates := make([]*ChainRecord, 0, len(chains))
	for _, chain := range chains {
		if chain.RefCount == 0 {
			candidates = append(candidates, chain)
		}
	}
	return candidates, nil
}

func (m *Manager) snapshotExpiredLayerCandidates(now time.Time, ttl time.Duration) ([]*LayerRecord, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	layers, err := m.store.listLayers()
	if err != nil {
		return nil, fmt.Errorf("failed to list layers: %w", err)
	}

	candidates := make([]*LayerRecord, 0, len(layers))
	for _, layer := range layers {
		if layer.RefCount != 0 || layer.RefZeroAtUnix == 0 {
			continue
		}
		if now.Sub(time.Unix(layer.RefZeroAtUnix, 0)) < ttl {
			continue
		}
		candidates = append(candidates, layer)
	}
	return candidates, nil
}

func (m *Manager) snapshotExpiredChainCandidates(now time.Time, ttl time.Duration) ([]*ChainRecord, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	chains, err := m.store.listChains()
	if err != nil {
		return nil, fmt.Errorf("failed to list chains: %w", err)
	}

	candidates := make([]*ChainRecord, 0, len(chains))
	for _, chain := range chains {
		if chain.RefCount != 0 || chain.RefZeroAtUnix == 0 {
			continue
		}
		if now.Sub(time.Unix(chain.RefZeroAtUnix, 0)) < ttl {
			continue
		}
		candidates = append(candidates, chain)
	}
	return candidates, nil
}

func (m *Manager) tryDeleteLayerCandidate(candidate *LayerRecord, now time.Time, ttl time.Duration, requireExpiry bool, warningContext string) (bool, error) {
	unlock := m.acquireLayerLock(candidate.Digest)
	defer unlock()

	layer, err := m.store.getLayer(candidate.Digest)
	if err != nil {
		return false, fmt.Errorf("failed to re-read layer metadata %s %s: %w", candidate.Digest, warningContext, err)
	}
	if layer == nil || layer.RefCount != 0 || layer.Path != candidate.Path {
		return false, nil
	}
	if requireExpiry {
		if layer.RefZeroAtUnix == 0 || now.Sub(time.Unix(layer.RefZeroAtUnix, 0)) < ttl {
			return false, nil
		}
	}

	if layer.Path != "" {
		_ = os.RemoveAll(filepath.Dir(layer.Path))
	}
	if err := m.store.deleteLayer(candidate.Digest); err != nil {
		logrus.Warnf("failed to delete layer metadata %s %s: %v", candidate.Digest, warningContext, err)
		return false, nil
	}
	return true, nil
}

func (m *Manager) tryDeleteChainCandidate(candidate *ChainRecord, now time.Time, ttl time.Duration, requireExpiry bool, warningContext string) (bool, error) {
	unlock := m.acquireChainLock(candidate.ChainID)
	defer unlock()

	chain, err := m.store.getChain(candidate.ChainID)
	if err != nil {
		return false, fmt.Errorf("failed to re-read chain metadata %s %s: %w", candidate.ChainID, warningContext, err)
	}
	if chain == nil || chain.RefCount != 0 || chain.Path != candidate.Path {
		return false, nil
	}
	if requireExpiry {
		if chain.RefZeroAtUnix == 0 || now.Sub(time.Unix(chain.RefZeroAtUnix, 0)) < ttl {
			return false, nil
		}
	}

	if chain.Path != "" {
		_ = os.RemoveAll(filepath.Dir(chain.Path))
	}
	if err := m.store.deleteChain(candidate.ChainID); err != nil {
		logrus.Warnf("failed to delete chain metadata %s %s: %v", candidate.ChainID, warningContext, err)
		return false, nil
	}
	return true, nil
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func dirSizeBytes(root string) (int64, error) {
	var size int64
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		size += info.Size()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return size, nil
}

func isNotMountedError(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EINVAL || errno == syscall.ENOENT
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errors.As(pathErr.Err, &errno) {
			return errno == syscall.EINVAL || errno == syscall.ENOENT
		}
	}
	if strings.Contains(strings.ToLower(err.Error()), "not mounted") {
		return true
	}
	return false
}
