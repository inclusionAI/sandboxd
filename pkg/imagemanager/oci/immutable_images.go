// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"
)

// Only immutable references retain process/layer metadata after a mount is
// released. The existing ROFS layer cache and its GC still own all file bytes.
// This record holds no layer references and cannot prevent their collection.
type immutableImageRecord struct {
	ImageURL     string               `json:"image_url"`
	LayerDigests []string             `json:"layer_digests"`
	ChainIDs     []string             `json:"chain_ids"`
	Env          []string             `json:"env"`
	ImageProcess *imageconfig.Process `json:"image_process"`
}

type resolvedImageLayers struct {
	immutableImageRecord
	LayerPaths []string
}

func immutableReference(value string) bool {
	_, err := name.NewDigest(value)
	return err == nil
}

func (s *metadataStore) putImmutableImage(record *immutableImageRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(immutableImagesBucket).Put([]byte(record.ImageURL), data) })
}

func (s *metadataStore) getImmutableImage(imageURL string) (*immutableImageRecord, error) {
	var record *immutableImageRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(immutableImagesBucket).Get([]byte(imageURL))
		if data == nil {
			return nil
		}
		record = &immutableImageRecord{}
		return json.Unmarshal(data, record)
	})
	return record, err
}

func validImmutableRecord(record *immutableImageRecord, imageURL string) bool {
	if record == nil || record.ImageURL != imageURL || record.ImageProcess == nil || len(record.LayerDigests) == 0 || len(record.ChainIDs) != len(record.LayerDigests) {
		return false
	}
	for _, digest := range append(append([]string(nil), record.LayerDigests...), record.ChainIDs...) {
		if hash, err := v1.NewHash(digest); err != nil || hash.Algorithm != "sha256" || len(hash.Hex) != 64 {
			return false
		}
	}
	return true
}

func (m *Manager) reserveCachedImage(ctx context.Context, imageURL string) (*resolvedImageLayers, error) {
	if !immutableReference(imageURL) {
		return nil, nil
	}
	record, err := m.store.getImmutableImage(imageURL)
	if err != nil || !validImmutableRecord(record, imageURL) {
		return nil, nil
	}
	var reserved, paths []string
	for _, digest := range record.LayerDigests {
		unlock, err := m.acquireLayerLockWithContext(ctx, digest)
		if err != nil {
			m.rollbackReservedLayerRefs(reserved)
			return nil, err
		}
		layer, err := m.store.getLayer(digest)
		if err == nil && layer != nil && layer.Path != "" && pathExists(layer.Path) {
			layer, err = m.store.incrementLayerRef(digest, m.now().Unix())
		} else {
			layer = nil
		}
		unlock()
		if err != nil || layer == nil {
			m.rollbackReservedLayerRefs(reserved)
			return nil, nil // GC/missing bytes: use the normal authenticated registry path.
		}
		reserved = append(reserved, digest)
		paths = append(paths, layer.Path)
	}
	logrus.Infof("OCI immutable metadata cache hit: image=%s layers=%d", imageURL, len(paths))
	return &resolvedImageLayers{immutableImageRecord: *record, LayerPaths: paths}, nil
}

func (m *Manager) resolveImageLayers(ctx context.Context, imageURL string, stage func(string, time.Duration)) (*resolvedImageLayers, error) {
	started := time.Now()
	if cached, err := m.reserveCachedImage(ctx, imageURL); err != nil {
		return nil, err
	} else if cached != nil {
		stage("reuse_immutable_metadata_layers", time.Since(started))
		return cached, nil
	}
	img, err := m.fetchImage(ctx, imageURL)
	if err != nil {
		return nil, err
	}
	stage("fetch_image", time.Since(started))
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read image config for %s: %w", imageURL, err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("missing image config for %s", imageURL)
	}
	started = time.Now()
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("image %s has no layers", imageURL)
	}
	stage("list_layers", time.Since(started))
	started = time.Now()
	diffIDs, err := resolveImageLayerDiffIDs(img, layers)
	if err != nil {
		return nil, err
	}
	chains, err := buildChainIDs(diffIDs)
	if err != nil {
		return nil, err
	}
	stage("build_chain_ids", time.Since(started))
	started = time.Now()
	digests, paths, err := m.extractLayersWithWorkers(ctx, layers)
	if err != nil {
		return nil, err
	}
	stage("extract_layers", time.Since(started))
	return &resolvedImageLayers{immutableImageRecord: immutableImageRecord{ImageURL: imageURL, LayerDigests: digests, ChainIDs: chains, Env: cfg.Config.Env, ImageProcess: imageconfig.FromOCI(cfg.Config)}, LayerPaths: paths}, nil
}
