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

package nydus

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// Standard Nydus annotations and media types
	// Reference: github.com/containerd/nydus-snapshotter/pkg/converter/constant.go
	// Reference: github.com/containerd/nydus-snapshotter/pkg/label/label.go

	// Layer annotations
	LayerAnnotationNydusBootstrap = "containerd.io/snapshot/nydus-bootstrap"
	LayerAnnotationNydusBlob      = "containerd.io/snapshot/nydus-blob"

	// Media types
	MediaTypeNydusBlob = "application/vnd.oci.image.layer.nydus.blob.v1"

	// Bootstrap file name in layer tar
	BootstrapFileNameInLayer = "image/image.boot"
)

// IsNydusImage checks if an image is in Nydus format
// Reference: github.com/containerd/nydus-snapshotter/pkg/converter/convert_unix.go::isNydusImage
func IsNydusImage(img v1.Image) (bool, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return false, fmt.Errorf("failed to get manifest: %w", err)
	}

	layers := manifest.Layers
	if len(layers) == 0 {
		return false, nil
	}

	// In Nydus images, the bootstrap layer is always the last layer
	lastLayer := layers[len(layers)-1]
	if lastLayer.Annotations != nil {
		if _, ok := lastLayer.Annotations[LayerAnnotationNydusBootstrap]; ok {
			return true, nil
		}
	}

	return false, nil
}

// ExtractBootstrap extracts the Nydus bootstrap from the image
// In Nydus images, the bootstrap is always in the last layer
func ExtractBootstrap(ctx context.Context, img v1.Image, outputDir string) (string, error) {
	// Stage 1: Get layers
	stageStart := time.Now()
	layers, err := img.Layers()
	if err != nil {
		return "", fmt.Errorf("failed to get layers: %w", err)
	}

	if len(layers) == 0 {
		return "", fmt.Errorf("image has no layers")
	}
	getLayersDuration := time.Since(stageStart)

	// Stage 2: Create output directory
	stageStart = time.Now()
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	mkdirDuration := time.Since(stageStart)

	// Stage 3: Extract bootstrap from last layer
	stageStart = time.Now()
	lastLayer := layers[len(layers)-1]
	bootstrapPath, err := extractBootstrapFromLayer(ctx, lastLayer, outputDir)
	if err != nil {
		return "", fmt.Errorf("failed to extract bootstrap from last layer: %w", err)
	}
	extractDuration := time.Since(stageStart)

	// Log sub-stage timings if we have a tracer
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent("extract_bootstrap_details",
			trace.WithAttributes(
				attribute.Int64("get_layers_ms", getLayersDuration.Milliseconds()),
				attribute.Int64("mkdir_ms", mkdirDuration.Milliseconds()),
				attribute.Int64("extract_layer_ms", extractDuration.Milliseconds()),
			),
		)
	}

	return bootstrapPath, nil
}

func extractBootstrapFromLayer(ctx context.Context, layer v1.Layer, outputDir string) (string, error) {
	// Stage 1: Decompress layer
	stageStart := time.Now()
	rc, err := layer.Uncompressed()
	if err != nil {
		return "", fmt.Errorf("failed to decompress layer: %w", err)
	}
	defer rc.Close()
	decompressDuration := time.Since(stageStart)

	// Stage 2: Read tar and find bootstrap
	stageStart = time.Now()
	tr := tar.NewReader(bootstrapReader{ctx: ctx, reader: rc})

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar: %w", err)
		}

		// Bootstrap must be at the standard path
		if header.Name == BootstrapFileNameInLayer {
			tarReadDuration := time.Since(stageStart)

			// Stage 3: Extract file
			stageStart = time.Now()
			outputPath := filepath.Join(outputDir, "bootstrap")
			if err := extractFile(ctx, tr, outputPath); err != nil {
				return "", err
			}
			extractFileDuration := time.Since(stageStart)

			// Log sub-stage timings if we have a tracer
			if span := trace.SpanFromContext(ctx); span.IsRecording() {
				span.AddEvent("extract_from_layer_details",
					trace.WithAttributes(
						attribute.Int64("decompress_ms", decompressDuration.Milliseconds()),
						attribute.Int64("tar_read_ms", tarReadDuration.Milliseconds()),
						attribute.Int64("extract_file_ms", extractFileDuration.Milliseconds()),
					),
				)
			}

			return outputPath, nil
		}
	}

	return "", fmt.Errorf("bootstrap file not found at %s", BootstrapFileNameInLayer)
}

type bootstrapReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r bootstrapReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func extractFile(ctx context.Context, tr *tar.Reader, outputPath string) error {
	tempDir, err := os.MkdirTemp(filepath.Dir(outputPath), ".bootstrap-")
	if err != nil {
		return fmt.Errorf("failed to stage bootstrap: %w", err)
	}
	defer os.Remove(tempDir)
	tempPath := filepath.Join(tempDir, "bootstrap")
	f, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer os.Remove(tempPath)

	_, copyErr := io.Copy(f, tr)
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("failed to write file: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close bootstrap: %w", closeErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		return fmt.Errorf("failed to publish bootstrap: %w", err)
	}
	return nil
}
