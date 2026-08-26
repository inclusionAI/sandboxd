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

package firecracker

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	checkpointImageName               = "checkpoint.img"
	firecrackerCheckpointStateName    = "vmstate"
	firecrackerCheckpointMemoryName   = "memory"
	firecrackerCheckpointOverlayName  = "overlay.ext4"
	firecrackerCheckpointFormatName   = ".sandboxd-checkpoint-format"
	firecrackerCheckpointFormat       = "1\n"
	firecrackerCheckpointMaxComponent = int64(16 << 40)
	firecrackerCheckpointMaxExtents   = 1 << 20

	firecrackerPAXPrefix     = "AKERNEL.sandboxd."
	firecrackerSparseSizePAX = "AKERNEL.sandboxd.sparse.size"
	firecrackerSparseMapPAX  = "AKERNEL.sandboxd.sparse.map"
)

type firecrackerSparseExtent struct {
	Offset int64
	Length int64
}

type firecrackerCheckpointFiles struct {
	State   string
	Memory  string
	Overlay string
}

func createFirecrackerCheckpointArchive(
	ctx context.Context,
	imagePath string,
	compress bool,
	files firecrackerCheckpointFiles,
) (retErr error) {
	image, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create Firecracker checkpoint archive: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			retErr = errors.Join(retErr, os.Remove(imagePath))
		}
	}()

	var archiveOutput io.Writer = image
	var compressor *gzip.Writer
	if compress {
		compressor, err = gzip.NewWriterLevel(image, gzip.BestSpeed)
		if err != nil {
			return errors.Join(err, image.Close())
		}
		archiveOutput = compressor
	}
	archive := tar.NewWriter(archiveOutput)
	writeErr := writeFirecrackerCheckpointFormat(archive)
	for _, component := range []struct {
		name string
		path string
	}{
		{name: firecrackerCheckpointStateName, path: files.State},
		{name: firecrackerCheckpointMemoryName, path: files.Memory},
		{name: firecrackerCheckpointOverlayName, path: files.Overlay},
	} {
		if writeErr != nil {
			break
		}
		writeErr = writeFirecrackerCheckpointFile(
			ctx,
			archive,
			component.name,
			component.path,
		)
		if writeErr != nil {
			break
		}
	}
	closeErr := archive.Close()
	if compressor != nil {
		closeErr = errors.Join(closeErr, compressor.Close())
	}
	closeErr = errors.Join(closeErr, image.Sync(), image.Close())
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	complete = true
	return nil
}

func writeFirecrackerCheckpointFormat(archive *tar.Writer) error {
	if err := archive.WriteHeader(&tar.Header{
		Name:     firecrackerCheckpointFormatName,
		Mode:     0400,
		Size:     int64(len(firecrackerCheckpointFormat)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err := io.WriteString(archive, firecrackerCheckpointFormat)
	return err
}

func writeFirecrackerCheckpointFile(
	ctx context.Context,
	archive *tar.Writer,
	name,
	path string,
) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Firecracker checkpoint component %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > firecrackerCheckpointMaxComponent {
		return fmt.Errorf(
			"Firecracker checkpoint component %s is not a bounded regular file",
			name,
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Firecracker checkpoint component %s: %w", name, err)
	}
	defer file.Close()
	extents, err := firecrackerDataExtents(file, info.Size())
	if err != nil {
		return fmt.Errorf("inspect sparse Firecracker component %s: %w", name, err)
	}
	storedSize := info.Size()
	var paxRecords map[string]string
	if !firecrackerExtentMapIsFull(extents, info.Size()) {
		storedSize = firecrackerExtentStoredSize(extents)
		paxRecords = map[string]string{
			firecrackerSparseSizePAX: strconv.FormatInt(info.Size(), 10),
			firecrackerSparseMapPAX:  formatFirecrackerSparseExtents(extents),
		}
	}
	if err := archive.WriteHeader(&tar.Header{
		Name:       name,
		Mode:       0600,
		Size:       storedSize,
		PAXRecords: paxRecords,
	}); err != nil {
		return err
	}
	var written int64
	for _, extent := range extents {
		count, copyErr := copyFirecrackerCheckpoint(
			ctx,
			archive,
			io.NewSectionReader(file, extent.Offset, extent.Length),
		)
		written += count
		if copyErr != nil {
			return fmt.Errorf("write Firecracker checkpoint component %s: %w", name, copyErr)
		}
	}
	if written != storedSize {
		return fmt.Errorf("Firecracker checkpoint component %s changed while reading", name)
	}
	return nil
}

func firecrackerDataExtents(file *os.File, size int64) ([]firecrackerSparseExtent, error) {
	extents := make([]firecrackerSparseExtent, 0, 8)
	for offset := int64(0); offset < size; {
		data, err := unix.Seek(int(file.Fd()), offset, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break
		}
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return []firecrackerSparseExtent{{Offset: 0, Length: size}}, nil
		}
		if err != nil {
			return nil, err
		}
		hole, err := unix.Seek(int(file.Fd()), data, unix.SEEK_HOLE)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return []firecrackerSparseExtent{{Offset: 0, Length: size}}, nil
		}
		if err != nil {
			return nil, err
		}
		if data < offset || data >= size || hole <= data {
			return nil, errors.New("filesystem returned an invalid sparse extent")
		}
		if hole > size {
			hole = size
		}
		extents = append(extents, firecrackerSparseExtent{
			Offset: data,
			Length: hole - data,
		})
		if len(extents) > firecrackerCheckpointMaxExtents {
			return nil, errors.New("Firecracker checkpoint component has too many sparse extents")
		}
		offset = hole
	}
	return extents, nil
}

func firecrackerExtentMapIsFull(extents []firecrackerSparseExtent, size int64) bool {
	return len(extents) == 1 && extents[0].Offset == 0 && extents[0].Length == size
}

func firecrackerExtentStoredSize(extents []firecrackerSparseExtent) int64 {
	var size int64
	for _, extent := range extents {
		size += extent.Length
	}
	return size
}

func formatFirecrackerSparseExtents(extents []firecrackerSparseExtent) string {
	var result strings.Builder
	for index, extent := range extents {
		if index != 0 {
			result.WriteByte(',')
		}
		result.WriteString(strconv.FormatInt(extent.Offset, 10))
		result.WriteByte(':')
		result.WriteString(strconv.FormatInt(extent.Length, 10))
	}
	return result.String()
}

func extractFirecrackerCheckpointArchive(
	ctx context.Context,
	imagePath string,
	files firecrackerCheckpointFiles,
) (retErr error) {
	imageInfo, err := os.Lstat(imagePath)
	if err != nil || !imageInfo.Mode().IsRegular() ||
		imageInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Firecracker checkpoint archive is not a regular file")
	}
	image, err := os.Open(imagePath)
	if err != nil {
		return fmt.Errorf("open Firecracker checkpoint archive: %w", err)
	}
	defer image.Close()

	buffered := bufio.NewReader(image)
	var archiveInput io.Reader = buffered
	var compressor *gzip.Reader
	magic, _ := buffered.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		compressor, err = gzip.NewReader(buffered)
		if err != nil {
			return fmt.Errorf("open Firecracker checkpoint compression: %w", err)
		}
		defer compressor.Close()
		archiveInput = compressor
	}

	outputs := map[string]string{
		firecrackerCheckpointStateName:   files.State,
		firecrackerCheckpointMemoryName:  files.Memory,
		firecrackerCheckpointOverlayName: files.Overlay,
	}
	created := make([]string, 0, len(outputs))
	defer func() {
		if retErr == nil {
			return
		}
		for _, path := range created {
			retErr = errors.Join(retErr, os.Remove(path))
		}
	}()
	seen := make(map[string]bool, len(outputs))
	formatSeen := false
	archive := tar.NewReader(archiveInput)
	for {
		header, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read Firecracker checkpoint archive: %w", nextErr)
		}
		if header.Name == firecrackerCheckpointFormatName {
			if formatSeen || len(seen) != 0 || header.Typeflag != tar.TypeReg ||
				header.Size != int64(len(firecrackerCheckpointFormat)) {
				return errors.New("invalid Firecracker checkpoint format marker")
			}
			content, readErr := io.ReadAll(archive)
			if readErr != nil || string(content) != firecrackerCheckpointFormat {
				return errors.New("unsupported Firecracker checkpoint format")
			}
			formatSeen = true
			continue
		}
		path, ok := outputs[header.Name]
		metadataErr := validateFirecrackerCheckpointMetadata(header, formatSeen)
		logicalSize, extents, sparse, sparseErr := parseFirecrackerSparseHeader(header)
		if !ok || seen[header.Name] || header.Typeflag != tar.TypeReg ||
			metadataErr != nil || sparseErr != nil ||
			logicalSize <= 0 || logicalSize > firecrackerCheckpointMaxComponent {
			return fmt.Errorf("invalid Firecracker checkpoint entry %q", header.Name)
		}
		seen[header.Name] = true
		output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("create Firecracker checkpoint component %s: %w", header.Name, err)
		}
		created = append(created, path)
		var written int64
		var copyErr error
		if sparse {
			copyErr = output.Truncate(logicalSize)
			for _, extent := range extents {
				if copyErr != nil {
					break
				}
				if _, copyErr = output.Seek(extent.Offset, io.SeekStart); copyErr != nil {
					break
				}
				var count int64
				count, copyErr = copyFirecrackerCheckpoint(
					ctx,
					output,
					io.LimitReader(archive, extent.Length),
				)
				written += count
				if copyErr == nil && count != extent.Length {
					copyErr = io.ErrUnexpectedEOF
				}
			}
		} else {
			written, copyErr = copyFirecrackerCheckpoint(ctx, output, archive)
		}
		closeErr := errors.Join(output.Sync(), output.Close())
		if err := errors.Join(copyErr, closeErr); err != nil {
			return fmt.Errorf("extract Firecracker checkpoint component %s: %w", header.Name, err)
		}
		if written != header.Size {
			return fmt.Errorf("Firecracker checkpoint component %s has truncated content", header.Name)
		}
	}
	for name := range outputs {
		if !seen[name] {
			return fmt.Errorf("Firecracker checkpoint component %s is missing", name)
		}
	}
	return nil
}

func validateFirecrackerCheckpointMetadata(header *tar.Header, formatSeen bool) error {
	hasPrivateMetadata := false
	for key := range header.PAXRecords {
		if !strings.HasPrefix(key, firecrackerPAXPrefix) {
			continue
		}
		hasPrivateMetadata = true
		if key != firecrackerSparseSizePAX && key != firecrackerSparseMapPAX {
			return fmt.Errorf("unsupported private PAX record %q", key)
		}
	}
	if hasPrivateMetadata && !formatSeen {
		return errors.New("private PAX records require a checkpoint format marker")
	}
	return nil
}

func parseFirecrackerSparseHeader(
	header *tar.Header,
) (int64, []firecrackerSparseExtent, bool, error) {
	sizeValue, hasSize := header.PAXRecords[firecrackerSparseSizePAX]
	mapValue, hasMap := header.PAXRecords[firecrackerSparseMapPAX]
	if !hasSize && !hasMap {
		if header.Size <= 0 || header.Size > firecrackerCheckpointMaxComponent {
			return 0, nil, false, errors.New("invalid component size")
		}
		return header.Size, nil, false, nil
	}
	if !hasSize || !hasMap || header.Size < 0 ||
		header.Size > firecrackerCheckpointMaxComponent {
		return 0, nil, false, errors.New("incomplete sparse component metadata")
	}
	logicalSize, err := strconv.ParseInt(sizeValue, 10, 64)
	if err != nil || logicalSize <= 0 || logicalSize > firecrackerCheckpointMaxComponent {
		return 0, nil, false, errors.New("invalid sparse component size")
	}
	extents := make([]firecrackerSparseExtent, 0, strings.Count(mapValue, ",")+1)
	if mapValue != "" {
		for _, value := range strings.Split(mapValue, ",") {
			offsetValue, lengthValue, found := strings.Cut(value, ":")
			offset, offsetErr := strconv.ParseInt(offsetValue, 10, 64)
			length, lengthErr := strconv.ParseInt(lengthValue, 10, 64)
			if !found || offsetErr != nil || lengthErr != nil || offset < 0 || length <= 0 ||
				offset > logicalSize-length {
				return 0, nil, false, errors.New("invalid sparse component extent")
			}
			if len(extents) != 0 {
				previous := extents[len(extents)-1]
				if offset < previous.Offset+previous.Length {
					return 0, nil, false, errors.New("overlapping sparse component extents")
				}
			}
			extents = append(extents, firecrackerSparseExtent{Offset: offset, Length: length})
			if len(extents) > firecrackerCheckpointMaxExtents {
				return 0, nil, false, errors.New("too many sparse component extents")
			}
		}
	}
	if firecrackerExtentStoredSize(extents) != header.Size {
		return 0, nil, false, errors.New("sparse component size mismatch")
	}
	return logicalSize, extents, true, nil
}

func copyFirecrackerCheckpoint(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
) (int64, error) {
	buffer := make([]byte, 1024*1024)
	var written int64
	for {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			outputCount, writeErr := destination.Write(buffer[:count])
			written += int64(outputCount)
			if writeErr != nil {
				return written, writeErr
			}
			if outputCount != count {
				return written, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}
