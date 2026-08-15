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

package runtime

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/loopdevice"
)

const erofsMountType = "erofs"

type erofsImageMounter func(source, target string) error

func newEROFSImageMounter(deviceDir string) (erofsImageMounter, error) {
	if deviceDir == "" {
		deviceDir = config.DefaultLoopDeviceDir
	}
	manager, err := loopdevice.New(deviceDir)
	if err != nil {
		return nil, err
	}
	return func(source, target string) error {
		return mountReadOnlyEROFSImageWithManager(manager, source, target)
	}, nil
}

// mountReadOnlyEROFSImage exposes an EROFS image as a host directory. The
// loop mapping is automatically cleared after the final mount disappears.
func mountReadOnlyEROFSImage(source, target string) error {
	mounter, err := newEROFSImageMounter(config.DefaultLoopDeviceDir)
	if err != nil {
		return err
	}
	return mounter(source, target)
}

func mountReadOnlyEROFSImageWithManager(
	manager *loopdevice.Manager,
	source, target string,
) error {
	device, err := manager.AttachReadOnly(source)
	if err != nil {
		return err
	}
	if err := syscall.Mount(
		device.Path(),
		target,
		erofsMountType,
		syscall.MS_RDONLY,
		"",
	); err != nil {
		return errors.Join(
			fmt.Errorf("mount EROFS loop %s at %s: %w", device.Path(), target, err),
			device.Detach(),
		)
	}
	if err := device.Release(); err != nil {
		return errors.Join(
			fmt.Errorf("release mounted EROFS loop %s: %w", device.Path(), err),
			syscall.Unmount(target, 0),
		)
	}
	return nil
}
