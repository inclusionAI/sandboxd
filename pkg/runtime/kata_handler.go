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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	tasktypes "github.com/containerd/containerd/api/types/task"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/util"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/sirupsen/logrus"
)

var _ Handler = &KataHandler{}

const defaultKataSharedSandboxRoot = "/run/kata-containers/shared/sandboxes"

type KataHandler struct {
	binary       string
	sandboxRoot  string
	sharedRoot   string
	configPath   string
	danConfigDir string
	loggerBinary string
	ociLoader    OciLoader
	shims        cmap.ConcurrentMap[string, *kataShimInstance]
}

func NewKataHandler(cfg config.Config, binary string, loader OciLoader) (*KataHandler, error) {
	kataConfig := cfg.RuntimeConfig.Kata
	if kataConfig.ConfigPath == "" {
		kataConfig.ConfigPath = config.DefaultKataConfig
	}
	if kataConfig.KVMDevice == "" {
		kataConfig.KVMDevice = config.DefaultKVMDevice
	}
	if kataConfig.DANConfigDir == "" {
		kataConfig.DANConfigDir = config.DefaultKataDANConfigDir
	}
	if kataConfig.LoggerBinary == "" {
		kataConfig.LoggerBinary = config.DefaultSandboxLogger
	}
	if err := validateKataHost(binary, kataConfig); err != nil {
		return nil, err
	}
	sandboxRoot := filepath.Join(cfg.RootDir, "containers")
	if err := os.MkdirAll(sandboxRoot, 0755); err != nil {
		return nil, fmt.Errorf("create kata sandbox root: %w", err)
	}
	handler := &KataHandler{
		binary:       binary,
		sandboxRoot:  sandboxRoot,
		sharedRoot:   defaultKataSharedSandboxRoot,
		configPath:   kataConfig.ConfigPath,
		danConfigDir: kataConfig.DANConfigDir,
		loggerBinary: kataConfig.LoggerBinary,
		ociLoader:    loader,
		shims:        cmap.New[*kataShimInstance](),
	}
	handler.recoverShims()
	return handler, nil
}

func validateKataHost(binary string, kataConfig config.KataConfig) error {
	if info, err := os.Stat(binary); err != nil {
		return fmt.Errorf("kata shim binary: %w", err)
	} else if info.IsDir() || info.Mode()&0111 == 0 {
		return fmt.Errorf("kata shim binary %s is not executable", binary)
	}
	if kataConfig.ConfigPath == "" {
		return fmt.Errorf("kata config path is empty")
	}
	if info, err := os.Stat(kataConfig.ConfigPath); err != nil {
		return fmt.Errorf("kata config: %w", err)
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("kata config %s is not a regular file", kataConfig.ConfigPath)
	}
	if info, err := os.Stat(kataConfig.LoggerBinary); err != nil {
		return fmt.Errorf("sandbox logger binary: %w", err)
	} else if info.IsDir() || info.Mode()&0111 == 0 {
		return fmt.Errorf("sandbox logger binary %s is not executable", kataConfig.LoggerBinary)
	}
	info, err := os.Stat(kataConfig.KVMDevice)
	if err != nil {
		return fmt.Errorf("kata requires KVM device %s: %w", kataConfig.KVMDevice, err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("kata KVM path %s is not a character device", kataConfig.KVMDevice)
	}
	kvm, err := os.OpenFile(kataConfig.KVMDevice, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open Kata KVM device %s: %w", kataConfig.KVMDevice, err)
	}
	return kvm.Close()
}

func (k *KataHandler) Start(ctx context.Context, startConfig StartConfig) error {
	if startConfig.Rootfs == "" {
		return fmt.Errorf("kata rootfs is required")
	}
	bundlePath, err := k.bundlePath(startConfig.ID)
	if err != nil {
		return err
	}
	rootfsKind, err := classifyKataRootfs(startConfig.Rootfs)
	if err != nil {
		return err
	}
	if startConfig.Resources != nil && startConfig.CgroupPath != "" {
		if err := updateCgroup(startConfig.CgroupPath, kataHostResources(startConfig.Resources)); err != nil {
			return fmt.Errorf("update cgroup: %w", err)
		}
	}

	kataConfig := cloneKataStartConfig(startConfig)
	cleanupMounts, err := prepareKataMounts(bundlePath, &kataConfig)
	if err != nil {
		return fmt.Errorf("prepare Kata mounts: %w", err)
	}
	bundlePath, _, err = k.ociLoader.GenerateOci(OciLoadOptions{
		SandboxID:  startConfig.ID,
		Config:     kataConfig,
		CgroupPath: startConfig.CgroupPath,
	})
	if err != nil {
		return errors.Join(
			fmt.Errorf("generate OCI bundle: %w", err),
			cleanupMounts(),
		)
	}

	rootfsPlan, err := prepareKataRootfs(
		bundlePath,
		kataConfig.Rootfs,
		rootfsKind,
	)
	if err != nil {
		return errors.Join(
			fmt.Errorf("prepare kata rootfs: %w", err),
			cleanupMounts(),
		)
	}
	cleanupNetwork, err := prepareKataNetwork(
		startConfig.ID,
		bundlePath,
		startConfig.Network,
		k.danConfigDir,
	)
	if err != nil {
		return errors.Join(
			fmt.Errorf("prepare kata network: %w", err),
			rootfsPlan.cleanup(),
			cleanupMounts(),
		)
	}
	cleanupPrepared := func() error {
		cleanupNetwork()
		return errors.Join(rootfsPlan.cleanup(), cleanupMounts())
	}
	restoreSpec, err := prepareKataResourceSpec(bundlePath, startConfig.Resources)
	if err != nil {
		return errors.Join(
			fmt.Errorf("prepare Kata VM resources: %w", err),
			cleanupPrepared(),
		)
	}
	runtimeOptions, err := kataRuntimeOptions(k.configPath)
	if err != nil {
		return errors.Join(
			fmt.Errorf("encode kata runtime options: %w", err),
			restoreSpec(),
			cleanupPrepared(),
		)
	}
	client, err := k.startShim(ctx, startConfig.ID, bundlePath)
	if err != nil {
		return errors.Join(err, restoreSpec(), cleanupPrepared())
	}
	defer client.Close()
	cleanupRuntime := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return errors.Join(
			k.forceStopShim(cleanupCtx, startConfig.ID, bundlePath),
			cleanupPrepared(),
		)
	}

	loggerURI, err := sandboxLoggerURI(k.loggerBinary, startConfig.Stdout, startConfig.Stderr)
	if err != nil {
		return errors.Join(
			fmt.Errorf("prepare task logger: %w", err),
			restoreSpec(),
			cleanupRuntime(),
		)
	}
	createRequest := &shimCreateTaskRequest{
		ID:       startConfig.ID,
		Bundle:   bundlePath,
		Terminal: false,
		Rootfs:   rootfsPlan.mounts,
		Options:  runtimeOptions,
		Stdout:   loggerURI,
		Stderr:   loggerURI,
	}
	if _, err := k.createTask(ctx, client, createRequest); err != nil {
		return errors.Join(
			fmt.Errorf("kata task create: %w", err),
			restoreSpec(),
			cleanupRuntime(),
		)
	}
	if err := restoreSpec(); err != nil {
		return errors.Join(
			fmt.Errorf("restore Kata OCI resource metadata: %w", err),
			cleanupRuntime(),
		)
	}
	if _, err := k.startTask(ctx, client, &shimStartRequest{ID: startConfig.ID}); err != nil {
		return errors.Join(
			fmt.Errorf("kata task start: %w", err),
			cleanupRuntime(),
		)
	}
	if err := writeSandboxRuntimeMarker(bundlePath, config.RuntimeNameKata); err != nil {
		return errors.Join(
			fmt.Errorf("persist sandbox runtime: %w", err),
			cleanupRuntime(),
		)
	}
	logrus.Infof("kata: started sandbox %s", startConfig.ID)
	return nil
}

func sandboxLoggerURI(binary, stdout, stderr string) (string, error) {
	if !filepath.IsAbs(binary) {
		return "", fmt.Errorf("logger binary path %q is not absolute", binary)
	}
	uri := &url.URL{Scheme: "binary", Path: filepath.Clean(binary)}
	query := uri.Query()
	query.Set("stdout", stdout)
	query.Set("stderr", stderr)
	uri.RawQuery = query.Encode()
	return uri.String(), nil
}

func (k *KataHandler) Delete(ctx context.Context, sandboxID string) error {
	bundlePath, err := k.bundlePath(sandboxID)
	if err != nil {
		return err
	}
	var deleteErrors []error
	stopErr := k.stopShim(ctx, sandboxID)
	if stopErr != nil {
		deleteErrors = append(deleteErrors, stopErr)
	}
	if err := cleanupKataRootfs(bundlePath); err != nil {
		deleteErrors = append(deleteErrors, err)
	}
	if err := cleanupKataMounts(bundlePath); err != nil {
		deleteErrors = append(deleteErrors, err)
	}
	cleanupKataNetwork(bundlePath)
	if stopErr == nil {
		if err := k.cleanupSharedPath(sandboxID); err != nil {
			deleteErrors = append(deleteErrors, err)
		}
	}
	if len(deleteErrors) > 0 {
		return errors.Join(deleteErrors...)
	}
	return nil
}

func (k *KataHandler) Wait(ctx context.Context, sandboxID string) (Exit, error) {
	instance, ok := k.shims.Get(sandboxID)
	if !ok {
		return Exit{}, fmt.Errorf("kata shim for %s is not available", sandboxID)
	}
	client, err := connectKataShim(instance.address)
	if err != nil {
		return Exit{}, err
	}
	defer client.Close()
	response, err := k.waitTask(ctx, client, sandboxID)
	if err != nil {
		if !kataProcessAlive(instance.pid) {
			return Exit{ExitedAt: time.Now(), ExitCode: 255}, nil
		}
		return Exit{}, err
	}
	exitedAt := time.Now()
	if response.ExitedAt != nil {
		exitedAt = response.ExitedAt.AsTime()
	}
	return Exit{ExitedAt: exitedAt, ExitCode: int(response.ExitStatus)}, nil
}

func (k *KataHandler) List(ctx context.Context) ([]*State, error) {
	result := make([]*State, 0, k.shims.Count())
	for sandboxID, instance := range k.shims.Items() {
		status := SandboxStatusUnknown
		pid := instance.pid
		client, err := connectKataShim(instance.address)
		if err == nil {
			state, stateErr := k.stateTask(ctx, client, sandboxID)
			_ = client.Close()
			if stateErr == nil {
				status = kataSandboxStatus(state.Status)
				if state.Pid != 0 {
					pid = int(state.Pid)
				}
			}
		}
		result = append(result, &State{
			ID:             sandboxID,
			InitProcessPid: pid,
			Status:         status,
			Created:        instance.createdAt.Format(time.RFC3339Nano),
		})
	}
	return result, nil
}

func (k *KataHandler) bundlePath(sandboxID string) (string, error) {
	bundlePath, err := util.JoinWithinRoot(k.sandboxRoot, sandboxID)
	if err != nil {
		return "", fmt.Errorf("resolve kata sandbox bundle: %w", err)
	}
	return bundlePath, nil
}

func (k *KataHandler) cleanupSharedPath(sandboxID string) error {
	if k.sharedRoot == "" {
		return nil
	}
	path, err := util.JoinWithinRoot(k.sharedRoot, sandboxID)
	if err != nil {
		return fmt.Errorf("resolve Kata shared path: %w", err)
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove Kata shared path %s: %w", path, err)
	}
	return nil
}

func kataSandboxStatus(status tasktypes.Status) SandboxStatus {
	switch status {
	case tasktypes.Status_CREATED:
		return SandboxStatusCreated
	case tasktypes.Status_RUNNING:
		return SandboxStatusRunning
	case tasktypes.Status_STOPPED:
		return SandboxStatusExited
	default:
		return SandboxStatusUnknown
	}
}

func writeSandboxRuntimeMarker(bundlePath, runtimeName string) error {
	data, err := json.Marshal(struct {
		Runtime string `json:"runtime"`
	}{Runtime: runtimeName})
	if err != nil {
		return err
	}
	temporaryPath := filepath.Join(bundlePath, ".runtime.json.tmp")
	finalPath := filepath.Join(bundlePath, "runtime.json")
	if err := os.WriteFile(temporaryPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(temporaryPath, finalPath)
}

func isKataRuntimeBundle(bundlePath string) bool {
	data, err := os.ReadFile(filepath.Join(bundlePath, "runtime.json"))
	if err != nil {
		return false
	}
	var marker struct {
		Runtime string `json:"runtime"`
	}
	return json.Unmarshal(data, &marker) == nil && marker.Runtime == config.RuntimeNameKata
}
