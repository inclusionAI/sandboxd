// Copyright (c) 2026 Ant Group Corporation.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

const rebootSocket = "/run/sandboxd/reboot.sock"

// Bind in a private directory before publishing the socket, so a client
// cannot connect between bind and chmod even under a permissive umask.
func serveRebootSocket(path string, handler http.Handler) (func(), error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	if old, err := os.Lstat(path); err == nil {
		if old.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s is not a Unix socket", path)
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%s is already accepting connections", path)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	tmp, err := os.MkdirTemp(dir, ".reboot-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	socket := filepath.Join(tmp, "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	stat, err := os.Lstat(socket)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := os.Rename(socket, path); err != nil {
		_ = listener.Close()
		return nil, err
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Error("maintenance socket failed")
		}
	}()
	return func() {
		_ = srv.Close()
		if current, err := os.Lstat(path); err == nil && os.SameFile(stat, current) {
			_ = os.Remove(path)
		}
	}, nil
}
