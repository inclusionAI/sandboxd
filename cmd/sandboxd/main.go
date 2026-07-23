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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	_ "github.com/inclusionAI/sandboxd/internal/metrics"
	"github.com/inclusionAI/sandboxd/internal/server"
	"github.com/inclusionAI/sandboxd/internal/trace"
	"github.com/inclusionAI/sandboxd/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog/v2"
)

var (
	root          = config.DefaultRootDir
	configFile    = ""
	socketAddress = config.DefaultSocketAddress
	httpAddress   = config.DefaultHttpAddress
	pprofAddress  = ""
	versionFlag   bool
	logLevel      = "info"
	logFile       = "./sandboxd.log"
)

func main() {
	initFlag()
	if versionFlag {
		fmt.Printf("%s:\n", os.Args[0])
		fmt.Println("  Version: ", version.Version)
		fmt.Println("  Go version:", version.GoVersion)
		fmt.Println("  runsc integration:", version.RunscPkgVersion)
		fmt.Println("")
		return
	}
	if err := setGLogLevel(); err != nil {
		logrus.WithError(err).Warning("failed to configure logging")
	}

	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 1024*1024)
			bufLen := runtime.Stack(buf, true)
			logrus.Errorf("panic: %v\n%s", r, buf[:bufLen])
		}

		removeSocket(socketAddress)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if configFile == "" {
		configFile = filepath.Join(root, "config.toml")
	}
	sandboxService, err := server.NewSandboxService(root, configFile)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create Sandbox service")
	}

	serveHTTP("metrics", httpAddress, metricsMux())
	serveHTTP("pprof", pprofAddress, pprofMux())
	go func() {
		if err = sandboxService.Run(); err != nil {
			logrus.WithError(err).Fatal("Failed to run Sandbox service")
		}
	}()

	enforcement := keepalive.EnforcementPolicy{
		MinTime:             30 * time.Second,
		PermitWithoutStream: true,
	}

	healthcheck := health.NewServer()
	rpc := grpc.NewServer(
		grpc.KeepaliveEnforcementPolicy(enforcement),
		grpc.UnaryInterceptor(trace.InjectTraceInterceptor))
	sandboxService.RegisterServer(rpc)
	healthgrpc.RegisterHealthServer(rpc, healthcheck)
	go func() {
		for {
			if sandboxService.Ready() {
				healthcheck.SetServingStatus(config.SandboxServiceName, healthgrpc.HealthCheckResponse_SERVING)
				healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
			} else {
				healthcheck.SetServingStatus(config.SandboxServiceName, healthgrpc.HealthCheckResponse_NOT_SERVING)
				healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
			}
			time.Sleep(1 * time.Second)
		}
	}()

	shutDownFunc := make([]func(), 0)
	shutDownFunc = append(shutDownFunc, sandboxService.ShutDown)
	serveGrpc(ctx, rpc, shutDownFunc)
}

func initFlag() {
	flag.BoolVar(&versionFlag, "version", false, "print version information and exit")
	flag.StringVar(&root, "root", root, "configuration directory; config defaults to <root>/config.toml")
	flag.StringVar(&configFile, "config", configFile, "path to config.toml; defaults to <root>/config.toml")
	flag.StringVar(&socketAddress, "socket", socketAddress, "sandbox socket address")
	flag.StringVar(&logLevel, "log-level", logLevel, "log level, include trace, debug, info, warn, error, fatal, panic")
	flag.StringVar(&logFile, "log-file", logFile, "log file path")
	flag.StringVar(&httpAddress, "http-address", httpAddress, "HTTP listen address for Prometheus metrics")
	flag.StringVar(&pprofAddress, "pprof-address", pprofAddress, "HTTP listen address for pprof; empty disables pprof")
	flag.Parse()
}

func setGLogLevel() error {
	l, err := logrus.ParseLevel(logLevel)
	if err != nil {
		l = logrus.InfoLevel
	}
	logrus.SetLevel(l)
	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: "2006-01-02 15:04:05.000", FullTimestamp: true})

	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		return err
	}

	logrus.SetOutput(&lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    256, // MiB per file
		MaxBackups: 5,
		MaxAge:     30, // days
		Compress:   true,
	})
	logrus.Infof("set log level to %s", l.String())

	fs := flag.NewFlagSet("klog", flag.PanicOnError)
	klog.InitFlags(fs)
	if err := fs.Set("logtostderr", "true"); err != nil {
		return err
	}
	switch l {
	case logrus.TraceLevel:
		return fs.Set("v", "6")
	case logrus.DebugLevel:
		return fs.Set("v", "5")
	case logrus.InfoLevel:
		return fs.Set("v", "4")
	case logrus.WarnLevel, logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
	}
	return nil
}

func metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}

func pprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func serveHTTP(name, address string, handler http.Handler) {
	if address == "" {
		return
	}
	go func() {
		server := &http.Server{
			Addr:              address,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
		}
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.WithError(err).Fatalf("failed to start %s HTTP server", name)
		}
	}()
}

const (
	socketPathLimit      = 106
	abstractSocketPrefix = "\x00"
)

type socket string

func (s socket) isAbstract() bool {
	return !strings.HasPrefix(string(s), "unix://")
}

func (s socket) path() string {
	path := strings.TrimPrefix(string(s), "unix://")
	if len(path) == len(s) {
		path = abstractSocketPrefix + path
	}
	return path
}

func removeSocket(address string) {
	sock := socket(address)
	if !sock.isAbstract() {
		if err := os.Remove(sock.path()); err != nil && !os.IsNotExist(err) {
			logrus.WithError(err).Warnf("failed to remove socket %s", sock.path())
		}
	}
}

func serveListener(path string) (net.Listener, error) {
	var (
		l   net.Listener
		err error
	)
	if path == "" {
		l, err = net.FileListener(os.NewFile(3, "socket"))
		path = "[inherited from parent]"
	} else {
		if len(path) > socketPathLimit {
			return nil, fmt.Errorf("%q: unix socket path too long (> %d)", path, socketPathLimit)
		}
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, err
		}
		l, err = net.Listen("unix", path)
	}
	if err != nil {
		return nil, err
	}
	logrus.WithField("socket", path).Debug("serving api on socket")
	return l, nil
}

func serveGrpc(ctx context.Context, server *grpc.Server, shutdown []func()) {
	dump := make(chan os.Signal, 32)
	signal.Notify(dump, syscall.SIGUSR1)

	_ = os.Remove(socketAddress)

	l, err := serveListener(socketAddress)
	if err != nil {
		logrus.WithError(err).Fatal("failed to serve grpc")
		return
	}
	go func() {
		defer l.Close()
		if err := server.Serve(l); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			logrus.WithError(err).Fatal("failed to serve grpc server")
		}
	}()

	handleExitSignals(ctx, shutdown)
}

func handleExitSignals(ctx context.Context, shutdown []func()) {
	ch := make(chan os.Signal, 32)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case s := <-ch:
			logrus.WithField("signal", s).Info("received signal, shutting down")
			for _, f := range shutdown {
				f()
			}
			return
		case <-ctx.Done():
			return
		}
	}
}
