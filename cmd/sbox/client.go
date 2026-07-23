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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

type SandboxClient struct {
	client        runtime.SandboxServiceClient
	healthzClient healthgrpc.HealthClient
	conn          *grpc.ClientConn

	timeout time.Duration
}

func NewSandboxClient(ctx *cli.Context) (*SandboxClient, error) {
	duration, err := time.ParseDuration(ctx.GlobalString("timeout"))
	if err != nil {
		duration = 10 * time.Second
	}
	conn, err := generateConnection(ctx.GlobalString("address"), duration)
	if err != nil {
		return nil, err
	}
	client := &SandboxClient{
		client:        runtime.NewSandboxServiceClient(conn),
		conn:          conn,
		timeout:       duration,
		healthzClient: healthgrpc.NewHealthClient(conn),
	}
	if strings.Contains(client.Healthz(), "connection refused") {
		return nil, fmt.Errorf("sandbox server is not ready or not running, please check")
	}
	return client, nil
}

func generateConnection(socketAddress string, timeout time.Duration) (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		if len(addr) > 104 {
			targetPath := filepath.Join(os.TempDir(), filepath.Base(addr))
			if _, err := os.Lstat(targetPath); os.IsNotExist(err) {
				if err := os.Symlink(addr, targetPath); err != nil {
					return nil, fmt.Errorf("error while create Symlink %+v", err)
				}
			}
			addr = targetPath
		}

		ta, err := net.ResolveUnixAddr("unix", addr)
		if err != nil {
			return nil, fmt.Errorf("error while resolve unix addr %+v", err)
		}

		conn, err := net.DialUnix("unix", nil, ta)
		if err != nil {
			return nil, fmt.Errorf("error while dial to %s with error %v", addr, err)
		}
		return conn, err
	}

	// create grpc conn via unix domain socket
	conn, err := grpc.DialContext(
		context.Background(),
		socketAddress,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			// keep this value bigger than the grpc server keepalive time (30s)
			Time:    1 * time.Minute,
			Timeout: timeout,
		}),
		grpc.WithDefaultServiceConfig(healthServiceConfig))
	if err == nil {
		return conn, nil
	}
	return nil, fmt.Errorf("error while dial to %s with error %v", socketAddress, err)
}

func (h *SandboxClient) Close() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}

func (h *SandboxClient) Healthz() string {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()
	resp, err := h.healthzClient.Check(ctx, &healthgrpc.HealthCheckRequest{Service: config.SandboxServiceName})
	if err != nil {
		return err.Error()
	}
	return healthgrpc.HealthCheckResponse_ServingStatus_name[int32(resp.Status)]
}

func (h *SandboxClient) DeleteSandbox(request *runtime.DeleteRequest) (*runtime.DeleteResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()
	return h.client.Delete(ctx, request)
}

func (h *SandboxClient) ListSandbox(selector map[string]string, id string) (*runtime.ListSandboxesResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()
	if id != "" {
		return h.client.List(ctx, &runtime.ListSandboxesRequest{
			ID: id,
		})
	}

	return h.client.List(ctx, &runtime.ListSandboxesRequest{
		Selector: selector,
	})
}

func (h *SandboxClient) StartSandbox(request *runtime.StartRequest) (*runtime.StartResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()
	return h.client.Start(ctx, request)
}

func (h *SandboxClient) WaitSandbox(request *runtime.WaitRequest) (*runtime.WaitResponse, error) {
	return h.client.Wait(context.Background(), request)
}

func (h *SandboxClient) Stats(request *runtime.StatsRequest) (*runtime.StatsResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()
	return h.client.Stats(ctx, request)
}
