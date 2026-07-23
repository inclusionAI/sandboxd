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
	"fmt"
	"io"

	"github.com/akernel-dev/sandboxd/config"
	"github.com/akernel-dev/sandboxd/version"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"google.golang.org/grpc/grpclog"
)

func init() {
	// Discard grpc logs so that they don't mess with our stdio
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))

	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Println(c.App.Name, c.App.Version)
	}
}

func newApp() *cli.App {
	app := cli.NewApp()
	app.Name = "sbox"
	app.Version = version.Version
	app.Description = "sbox is the administrative client for sandboxd."
	app.Usage = "manage sandboxd sandboxes"
	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Enable debug output in logs",
		},
		cli.StringFlag{
			Name:  "address, a",
			Usage: "sandboxd gRPC socket address",
			Value: config.DefaultSocketAddress,
		},
		cli.DurationFlag{
			Name:  "timeout",
			Usage: "Timeout for connecting to sandboxd and completing each RPC",
			Value: config.DefaultTimeout,
		},
	}
	app.Commands = []cli.Command{
		HealthzCmd,
		StartCmd,
		ListCmd,
		InspectCmd,
		WaitCmd,
		DeleteCmd,
		ExecCmd,
		StatsCmd,
	}
	app.Before = func(context *cli.Context) error {
		logrus.SetLevel(logrus.InfoLevel)
		if context.Bool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
		return nil
	}
	return app
}
