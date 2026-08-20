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
	"flag"
	"os"

	"github.com/inclusionAI/sandboxd/internal/runcshim"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("runc-shim", flag.ContinueOnError)
	options := runcshim.Options{}
	flags.StringVar(&options.Binary, "binary", "", "runc binary")
	flags.StringVar(&options.Root, "root", "", "runc state root")
	flags.StringVar(&options.Bundle, "bundle", "", "OCI bundle")
	flags.StringVar(&options.ID, "id", "", "container ID")
	flags.StringVar(&options.Stdout, "stdout", "", "container stdout")
	flags.StringVar(&options.Stderr, "stderr", "", "container stderr")
	if err := flags.Parse(args); err != nil {
		return 125
	}
	if err := options.Validate(); err != nil {
		return 125
	}
	return runcshim.Run(options)
}
