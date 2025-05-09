// Copyright 2024 Google LLC
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
	"log"
	"os"

	cli "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/internal/cli"
	cfg "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/internal/config"
	sf "github.com/wissance/stringFormatter"
)

func main() {
	log.Println(sf.Format("PCAP sidecar v{0}@{1}", cfg.Version, cfg.Build))

	cmd := cli.NewCLI("pcapcfg")

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// TODO: move ALL cmd args from all modules to this one and merge them with env vars using:
	//  - https://pkg.go.dev/github.com/knadh/koanf/providers/posflag
	//  - https://github.com/knadh/koanf?tab=readme-ov-file#reading-from-command-line
}
