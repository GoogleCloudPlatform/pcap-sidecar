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

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	cfg "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/internal/config"
	flag "github.com/spf13/pflag"
	"github.com/urfave/cli/v3"
	sf "github.com/wissance/stringFormatter"
)

var createCommandFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "template",
		Value: "/cfg/pcap.jsonnet",
		Aliases: []string{
			"t",
			"tpl",
		},
		Usage: "absolute path of the PCAP config file template",
	},
	&cli.StringFlag{
		Name:  "config",
		Value: "/cfg/pcap.json",
		Aliases: []string{
			"c",
			"cfg",
		},
		Usage: "absolute path where the PCAP config file should be generated",
	},
}

func createCommand(
	ctx context.Context,
	cmd *cli.Command,
) error {
	flags := flag.NewFlagSet("pcap", flag.ContinueOnError)

	cfg.RegisterFlags(flags)

	flags.Parse(os.Args[3:])

	template := cmd.String("template")
	config := cmd.String("config")

	if err := cfg.CreateJSON(&template, &config, flags); err != nil {
		return errors.Join(err, errors.New("failed to create config file"))
	}

	// other pcap modules can use the generated config file via `config.LoadJSON`
	fmt.Println(
		sf.Format("config file created at: {0}", config),
	)
	return nil
}

func newCreateCommand() *cli.Command {
	return &cli.Command{
		Name:   "create",
		Usage:  "create PCAP sidecar's config file from environment",
		Flags:  createCommandFlags,
		Action: createCommand,
	}
}
