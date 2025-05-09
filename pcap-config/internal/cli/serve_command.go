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
	"fmt"
	"os"

	cfg "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/internal/config"
	c "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/pkg/config"
	"github.com/knadh/koanf/v2"

	"github.com/gin-gonic/gin"
	"github.com/urfave/cli/v3"
	sf "github.com/wissance/stringFormatter"
)

const serveCommandContextKey = "pcap/ctx"

var serveCommandFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "config",
		Value: "/cfg/pcap.json",
		Aliases: []string{
			"c",
			"cfg",
		},
		Usage: "absolute path where the PCAP config file should be generated",
	},
	&cli.StringFlag{
		Name:  "socket",
		Value: "/cfg/pcap.sock",
		Aliases: []string{
			"s",
			"uds",
		},
		Usage: "absolute path where the PCAP config file should be generated",
	},
}

func newServeHandler(
	ktx *koanf.Koanf,
	ctx context.Context,
) gin.HandlerFunc {
	return func(
		gtx *gin.Context,
	) {
		gtx.Set(serveCommandContextKey, ctx)

		path := gtx.Request.URL.Path

		if path == "/" {
			gtx.JSON(200, ktx.Raw())
			return
		}

		key := sf.Format("pcap{0}", path)
		value := ktx.Get(key)

		if value == nil {
			gtx.String(404, "")
			return
		}

		gtx.JSON(200, value)
	}
}

func serveCommand(
	ctx context.Context,
	cmd *cli.Command,
) error {
	config := cmd.String("config")
	socket := cmd.String("socket")

	ktx, err := cfg.LoadJSON(config, "/")
	if err != nil {
		return err
	}
	ctx = cfg.LoadContext(ctx, ktx)

	fmt.Println(ktx.Sprint())

	if !c.IsDebugOrDefault(ctx, false) {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()
	r.NoRoute(newServeHandler(ktx, ctx))

	os.Remove(socket)
	if err := r.RunUnix(socket); err != nil {
		return err
	}

	return os.Remove(socket)
}

func newServeCommand() *cli.Command {
	return &cli.Command{
		Name:   "serve",
		Usage:  "serve PCAP sidecar's config file",
		Flags:  serveCommandFlags,
		Action: serveCommand,
	}
}
