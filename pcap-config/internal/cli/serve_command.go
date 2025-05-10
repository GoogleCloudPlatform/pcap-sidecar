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
	"net/http"
	"os"
	"strings"

	cfg "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/internal/config"
	c "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/pkg/config"
	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/pkg/pb"
	"github.com/knadh/koanf/v2"

	"github.com/gin-gonic/gin"
	"github.com/urfave/cli/v3"
	sf "github.com/wissance/stringFormatter"
)

const (
	serveCommandContextKey = "pcap/ctx"
	serveCommandKontextKey = "pcap/ktx"
)

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

func serveConfigResponse(
	gtx *gin.Context,
	key *cfg.CtxKey,
	value any,
	config *pb.PcapConfig,
) {
	k := string(*key)
	v := sf.Format("{0}", value)
	gtx.Header("x-pcap-config-key", k)
	gtx.Header("x-pcap-config-value", v)
	gtx.ProtoBuf(http.StatusOK, config)
}

func newServeConfigKey(
	path *string,
) string {
	return sf.Format(cfg.KtxKeyTemplate, *path)
}

func serveConfigKey(
	ctx context.Context,
	ktx *koanf.Koanf,
	gtx *gin.Context,
	config *pb.PcapConfig,
	path *string,
) {
	key := newServeConfigKey(path)
	value := ktx.Get(key)

	if value == nil {
		gtx.ProtoBuf(http.StatusNotFound, config)
		return
	}

	ctxKey := cfg.CtxKey(*path)

	serveConfigResponse(gtx, &ctxKey, value,
		cfg.SetProtoValue(ctx, &ctxKey, config))
}

func newServeHandler(
	ctx context.Context,
	ktx *koanf.Koanf,
) gin.HandlerFunc {
	return func(
		gtx *gin.Context,
	) {
		config := &pb.PcapConfig{
			Version:  c.GetVersion(ctx),
			Build:    c.GetBuild(ctx),
			Features: &pb.PcapConfig_PcapFeatures{},
		}

		path := strings.Trim(gtx.Request.URL.Path, "/")

		if path == "" || path == "/" {
			gtx.ProtoBuf(http.StatusOK, config)
		} else {
			serveConfigKey(ctx, ktx, gtx, config, &path)
		}
	}
}

func newServeCommandEngine(
	ctx context.Context,
	ktx *koanf.Koanf,
) *gin.Engine {
	if c.IsDebugOrDefault(ctx, false) {
		gin.SetMode(gin.TestMode)
		gin.ForceConsoleColor()
	} else {
		gin.SetMode(gin.ReleaseMode)
		gin.DisableConsoleColor()
	}

	rtr := gin.Default()

	rtr.Use(gin.Recovery())
	rtr.Use(func(gtx *gin.Context) {
		gtx.Set(serveCommandContextKey, ctx)
		gtx.Set(serveCommandKontextKey, ktx)
	})
	rtr.NoRoute(newServeHandler(ctx, ktx))

	return rtr
}

func serveCommand(
	ctx context.Context,
	cmd *cli.Command,
) error {
	config := cmd.String("config")
	socket := cmd.String("socket")

	ktx, err := cfg.LoadJSON(config)
	if err != nil {
		return err
	}
	fmt.Println(ktx.Sprint())

	ctx = cfg.LoadContext(ctx, ktx)

	rtr := newServeCommandEngine(ctx, ktx)

	os.Remove(socket)
	if err := rtr.RunUnix(socket); err != nil {
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
