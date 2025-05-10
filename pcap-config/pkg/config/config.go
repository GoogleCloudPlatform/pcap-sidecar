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

package config

import (
	"context"
	"errors"
	"net"
	"net/http"

	cfg "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/internal/config"
)

type (
	PcapVerbosity string

	PcapConfig struct {
		Debug     bool
		Verbosity PcapVerbosity
	}

	ConfigClient interface {
		GetVersion(
			ctx context.Context,
		) (string, error)

		GetBuild(
			ctx context.Context,
		) (string, error)

		IsDebug(
			ctx context.Context,
		) (bool, error)
	}
)

const (
	PCAP_VERBOSITY_INFO  = PcapVerbosity("INFO")
	PCAP_VERBOSITY_DEBUG = PcapVerbosity("DEBUG")

	localhostURLtemplate = "http://localhost:34567/{1}"
	socketURLtemplate    = "http://config/{0}"
)

func LoadJSON(
	ctx context.Context,
	configFile string,
) (context.Context, error) {
	if k, err := cfg.
		LoadJSON(configFile); err == nil {
		return cfg.LoadContext(ctx, k), nil
	} else {
		return ctx, err
	}
}

func NewSocketClient(
	_ context.Context,
	configSocket string,
	clientID string,
) (ConfigClient, error) {
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("http.DefaultTransport is not a *http.Transport")
	}

	unixTransport := defaultTransport.Clone()
	defaultDialContext := unixTransport.DialContext
	unixTransport.DialContext = func(
		ctx context.Context,
		_, _ string,
	) (net.Conn, error) {
		return defaultDialContext(ctx, "unix", configSocket)
	}

	client := http.Client{Transport: unixTransport}
	return cfg.NewHttpClient(clientID, socketURLtemplate, &client), nil
}
