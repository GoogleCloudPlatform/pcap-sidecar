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
	"io"
	"net/http"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/pkg/pb"
	sf "github.com/wissance/stringFormatter"
	"google.golang.org/protobuf/proto"
)

type (
	HttpClient struct {
		id       string
		template string
		client   *http.Client
	}
)

func (c *HttpClient) newURL(
	key CtxKey,
) string {
	base := sf.Format(c.template, key.ToKtxKey())
	return sf.Format("{0}?ref={1}", base, c.id)
}

func (c *HttpClient) parsePcapConfigProto(
	response *http.Response,
	config *pb.PcapConfig,
) (*pb.PcapConfig, error) {
	if data, err := io.
		ReadAll(response.Body); err == nil {
		return config, proto.Unmarshal(data, config)
	} else {
		return config, err
	}
}

func (c *HttpClient) get(
	_ context.Context,
	key CtxKey,
) (*pb.PcapConfig, error) {
	config := &pb.PcapConfig{}
	if response, err := c.client.
		Get(c.newURL(key)); err == nil {
		defer response.Body.Close()
		return c.parsePcapConfigProto(response, config)
	} else {
		return config, err
	}
}

func (c *HttpClient) GetVersion(
	ctx context.Context,
) (string, error) {
	if c, err := c.
		get(ctx, BuildKey); err == nil {
		return c.GetVersion(), nil
	} else {
		return "", err
	}
}

func (c *HttpClient) GetBuild(
	ctx context.Context,
) (string, error) {
	if c, err := c.
		get(ctx, BuildKey); err == nil {
		return c.GetBuild(), nil
	} else {
		return "", err
	}
}

func (c *HttpClient) IsDebug(
	ctx context.Context,
) (bool, error) {
	if c, err := c.
		get(ctx, DebugKey); err == nil {
		return c.Features.GetDebug(), nil
	} else {
		return false, err
	}
}

func NewHttpClient(
	id string,
	urlTemplate string,
	httpClient *http.Client,
) *HttpClient {
	return &HttpClient{id, urlTemplate, httpClient}
}
