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
	"encoding/json"
	"io"
	"net/http"

	sf "github.com/wissance/stringFormatter"
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

func (c *HttpClient) get(
	_ context.Context,
	key CtxKey,
) ([]byte, error) {
	if response, err := c.client.
		Get(c.newURL(key)); err == nil {
		defer response.Body.Close()
		return io.ReadAll(response.Body)
	} else {
		return nil, err
	}
}

func (c *HttpClient) getString(
	ctx context.Context,
	key CtxKey,
) (string, error) {
	if data, err := c.get(ctx, key); err == nil {
		return string(data), nil
	} else {
		return "", err
	}
}

func (c *HttpClient) getStrings(
	ctx context.Context,
	key CtxKey,
) ([]string, error) {
	if data, err := c.get(ctx, key); err == nil {
		var value []string
		err = json.Unmarshal(data, &value)
		if err != nil {
			return nil, err
		}
		return value, err
	} else {
		return nil, err
	}
}

func (c *HttpClient) getUint16s(
	ctx context.Context,
	key CtxKey,
) ([]uint16, error) {
	if data, err := c.get(ctx, key); err == nil {
		var value []uint16
		err = json.Unmarshal(data, &value)
		if err != nil {
			return nil, err
		}
		return value, err
	} else {
		return nil, err
	}
}

func (c *HttpClient) GetVersion(
	ctx context.Context,
) (string, error) {
	return c.getString(ctx, VerbosityKey)
}

func (c *HttpClient) GetBuild(
	ctx context.Context,
) (string, error) {
	return c.getString(ctx, BuildKey)
}

func (c *HttpClient) GetHosts(
	ctx context.Context,
) ([]string, error) {
	return c.getStrings(ctx, HostsFilterKey)
}

func (c *HttpClient) GetPorts(
	ctx context.Context,
) ([]uint16, error) {
	return c.getUint16s(ctx, PortsFilterKey)
}

func NewHttpClient(
	id string,
	urlTemplate string,
	httpClient *http.Client,
) *HttpClient {
	return &HttpClient{id, urlTemplate, httpClient}
}
