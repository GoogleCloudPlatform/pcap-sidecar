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

	cfg "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/internal/config"
	sf "github.com/wissance/stringFormatter"
)

func IsDebug(
	ctx context.Context,
) (bool, error) {
	return cfg.GetBoolean(ctx, cfg.DebugKey)
}

func IsDebugOrDefault(
	ctx context.Context,
	defaultValue bool,
) bool {
	return cfg.GetBooleanOrDefault(ctx, cfg.DebugKey, defaultValue)
}

func GetVerbosityOrDefault(
	ctx context.Context,
	defaultValue PcapVerbosity,
) (PcapVerbosity, error) {
	if v, err := cfg.GetString(ctx, cfg.DebugKey); err == nil {
		return PcapVerbosity(v), nil
	} else {
		return defaultValue, err
	}
}

func GetVerbosity(
	ctx context.Context,
) (PcapVerbosity, error) {
	return GetVerbosityOrDefault(ctx, PCAP_VERBOSITY_DEBUG)
}

func GetBuild(
	ctx context.Context,
) string {
	return cfg.GetStringOrDefault(ctx, cfg.BuildKey, cfg.Build)
}

func GetVersion(
	ctx context.Context,
) string {
	return cfg.GetStringOrDefault(ctx, cfg.VersionKey, cfg.Version)
}

func GetFullVersion(
	ctx context.Context,
) string {
	return sf.Format("{0}/{1}", GetVersion(ctx), GetBuild(ctx))
}

func GetFilter(
	ctx context.Context,
) string {
	return cfg.GetStringOrDefault(ctx, cfg.FilterKey, "DISABLED")
}

func GetHosts(
	ctx context.Context,
) ([]string, error) {
	return cfg.GetStrings(ctx, cfg.HostsFilterKey)
}

func GetPorts(
	ctx context.Context,
) ([]uint16, error) {
	return cfg.GetUint16s(ctx, cfg.PortsFilterKey)
}
