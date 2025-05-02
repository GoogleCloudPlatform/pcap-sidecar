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
	"reflect"

	c "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config/internal/config"
	sf "github.com/wissance/stringFormatter"
)

var (
	UnavailableConfigError = errors.New("unavailable")
	InvalidConfigTypeError = errors.New("invalid-type")
)

func newConfigError(
	key c.CtxKey,
	err error,
) error {
	return errors.Join(
		UnavailableConfigError,
		errors.New(key.ToCtxKey()),
		err,
	)
}

func newInvalidConfigError(
	key c.CtxKey,
	want c.CtxVarType,
	value any,
) error {
	return errors.Join(
		InvalidConfigTypeError,
		errors.New(
			sf.Format(
				"{0} has invalid type; want: {1}, got: {2}",
				key.ToCtxKey(), string(want), reflect.TypeOf(value),
			),
		),
	)
}

func contextKey(
	key c.CtxKey,
) string {
	return key.ToCtxKey()
}

func getBoolean(
	ctx context.Context,
	key c.CtxKey,
) (bool, error) {
	k := contextKey(key)
	value := ctx.Value(k)

	if v, ok := value.(bool); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return false, newConfigError(key, err)
	} else {
		return false, newInvalidConfigError(key, c.TYPE_BOOLEAN, v)
	}
}

func getBooleanOrDefault(
	ctx context.Context,
	key c.CtxKey,
	defaultValue bool,
) bool {
	if value, err := getBoolean(ctx, key); err == nil {
		return value
	}
	return defaultValue
}

func getString(
	ctx context.Context,
	key c.CtxKey,
) (string, error) {
	k := contextKey(key)
	value := ctx.Value(k)

	if v, ok := value.(string); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return "", newConfigError(key, err)
	} else {
		return "", newInvalidConfigError(key, c.TYPE_STRING, v)
	}
}

func getStringOrDefault(
	ctx context.Context,
	key c.CtxKey,
	defaultValue string,
) string {
	if value, err := getString(ctx, key); err == nil {
		return value
	}
	return defaultValue
}

func getStrings(
	ctx context.Context,
	key c.CtxKey,
) ([]string, error) {
	k := contextKey(key)
	value := ctx.Value(k)

	if v, ok := value.([]string); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return nil, newConfigError(key, err)
	} else {
		return nil, newInvalidConfigError(key, c.TYPE_LIST_STRING, v)
	}
}

func getUint16(
	ctx context.Context,
	key c.CtxKey,
) (uint16, error) {
	k := contextKey(key)
	value := ctx.Value(k)

	if v, ok := value.(uint16); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return 0, newConfigError(key, err)
	} else {
		return 0, newInvalidConfigError(key, c.TYPE_UINT16, v)
	}
}

func getUint16s(
	ctx context.Context,
	key c.CtxKey,
) ([]uint16, error) {
	k := contextKey(key)
	value := ctx.Value(k)

	if v, ok := value.([]uint16); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return nil, newConfigError(key, err)
	} else {
		return nil, newInvalidConfigError(key, c.TYPE_LIST_UINT16, v)
	}
}

func IsDebug(
	ctx context.Context,
) (bool, error) {
	return getBoolean(ctx, c.DebugKey)
}

func IsDebugOrDefault(
	ctx context.Context,
	defaultValue bool,
) bool {
	return getBooleanOrDefault(ctx, c.DebugKey, defaultValue)
}

func GetVerbosityOrDefault(
	ctx context.Context,
	defaultValue PcapVerbosity,
) (PcapVerbosity, error) {
	if v, err := getString(ctx, c.DebugKey); err == nil {
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
	return getStringOrDefault(ctx, c.BuildKey, c.Build)
}

func GetVersion(
	ctx context.Context,
) string {
	return getStringOrDefault(ctx, c.VersionKey, c.Version)
}

func GetFullVersion(
	ctx context.Context,
) string {
	return sf.Format("{0}/{1}", GetVersion(ctx), GetBuild(ctx))
}

func GetFilter(
	ctx context.Context,
) string {
	return getStringOrDefault(ctx, c.FilterKey, "DISABLED")
}

func GetHosts(
	ctx context.Context,
) ([]string, error) {
	return getStrings(ctx, c.HostsFilterKey)
}

func GetPorts(
	ctx context.Context,
) ([]uint16, error) {
	return getUint16s(ctx, c.PortsFilterKey)
}
