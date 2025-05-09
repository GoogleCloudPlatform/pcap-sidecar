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

	"github.com/knadh/koanf/v2"
	sf "github.com/wissance/stringFormatter"
)

const (
	ctxKeyPrefix       = "pcap"
	ctxKeyPathTemplate = "{0}.{1}"
)

var (
	errInvalidConfigValue = errors.New("invalid config value type")
	errIllegalConfigState = errors.New("illegal config state")
	errUnavailableConfig  = errors.New("config not found")
)

var ctxVars = map[CtxKey]*ctxVar{
	// map from `Context Key` to `Context Variable`
	// NOTE: keys are automatically prefixed with `pcap.`
	BuildKey:          {"build", TYPE_STRING, true},
	VersionKey:        {"version", TYPE_STRING, true},
	DebugKey:          {"debug", TYPE_BOOLEAN, false},
	VerbosityKey:      {"verbosity", TYPE_STRING, false},
	ExecEnvKey:        {"env.id", TYPE_STRING, false},
	InstanceIDKey:     {"env.instance.id", TYPE_STRING, true},
	FilterKey:         {"filter.bpf", TYPE_STRING, false},
	HostsFilterKey:    {"filter.hosts", TYPE_LIST_STRING, false},
	PortsFilterKey:    {"filter.ports", TYPE_LIST_UINT16, false},
	L3ProtosFilterKey: {"filter.protos.l3", TYPE_LIST_STRING, false},
	L4ProtosFilterKey: {"filter.protos.l4", TYPE_LIST_STRING, false},
	TcpFlagsFilterKey: {"filter.tcp.flags", TYPE_LIST_STRING, false},
}

func newConfigPathError(
	path *string,
) error {
	return errors.New(
		sf.Format("key => {0}", *path),
	)
}

func newUnavailableConfigError(
	path *string,
) error {
	return errors.Join(
		errUnavailableConfig,
		newConfigPathError(path),
	)
}

func newInvalidConfigValueTypeError(
	path *string,
) error {
	return errors.Join(
		errInvalidConfigValue,
		newConfigPathError(path),
	)
}

func newIllegalConfigStateError(
	path *string,
) error {
	return errors.Join(
		errIllegalConfigState,
		newConfigPathError(path),
	)
}

func newCtxKeyPath(
	v *ctxVar,
) string {
	return sf.Format(ctxKeyPathTemplate, ctxKeyPrefix, v.path)
}

func setCtxVar(
	ctx context.Context,
	ktx *koanf.Koanf,
	k *CtxKey,
	v *ctxVar,
) (context.Context, error) {
	path := newCtxKeyPath(v)
	var value any = nil

	isAvailable := ktx.Exists(path)

	if v.required && !isAvailable {
		return ctx, newUnavailableConfigError(&path)
	} else if !isAvailable {
		if envVar, ok := envVars[*k]; ok {
			ktx.Set(path, envVar.defaultValue)
		} else {
			return ctx, newIllegalConfigStateError(&path)
		}
	}

	switch v.typ {
	case TYPE_STRING:
		value = ktx.String(path)
	case TYPE_BOOLEAN:
		value = ktx.Bool(path)
	case TYPE_UINT16:
		value = t_uint16(ktx, &path)
	case TYPE_LIST_STRING:
		value = ktx.Strings(path)
	case TYPE_LIST_UINT16:
		value = t_uint16s(ktx, &path)
	default:
		return ctx, newInvalidConfigValueTypeError(&path)
	}

	return context.WithValue(ctx, *k, value), nil
}

func LoadContext(
	ctx context.Context,
	ktx *koanf.Koanf,
) context.Context {
	for k, v := range ctxVars {
		if _ctx, err := setCtxVar(ctx, ktx, &k, v); err == nil {
			ctx = _ctx
		} else {
			ctx = context.WithValue(ctx, k, err)
		}
	}
	return ctx
}

func newConfigError(
	key CtxKey,
	err error,
) error {
	return errors.Join(
		errUnavailableConfig,
		errors.New(key.ToCtxKey()),
		err,
	)
}

func newInvalidConfigError(
	key CtxKey,
	want CtxVarType,
	value any,
) error {
	return errors.Join(
		errInvalidConfigValue,
		errors.New(
			sf.Format(
				"{0} has invalid type; want: {1}, got: {2}",
				key.ToCtxKey(), string(want), reflect.TypeOf(value),
			),
		),
	)
}

func GetBoolean(
	ctx context.Context,
	key CtxKey,
) (bool, error) {
	value := ctx.Value(key)

	if v, ok := value.(bool); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return false, newConfigError(key, err)
	} else {
		return false, newInvalidConfigError(key, TYPE_BOOLEAN, v)
	}
}

func GetBooleanOrDefault(
	ctx context.Context,
	key CtxKey,
	defaultValue bool,
) bool {
	if value, err := GetBoolean(ctx, key); err == nil {
		return value
	}
	return defaultValue
}

func GetString(
	ctx context.Context,
	key CtxKey,
) (string, error) {
	value := ctx.Value(key)

	if v, ok := value.(string); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return "", newConfigError(key, err)
	} else {
		return "", newInvalidConfigError(key, TYPE_STRING, v)
	}
}

func GetStringOrDefault(
	ctx context.Context,
	key CtxKey,
	defaultValue string,
) string {
	if value, err := GetString(ctx, key); err == nil {
		return value
	}
	return defaultValue
}

func GetStrings(
	ctx context.Context,
	key CtxKey,
) ([]string, error) {
	value := ctx.Value(key)

	if v, ok := value.([]string); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return nil, newConfigError(key, err)
	} else {
		return nil, newInvalidConfigError(key, TYPE_LIST_STRING, v)
	}
}

func GetUint16(
	ctx context.Context,
	key CtxKey,
) (uint16, error) {
	value := ctx.Value(key)

	if v, ok := value.(uint16); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return 0, newConfigError(key, err)
	} else {
		return 0, newInvalidConfigError(key, TYPE_UINT16, v)
	}
}

func GetUint16s(
	ctx context.Context,
	key CtxKey,
) ([]uint16, error) {
	value := ctx.Value(key)

	if v, ok := value.([]uint16); ok {
		return v, nil
	} else if err, errOK := value.(error); errOK {
		return nil, newConfigError(key, err)
	} else {
		return nil, newInvalidConfigError(key, TYPE_LIST_UINT16, v)
	}
}
