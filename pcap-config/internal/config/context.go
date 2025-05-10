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
	CtxKeyPrefix       = "pcap"
	ctxKeyPathTemplate = "{0}/{1}"
)

var (
	errInvalidConfigValue = errors.New("invalid config value type")
	errIllegalConfigState = errors.New("illegal config state")
	errUnavailableConfig  = errors.New("config not found")
)

var CtxVars = map[CtxKey]*ctxVar{
	// map from `Context Key` to `Context Variable`
	// NOTE: keys are automatically prefixed with `pcap.`
	BuildKey:          {TYPE_STRING, true},
	VersionKey:        {TYPE_STRING, true},
	ExecEnvKey:        {TYPE_STRING, false},
	InstanceIDKey:     {TYPE_STRING, true},
	DebugKey:          {TYPE_BOOLEAN, false},
	FilterKey:         {TYPE_STRING, false},
	HostsFilterKey:    {TYPE_LIST_STRING, false},
	PortsFilterKey:    {TYPE_LIST_UINT16, false},
	L3ProtosFilterKey: {TYPE_LIST_STRING, false},
	L4ProtosFilterKey: {TYPE_LIST_STRING, false},
	TcpFlagsFilterKey: {TYPE_LIST_STRING, false},
	VerbosityKey:      {TYPE_STRING, false},
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

func newUnavailableCtxKeyError(
	key *CtxKey,
) error {
	path := string(*key)
	return newUnavailableConfigError(&path)
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

func newIllegalCtxKeyError(
	key *CtxKey,
) error {
	path := string(*key)
	return newIllegalConfigStateError(&path)
}

func newCtxKeyPath(
	key *CtxKey,
) string {
	return sf.Format(ctxKeyPathTemplate, CtxKeyPrefix, string(*key))
}

func setCtxVar(
	ctx context.Context,
	ktx *koanf.Koanf,
	k *CtxKey,
	v *ctxVar,
) (context.Context, error) {
	path := newCtxKeyPath(k)
	var value any = nil

	isAvailable := ktx.Exists(path)

	if v.req && !isAvailable {
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
	for k, v := range CtxVars {
		if _ctx, err := setCtxVar(ctx, ktx, &k, v); err == nil {
			ctx = _ctx
		} else {
			ctx = context.WithValue(ctx, k, err)
		}
	}
	return ctx
}

func newConfigError(
	key *CtxKey,
	err error,
) error {
	return errors.Join(
		errUnavailableConfig,
		errors.New(key.ToCtxKey()),
		err,
	)
}

func newInvalidConfigError(
	key *CtxKey,
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

func getCtxVar(
	ctx context.Context,
	key *CtxKey,
) (any, error) {
	if value := ctx.Value(*key); value == nil {
		return nil, newUnavailableCtxKeyError(key)
	} else if err, errOK := value.(error); errOK {
		return nil, newConfigError(key, err)
	}
	return nil, newIllegalCtxKeyError(key)
}

func GetBoolean(
	ctx context.Context,
	key CtxKey,
) (bool, error) {
	if value, err := getCtxVar(ctx, &key); err != nil {
		return false, err
	} else if v, ok := value.(bool); ok {
		return v, nil
	} else {
		return false, newInvalidConfigError(&key, TYPE_BOOLEAN, v)
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
	if value, err := getCtxVar(ctx, &key); err != nil {
		return "", err
	} else if v, ok := value.(string); ok {
		return v, nil
	} else {
		return "", newInvalidConfigError(&key, TYPE_STRING, v)
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
	if value, err := getCtxVar(ctx, &key); err != nil {
		return nil, err
	} else if v, ok := value.([]string); ok {
		return v, nil
	} else {
		return nil, newInvalidConfigError(&key, TYPE_LIST_STRING, v)
	}
}

func GetUint16(
	ctx context.Context,
	key CtxKey,
) (uint16, error) {
	if value, err := getCtxVar(ctx, &key); err != nil {
		return 0, err
	} else if v, ok := value.(uint16); ok {
		return v, nil
	} else {
		return 0, newInvalidConfigError(&key, TYPE_UINT16, v)
	}
}

func GetUint16s(
	ctx context.Context,
	key CtxKey,
) ([]uint16, error) {
	if value, err := getCtxVar(ctx, &key); err != nil {
		return nil, err
	} else if v, ok := value.([]uint16); ok {
		return v, nil
	} else {
		return nil, newInvalidConfigError(&key, TYPE_LIST_UINT16, v)
	}
}
