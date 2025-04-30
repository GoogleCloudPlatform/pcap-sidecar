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

	"github.com/knadh/koanf/v2"
	sf "github.com/wissance/stringFormatter"
)

const (
	ctxKeyPrefix       = "pcap"
	ctxKeyPathTemplate = "{0}.{1}"
)

var (
	invalidConfigValueErr = errors.New("invalid config value type")
	IllegalConfigStateErr = errors.New("illegal config state")
	unavailableConfigErr  = errors.New("config not found")
)

var ctxVars = map[CtxKey]*ctxVar{
	// map from `path in JSON config` to `Context Variable`
	// NOTE: keys are automatically prefixed with `pcap.`
	DebugKey:          {"debug", TYPE_BOOLEAN, false},
	VerbosityKey:      {"verbosity", TYPE_STRING, false},
	ExecEnvKey:        {"env.id", TYPE_STRING, false},
	InstanceIDKey:     {"env.instance.id", TYPE_STRING, true},
	L3ProtosFilterKey: {"protos.l3", TYPE_LIST_STRING, false},
	L4ProtosFilterKey: {"protos.l4", TYPE_LIST_STRING, false},
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
		unavailableConfigErr,
		newConfigPathError(path),
	)
}

func newInvalidConfigValueTypeError(
	path *string,
) error {
	return errors.Join(
		invalidConfigValueErr,
		newConfigPathError(path),
	)
}

func newIllegalConfigStateError(
	path *string,
) error {
	return errors.Join(
		IllegalConfigStateErr,
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
	case TYPE_LIST_STRING:
		value = ktx.Strings(path)
	default:
		return ctx, newInvalidConfigValueTypeError(&path)
	}

	return context.WithValue(ctx, k.ToCtxKey(), value), nil
}

func LoadContext(
	ctx context.Context,
	ktx *koanf.Koanf,
) context.Context {
	for k, v := range ctxVars {
		if _ctx, err := setCtxVar(ctx, ktx, &k, v); err == nil {
			ctx = _ctx
		} else {
			ctx = context.WithValue(ctx, k.ToCtxKey(), err)
		}
	}
	return ctx
}
