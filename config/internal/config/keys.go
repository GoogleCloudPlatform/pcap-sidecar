package config

import (
	"context"
	"errors"

	"github.com/knadh/koanf/v2"
	sf "github.com/wissance/stringFormatter"
)

type (
	CtxKey string

	ctxVarType string

	ctxVar struct {
		key      CtxKey
		typ      ctxVarType
		required bool
	}
)

const (
	ctxKeyPrefix       = "pcap"
	ctxKeyTemplate     = "pcap/config/{0}"
	ctxKeyPathTemplate = "{0}.{1}"

	DebugKey      = CtxKey("debug")
	ExecEnvKey    = CtxKey("execEnv")
	InstanceIDKey = CtxKey("instance-id")
	VerbosityKey  = CtxKey("verbosity")

	TYPE_STRING  = "string"
	TYPE_BOOLEAN = "boolean"
)

var (
	invalidConfigValueErr = errors.New("invalid config value type")
	IllegalConfigStateErr = errors.New("illegal config state")
	unavailableConfigErr  = errors.New("config not found")
)

var ctxVars = map[string]*ctxVar{
	// map from `path in JSON config` to `Context Variable`
	// NOTE: keys are automatically prefixed with `pcap.`
	"debug":     {DebugKey, TYPE_BOOLEAN, false},
	"verbosity": {VerbosityKey, TYPE_STRING, false},
}

func getEnvVar() {
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

func (k *CtxKey) ToCtxKey() string {
	return sf.Format(ctxKeyTemplate, string(*k))
}

func newCtxKeyPath(
	key *string,
) string {
	return sf.Format(ctxKeyPathTemplate, ctxKeyPrefix, *key)
}

func setCtxVar(
	ctx context.Context,
	ktx *koanf.Koanf,
	key *string,
	v *ctxVar,
) (context.Context, error) {
	path := newCtxKeyPath(key)
	var value any = nil

	isAvailable := ktx.Exists(path)

	if v.required && !isAvailable {
		return ctx, newUnavailableConfigError(&path)
	} else if !isAvailable {
		if envVar, ok := envVars[v.key]; ok {
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
	default:
		return ctx, newInvalidConfigValueTypeError(&path)
	}

	return context.WithValue(ctx,
		v.key.ToCtxKey(), value), nil
}

func LoadContext(
	ctx context.Context,
	ktx *koanf.Koanf,
) context.Context {
	for k, v := range ctxVars {
		if _ctx, err := setCtxVar(ctx, ktx, &k, v); err == nil {
			ctx = _ctx
		} else {
			ctx = context.WithValue(ctx, v.key.ToCtxKey(), err)
		}
	}
	return ctx
}
