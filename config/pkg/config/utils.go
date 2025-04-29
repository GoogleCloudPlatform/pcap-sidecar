package config

import (
	"context"
	"errors"

	c "github.com/GoogleCloudPlatform/pcap-sidecar/config/internal/config"
)

var UnavailableConfigError = errors.New("")

func newError(
	err error,
) error {
	return errors.Join(UnavailableConfigError, err)
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
		return false, newError(err)
	}

	return false, UnavailableConfigError
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
		return "", newError(err)
	}

	return "", UnavailableConfigError
}

func GetDebug(
	ctx context.Context,
) (bool, error) {
	return getBoolean(ctx, c.DebugKey)
}

func GetDebugOrDefault(
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
