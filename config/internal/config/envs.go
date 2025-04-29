package config

import (
	"os"

	"github.com/google/go-jsonnet"
	sf "github.com/wissance/stringFormatter"
)

type (
	variable struct {
		name         string
		defaultValue string
	}

	envVar struct {
		// env vars are expected to have the prefix: `PCAP_`
		name  string
		value string
	}
)

const (
	envVarPrefix   = "PCAP"
	extVarTemplate = "env__{0}"
	envVarTemplate = "{0}_{1}"
)

var envVars = map[CtxKey]*variable{
	DebugKey:     {"DEBUG", "false"},
	VerbosityKey: {"VERBOSITY", "DEBUG"},
}

func newEnvVarKey(
	ev *envVar,
) string {
	return sf.Format(extVarTemplate, ev.name)
}

func newEnvVarName(
	v *variable,
) string {
	// append the `PCAP_` prefix for the name of the env var
	return sf.Format(envVarTemplate, envVarPrefix, v.name)
}

func setEnvVarValue(
	ev *envVar,
	v *variable,
) *envVar {
	if value, ok := os.LookupEnv(ev.name); ok {
		ev.value = value
	} else {
		ev.value = v.defaultValue
	}
	return ev
}

func setEnvVar(
	vm *jsonnet.VM,
	ev *envVar,
) {
	vm.ExtVar(newEnvVarKey(ev), ev.value)
}

func newEnvVar(
	v *variable,
) *envVar {
	return setEnvVarValue(&envVar{
		name: newEnvVarName(v),
	}, v)
}

func loadEnvironmentVariables(
	vm *jsonnet.VM,
) *jsonnet.VM {
	for _, v := range envVars {
		setEnvVar(vm, newEnvVar(v))
	}
	return vm
}
