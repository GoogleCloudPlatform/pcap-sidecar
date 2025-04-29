package config

import (
	"os"
	"strings"

	"github.com/google/go-jsonnet"
	sf "github.com/wissance/stringFormatter"
)

type (
	variable struct {
		name         string
		defaultValue string
		description  string
	}

	envVar struct {
		// env vars are expected to have the prefix: `PCAP_`
		name  string
		value string
	}
)

const (
	envVarPrefix   = "PCAP"
	envVarTemplate = "{0}_{1}"

	extVarTemplate = "ext__{0}"
)

var envVars = map[CtxKey]*variable{
	DebugKey: {
		"debug",
		"false",
		"log debug information from PCAP sidecar processes",
	},
	VerbosityKey: {
		"verbosity",
		"DEBUG",
		"how much information to include for packet translations",
	},
}

func newEnvVarKey(
	ev *envVar,
) string {
	return sf.Format(extVarTemplate, ev.name)
}

func newEnvVarName(
	v *variable,
) string {
	name := strings.ToUpper(v.name)
	// append the `PCAP_` prefix for the name of the env var
	return sf.Format(envVarTemplate, envVarPrefix, name)
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
