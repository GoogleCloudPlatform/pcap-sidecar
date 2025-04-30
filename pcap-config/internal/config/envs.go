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
	BuildKey: {
		"build",
		Build,
		"PCAP sidecar's build/commit id",
	},
	VersionKey: {
		"version",
		Version,
		"PCAP sidecar's version",
	},
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
	ExecEnvKey: {
		"exec_env",
		"run",
		"execution environment, one of (run,gae,gke)",
	},
	InstanceIDKey: {
		"instance_id",
		"unknown",
		"runtime instance ID (depends on the execution environment)",
	},
	L3ProtosFilterKey: {
		"l3_protos",
		"icmp,icmp6",
		"list of network layer protocols that should be captured",
	},
	L4ProtosFilterKey: {
		"l4_protos",
		"tcp,udp",
		"list of transport layer protocols that should be captured",
	},
}

func setEnvVarDefaultValue(
	ctxKey CtxKey,
	defaultValue *string,
) {
	if envVar, ok := envVars[ctxKey]; ok {
		envVar.defaultValue = *defaultValue
	}
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
