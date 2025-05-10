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
	"errors"
	"log"
	"strconv"
	"strings"

	"github.com/google/go-jsonnet"
	"github.com/spf13/pflag"
	sf "github.com/wissance/stringFormatter"
)

const (
	flagVarPrefix   = CtxKeyPrefix
	flagVarTemplate = "{0}_{1}"
)

func newFlagVarKey(
	flag *pflag.Flag,
) string {
	name := strings.ToUpper(flag.Name)
	return sf.Format(extVarTemplate, name)
}

func newFlagVarName(
	ev *variable,
) string {
	return sf.Format(flagVarTemplate, flagVarPrefix, ev.name)
}

func setFlagVar(
	vm *jsonnet.VM,
	flag *pflag.Flag,
) {
	key := newFlagVarKey(flag)
	value := flag.DefValue
	if flag.Changed {
		value = flag.Value.String()
	}
	vm.ExtVar(key, value)
}

func loadFlagVariables(
	vm *jsonnet.VM,
	flags *pflag.FlagSet,
) *jsonnet.VM {
	flags.Visit(func(
		flag *pflag.Flag,
	) {
		setFlagVar(vm, flag)
	})
	return vm
}

func registerBooleanFlag(
	flags *pflag.FlagSet,
	name *string,
	cv *ctxVar,
	ev *variable,
) error {
	if value, err := strconv.
		ParseBool(ev.defaultValue); err == nil {
		flags.Bool(*name, value, ev.defaultValue)
		return nil
	} else {
		return errors.Join(errors.New(
			sf.Format("invalid boolean value: {0}", ev.defaultValue),
		), err)
	}
}

func registerFlag(
	flags *pflag.FlagSet,
	cv *ctxVar,
	ev *variable,
) {
	flags.String(
		newFlagVarName(ev),
		ev.defaultValue,
		ev.description,
	)
}

func logFlagRegistrationError(
	v *variable,
	err error,
) {
	log.Println(
		sf.Format("failed to parse flag '{0}': {1}", v.name, err.Error()),
	)
}

func RegisterFlags(
	flags *pflag.FlagSet,
) {
	for k, ev := range envVars {
		if cv, ok := CtxVars[k]; ok {
			registerFlag(flags, cv, ev)
		}
	}
}
