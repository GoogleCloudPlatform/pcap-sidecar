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
	"io"
	"os"
	"strings"

	"github.com/google/go-jsonnet"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

var (
	Build   string
	Version string
)

func newConfigFile(
	jsonConfigPath *string,
) (*os.File, error) {
	return os.OpenFile(*jsonConfigPath,
		os.O_RDWR|os.O_CREATE|os.O_EXCL,
		0o666,
	)
}

func newConfigReader(
	config *string,
) io.Reader {
	return strings.NewReader(*config)
}

func writeConfig(
	jsonConfig *string,
	configFile *os.File,
) error {
	config := newConfigReader(jsonConfig)
	if _, err := io.
		Copy(configFile, config); err != nil {
		return err
	}
	return nil
}

func saveConfig(
	configPath *string,
	jsonConfig *string,
) error {
	if json, err := newConfigFile(configPath); err == nil {
		defer json.Close()
		return writeConfig(jsonConfig, json)
	} else {
		return err
	}
}

func newVM(
	flags *pflag.FlagSet,
) *jsonnet.VM {
	vm := jsonnet.MakeVM()
	return loadFlagVariables(
		// flags override environment variables
		loadEnvironmentVariables(vm),
		flags)
}

func CreateJSON(
	templatePath *string,
	configPath *string,
	flags *pflag.FlagSet,
) error {
	if cfg, err := newVM(flags).
		EvaluateFile(*templatePath); err == nil {
		return saveConfig(configPath, &cfg)
	} else {
		return err
	}
}

func LoadJSON(
	configFile string,
	separator string,
) (*koanf.Koanf, error) {
	k := koanf.New(separator)
	if err := k.Load(
		file.Provider(configFile),
		json.Parser(),
	); err != nil {
		return nil, err
	}
	return k, nil
}
