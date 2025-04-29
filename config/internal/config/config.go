package config

import (
	"io"
	"os"
	"strings"

	"github.com/google/go-jsonnet"
	"github.com/spf13/pflag"
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
	if _, err := io.Copy(configFile, config); err == nil {
		return configFile.Close()
	} else {
		return err
	}
}

func saveConfig(
	configPath *string,
	jsonConfig *string,
) error {
	if json, err := newConfigFile(configPath); err == nil {
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
