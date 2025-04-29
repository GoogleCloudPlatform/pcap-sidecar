package config

import (
	"context"

	"github.com/GoogleCloudPlatform/pcap-sidecar/config/internal/config"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type (
	PcapVerbosity string

	PcapConfig struct {
		Debug     bool
		Verbosity PcapVerbosity
	}
)

const (
	PCAP_VERBOSITY_INFO  = PcapVerbosity("INFO")
	PCAP_VERBOSITY_DEBUG = PcapVerbosity("DEBUG")
)

func LoadJSON(
	ctx context.Context,
	configFile string,
) (context.Context, error) {
	k := koanf.New(".")
	if err := k.Load(
		file.Provider(configFile),
		json.Parser(),
	); err == nil {
		return config.LoadContext(ctx, k), nil
	} else {
		return ctx, err
	}
}
