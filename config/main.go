package main

import (
	"log"
	"os"

	"github.com/GoogleCloudPlatform/pcap-sidecar/config/internal/config"
	cfg "github.com/GoogleCloudPlatform/pcap-sidecar/config/internal/config"
	"github.com/spf13/pflag"
	flag "github.com/spf13/pflag"
	sf "github.com/wissance/stringFormatter"
)

func registerFlags(
	flags *pflag.FlagSet,
) *pflag.FlagSet {
	flags.String("template", "/pcap.jsonnet", "absolute path of the PCAP config file template")
	flags.String("config", "/pcap.json", "absolute path where the PCAP config file should be generated")

	return flags
}

func main() {
	flags := flag.NewFlagSet("pcap", flag.ContinueOnError)

	config.RegisterFlags(registerFlags(flags))

	flags.Parse(os.Args[1:])

	template, _ := flags.GetString("template")
	config, _ := flags.GetString("config")

	if err := cfg.CreateJSON(&template, &config, flags); err != nil {
		log.Fatalln(
			sf.Format("failed to create config file: {0}", err.Error()),
		)
	}

	// other pcap modules can use the generated config file via `config.LoadJSON`
	log.Println(
		sf.Format("config file created at: {0}", config),
	)

	// TODO: move ALL cmd args from all modules to this one and merge them with env vars using:
	//  - https://pkg.go.dev/github.com/knadh/koanf/providers/posflag
	//  - https://github.com/knadh/koanf?tab=readme-ov-file#reading-from-command-line
}
