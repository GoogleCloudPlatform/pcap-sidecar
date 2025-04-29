package main

import (
	"flag"
	"log"

	cfg "github.com/GoogleCloudPlatform/pcap-sidecar/config/internal/config"
	sf "github.com/wissance/stringFormatter"
)

var (
	template = flag.String("template", "/pcap.jsonnet", "absolute path of the PCAP config file template")
	config   = flag.String("config", "/pcap.json", "absolute path where the PCAP config file should be generated")
)

func main() {
	flag.Parse()
	if err := cfg.CreateJSON(template, config); err != nil {
		log.Fatalln(
			sf.Format("failed to create config file: {0}", err.Error()),
		)
	}
	// other pcap modules can use the generated config file via `config.LoadJSON`
	log.Println(
		sf.Format("config file created at: {0}", *config),
	)
	// TODO: move ALL cmd args from all modules to this one and merge them with env vars using:
	//  - https://pkg.go.dev/github.com/knadh/koanf/providers/posflag
	//  - https://github.com/knadh/koanf?tab=readme-ov-file#reading-from-command-line
}
