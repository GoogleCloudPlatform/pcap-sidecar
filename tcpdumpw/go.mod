module github.com/GoogleCloudPlatform/pcap-sidecar/tcpdumpw

go 1.22.4

require github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli v0.0.0

require (
	github.com/alphadose/haxmap v1.4.0
	github.com/deckarep/golang-set/v2 v2.6.0
	github.com/go-co-op/gocron/v2 v2.5.0
	github.com/gofrs/flock v0.12.1
	github.com/google/uuid v1.6.0
	github.com/wissance/stringFormatter v1.2.0
)

require (
	atomicgo.dev/cursor v0.2.0 // indirect
	atomicgo.dev/keyboard v0.2.9 // indirect
	atomicgo.dev/schedule v0.1.0 // indirect
	dario.cat/mergo v1.0.0 // indirect
	github.com/Jeffail/gabs/v2 v2.7.0 // indirect
	github.com/containerd/console v1.0.3 // indirect
	github.com/easyCZ/logrotate v0.3.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/itchyny/timefmt-go v0.1.6 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/lithammer/fuzzysearch v1.1.8 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/panjf2000/ants/v2 v2.10.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pterm/pterm v0.12.79 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/segmentio/fasthash v1.0.3 // indirect
	github.com/tejzpr/ordered-concurrently/v3 v3.0.1 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/zhangyunhao116/fastrand v0.3.0 // indirect
	github.com/zhangyunhao116/skipmap v0.10.1 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/term v0.27.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli => ../pcap-cli
