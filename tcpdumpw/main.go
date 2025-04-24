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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	// _ "net/http/pprof"
	_ "time/tzdata"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/pkg/pcap"
	"github.com/alphadose/haxmap"
	"github.com/go-co-op/gocron/v2"
	"github.com/gofrs/flock"
	"github.com/google/uuid"
	"github.com/wissance/stringFormatter"

	pcapFilter "github.com/GoogleCloudPlatform/pcap-sidecar/tcpdumpw/pkg/filter"
)

func UNUSED(x ...interface{}) {}

var (
	use_cron       = flag.Bool("use_cron", false, "perform packet capture at specific intervals")
	cron_exp       = flag.String("cron_exp", "", "stardard cron expression; i/e: '1 * * * *'")
	timezone       = flag.String("timezone", "UTC", "TimeZone to be used to schedule packet captures")
	duration       = flag.Int("timeout", 0, "perform packet capture during this mount of seconds")
	interval       = flag.Int("interval", 60, "seconds after which tcpdump rotates PCAP files")
	snaplen        = flag.Int("snaplen", 0, "bytes to be captured from each packet")
	extension      = flag.String("extension", "pcap", "extension to be used for tcpdump PCAP files")
	directory      = flag.String("directory", "", "directory where PCAP files will be stored")
	tcp_dump       = flag.Bool("tcpdump", true, "enable JSON PCAP using tcpdump")
	json_dump      = flag.Bool("jsondump", false, "enable JSON PCAP using gopacket")
	json_log       = flag.Bool("jsonlog", false, "enable JSON PCAP to stardard output")
	ordered        = flag.Bool("ordered", false, "write JSON PCAP output as obtained from gopacket")
	conntrack      = flag.Bool("conntrack", false, "enable connection tracking ('ordered' is also enabled)")
	gcp_env        = flag.String("env", "run", "literal ID of the execution environment; any of: run, gae, gke")
	gcp_run        = flag.Bool("run", true, "Cloud Run execution environment")
	gcp_gae        = flag.Bool("gae", false, "App Engine execution environment")
	gcp_gke        = flag.Bool("gke", false, "Kubernetes Engine execution environment")
	pcap_iface     = flag.String("iface", "", "prefix to scan for network interfaces to capture from")
	hc_port        = flag.Uint("hc_port", 12345, "TCP port for health checking")
	filter         = flag.String("filter", pcap.PcapDefaultFilter, "BPF filter to be used for capturing packets")
	l3_protos      = flag.String("l3_protos", "ipv4,ipv6", "FQDNs to be translated into IPs to apply as packet filter")
	l4_protos      = flag.String("l4_protos", "tcp,udp", "FQDNs to be translated into IPs to apply as packet filter")
	hosts          = flag.String("hosts", "", "FQDNs to be translated into IPs to apply as packet filter")
	ports          = flag.String("ports", "", "TCP/UDP ports to be used in any side of the 5-tuple for a packet to be captured")
	ipv4           = flag.String("ipv4", "", "IPv4s or CIDR to be applied to the packet filter")
	ipv6           = flag.String("ipv6", "", "IPv6s or CIDR to be applied to the packet filter")
	tcp_flags      = flag.String("tcp_flags", "", "TCP flags to be set for a segment to be captured")
	ephemerals     = flag.String("ephemerals", "32768,65535", "range of ephemeral ports")
	compat         = flag.Bool("compat", false, "apply filters in Cloud Run gen1 mode")
	rt_env         = flag.String("rt_env", "cloud_run_gen2", "runtime where PCAP sidecar is used")
	pcap_debug     = flag.Bool("debug", false, "enable debug logs")
	pcap_verbosity = flag.String("verbosity", "DEBUG", "PCAP translations verbosity")

	supervisor = flag.String("supervisor", "http://127.0.0.1:23456", "supervisord 'serverurl'")

	no_procs          = flag.String("no_procs", "gcsfuse", "process for which TCP sockets should be excluded")
	no_procs_interval = flag.Uint("no_procs_interval", 15, "how often to reresh sockets owned by pcap-sidecar's processes")
	no_procs_debug    = flag.Bool("no_procs_debug", false, "enable/disable logging of socket discovery for pcap-sidecar's processes")
)

type (
	pcapTask struct {
		engine  pcap.PcapEngine   `json:"-"`
		writers []pcap.PcapWriter `json:"-"`
		iface   string            `json:"-"`
	}

	tcpdumpJob struct {
		ctx   context.Context `json:"-"`
		j     *gocron.Job     `json:"-"`
		Xid   string          `json:"xid,omitempty"`
		Jid   string          `json:"jid,omitempty"`
		Name  string          `json:"name,omitempty"`
		Tags  []string        `json:"-"`
		tasks []*pcapTask     `json:"-"`
		debug bool            `json:"-"`
	}

	jLogLevel string

	jLogEntry struct {
		Severity  jLogLevel        `json:"severity"`
		Message   string           `json:"message"`
		Sidecar   string           `json:"sidecar"`
		Module    string           `json:"module"`
		Job       tcpdumpJob       `json:"job,omitempty"`
		Tags      []string         `json:"tags,omitempty"`
		Timestamp map[string]int64 `json:"timestamp,omitempty"`
	}
)

var (
	projectID         string = os.Getenv("PROJECT_ID")
	ifacePrefixEnvVar string = os.Getenv("PCAP_IFACE_SAFE")
	sidecarEnvVar     string = os.Getenv("APP_SIDECAR")
	moduleEnvVar      string = os.Getenv("PROC_NAME")
	gaeEnvVar         string = os.Getenv("GCP_GAE")
	hcPortEnvVar      string = os.Getenv("PCAP_HC_PORT")
)

var wg sync.WaitGroup

var jid, xid atomic.Value

var jobs *haxmap.Map[string, *tcpdumpJob]

var emptyTcpdumpJob = tcpdumpJob{Jid: uuid.Nil.String()}

var (
	errTcpdumpDisabled  = errors.New("GCS PCAP export disabled")
	errJsondumpDisabled = errors.New("GCS JSON export disabled")
	errJSONLogDisabled  = errors.New("STDOUT JSON log disabled")
	errGaeDisabled      = errors.New("GAE JSON log disabled")
)

var gaeJSONInterval = 0 // disable time based file rotation

const (
	INFO  jLogLevel = "INFO"
	ERROR jLogLevel = "ERROR"
	FATAL jLogLevel = "FATAL"
)

const (
	fileNamePattern      = "%d_%s__%%Y%%m%%dT%%H%%M%%S"
	runFileOutput        = `%s/part__` + fileNamePattern
	gaeFileOutput        = `/var/log/app_engine/app/app_pcap__` + fileNamePattern
	pcapLockFile         = "/var/lock/pcap.lock"
	defaultPcapFilter    = "(tcp or udp or icmp or icmp6) and (ip or ip6)"
	devicesRegexTemplate = "^(?:(?:lo$)|(?:(?:ipvlan-)?%s\\d+.*$))"
)

const (
	anyIfaceName  string = "any"
	anyIfaceIndex int    = int(0)
)

const (
	defaultNoProcsInterval = uint(15)  // 15 seconds
	maxNoProcsInterval     = uint(240) // 4 minutes
)

func parsePcapVerbosity(
	pcapVerbosity *string,
) pcap.PcapVerbosity {
	switch strings.ToUpper(*pcapVerbosity) {
	case "INFO":
		return pcap.VERBOSITY_INFO
	default: // DEBUG
		return pcap.VERBOSITY_DEBUG
	}
}

func jlog(severity jLogLevel, job *tcpdumpJob, message string) {
	now := time.Now()

	j := *job
	// this is safe as only 1 concurrent job execution is ever allowed.
	j.Xid = xid.Load().(uuid.UUID).String()

	entry := &jLogEntry{
		Severity: severity,
		Message:  message,
		Sidecar:  sidecarEnvVar,
		Module:   moduleEnvVar,
		Job:      j,
		Tags:     j.Tags,
		Timestamp: map[string]int64{
			"seconds": now.Unix(),
			"nanos":   int64(now.Nanosecond()),
		},
	}

	jEntry, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", entry)
		return
	}
	io.WriteString(os.Stdout, string(jEntry)+"\n")
}

func afterTcpdump(id uuid.UUID, name string) {
	if job, jobFound := jobs.Get(id.String()); jobFound {
		jlog(INFO, job, "execution complete")
		j := *job.j
		nextRun, _ := j.NextRun()
		jlog(INFO, job, fmt.Sprintf("next execution: %v", nextRun))
	}
	xid.Store(uuid.Nil) // reset execution id
}

func beforeTcpdump(id uuid.UUID, name string) {
	if job, jobFound := jobs.Get(id.String()); jobFound {
		j := *job.j
		lastRun, _ := j.LastRun()
		jlog(INFO, job, fmt.Sprintf("execution started ( last execution: %v )", lastRun))
	}
	xid.Store(uuid.New())
}

func waitJobDone(
	job *tcpdumpJob,
	wg *sync.WaitGroup,
	ctxDoneTS *time.Time,
	deadline *time.Duration,
	stopDeadline chan<- *time.Duration,
) {
	jobDoneSignal := make(chan struct{})

	maxWaitTime := *deadline - time.Since(*ctxDoneTS)
	timer := time.NewTimer(maxWaitTime)

	go func(wg *sync.WaitGroup, ctxDoneTS *time.Time, deadline *time.Duration, signal chan struct{}) {
		jlog(INFO, job, fmt.Sprintf("waiting for PCAP job execution to stop | deadline: %v", *deadline))
		for range job.tasks {
			taskStopDeadline := *deadline - time.Since(*ctxDoneTS)
			stopDeadline <- &taskStopDeadline
		}
		// wait for tasks to gracefully stop
		wg.Wait()
		close(signal)
	}(wg, ctxDoneTS, &maxWaitTime, jobDoneSignal)

	select {
	case <-timer.C:
		jlog(ERROR, job, "timed out waiting for PCAP job execution to stop")
	case <-jobDoneSignal:
		if !timer.Stop() {
			<-timer.C
		}
		jlog(INFO, job, fmt.Sprintf("PCAP job execution stopped | latency: %v", time.Since(*ctxDoneTS)))
	}
}

func start(ctx context.Context, timeout *time.Duration, job *tcpdumpJob) error {
	var cancel context.CancelFunc
	if *timeout > 0*time.Second {
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	stopDeadline := make(chan *time.Duration, len(job.tasks))
	for _, task := range job.tasks {
		wg.Add(1)
		go func(ctx context.Context, wg *sync.WaitGroup, j *tcpdumpJob, t *pcapTask) {
			defer wg.Done()
			// all PCAP engines are context aware
			err := t.engine.Start(ctx, t.writers, stopDeadline)
			if err != nil {
				jlog(INFO, j, fmt.Sprintf("PCAP task execution stopped: %s | %s", t.iface, err.Error()))
			} else {
				jlog(INFO, j, fmt.Sprintf("PCAP task execution stopped: %s", t.iface))
			}
		}(ctx, &wg, job, task)
	}

	// wait for context cancel/timeout
	<-ctx.Done()
	ctxDoneTS := time.Now()

	deadline := 2 * time.Second
	waitJobDone(job, &wg, &ctxDoneTS, &deadline, stopDeadline)
	close(stopDeadline)

	return ctx.Err()
}

func tcpdump(
	timeout time.Duration,
	debug bool,
	verbosity pcap.PcapVerbosity,
) error {
	jobID := jid.Load().(uuid.UUID)
	exeID := xid.Load().(uuid.UUID)

	var job *tcpdumpJob
	var jobFound bool
	if job, jobFound = jobs.Get(jobID.String()); !jobFound {
		message := fmt.Sprintf("job[id:%s] not found", jobID)
		jlog(ERROR, &emptyTcpdumpJob, message)
		return fmt.Errorf(message)
	}

	// enable PCAP tasks with context awareness
	id := fmt.Sprintf("job/%s/exe/%s", jobID.String(), exeID.String())
	ctx := context.WithValue(job.ctx, pcap.PcapContextID, id)
	ctx = context.WithValue(ctx, pcap.PcapContextLogName,
		fmt.Sprintf("projects/%s/pcap/%s", projectID, id))
	ctx = context.WithValue(ctx, pcap.PcapContextDebug, debug)
	ctx = context.WithValue(ctx, pcap.PcapContextVerbosity, verbosity)

	err := start(ctx, &timeout, job)
	if err == context.DeadlineExceeded || err == context.Canceled {
		// if context times out, it is a clean termination
		return nil
	}
	return err
}

func newPcapConfig(
	iface, format, output, extension, filter string,
	filters []pcap.PcapFilterProvider,
	compatFilters pcap.PcapFilters,
	snaplen, interval int,
	compat, debug, ordered, conntrack bool,
	ephemerals *pcap.PcapEphemeralPorts,
	verbosity pcap.PcapVerbosity,
) *pcap.PcapConfig {
	return &pcap.PcapConfig{
		Compat:        compat,
		Debug:         debug,
		Promisc:       true,
		Iface:         iface,
		Snaplen:       snaplen,
		TsType:        "",
		Format:        format,
		Output:        output,
		Extension:     extension,
		Filter:        filter,
		Interval:      interval,
		Ordered:       ordered,
		ConnTrack:     conntrack,
		Filters:       filters,
		CompatFilters: compatFilters,
		Ephemerals:    ephemerals,
		Verbosity:     verbosity,
	}
}

func createTasks(
	ctx context.Context,
	ifacePrefix, timezone, directory, extension, filter *string,
	filters []pcap.PcapFilterProvider,
	compatFilters pcap.PcapFilters,
	snaplen, interval *int,
	compat, debug, tcpdump, jsondump, jsonlog, ordered, conntrack, gcpGAE *bool,
	ephemerals *pcap.PcapEphemeralPorts,
	verbosity pcap.PcapVerbosity,
) []*pcapTask {
	tasks := []*pcapTask{}

	iface := *ifacePrefix
	if iface == "" {
		iface = ifacePrefixEnvVar
	}

	isGAE, err := strconv.ParseBool(gaeEnvVar)
	isGAE = (err == nil && isGAE) || *gcpGAE

	var devices []*pcap.PcapDevice = nil
	if strings.EqualFold(iface, anyIfaceName) {
		devices = []*pcap.PcapDevice{
			{
				NetInterface: &net.Interface{
					Name:  anyIfaceName,
					Index: anyIfaceIndex,
				},
			},
		}
	} else {
		ifaceRegexp := regexp.MustCompile(fmt.Sprintf(devicesRegexTemplate, iface))
		devices, _ = pcap.FindDevicesByRegex(ifaceRegexp)
	}

	for _, device := range devices {

		netIface := device.NetInterface
		iface := netIface.Name
		ifaceAndIndex := fmt.Sprintf("%d/%s", netIface.Index, iface)

		jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configuring PCAP for iface: %s", ifaceAndIndex))

		output := fmt.Sprintf(runFileOutput, *directory, netIface.Index, netIface.Name)

		tcpdumpCfg := newPcapConfig(iface, "pcap", output, *extension, *filter, filters, compatFilters, *snaplen, *interval, *compat, *debug, *ordered, *conntrack, ephemerals, verbosity)
		jsondumpCfg := newPcapConfig(iface, "json", output, "json", *filter, filters, compatFilters, *snaplen, *interval, *compat, *debug, *ordered, *conntrack, ephemerals, verbosity)

		// premature optimization is the root of all evil
		var engineErr, writerErr error = nil, nil
		var tcpdumpEngine, jsondumpEngine pcap.PcapEngine = nil, nil
		var jsondumpWriter, jsonlogWriter, gaejsonWriter pcap.PcapWriter = nil, nil, nil // `tcpdump` does not use custom writers

		if *tcpdump {
			tcpdumpEngine, engineErr = pcap.NewTcpdump(tcpdumpCfg)
		} else {
			engineErr = errTcpdumpDisabled
		}
		if engineErr == nil {
			tasks = append(tasks, &pcapTask{engine: tcpdumpEngine, writers: nil, iface: iface})
			jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured 'tcpdump' for iface: %s", ifaceAndIndex))
		} else if *tcpdump {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("tcpdump GCS writer creation failed: %s (%s)", ifaceAndIndex, engineErr))
		}

		// skip JSON setup if JSON pcap is disabled
		if !*jsondump && !*jsonlog {
			continue
		}

		engineErr = nil
		jsondumpCfg.Ordered = *ordered

		// some form of JSON packet capturing is enabled
		jsondumpEngine, engineErr = pcap.NewPcap(jsondumpCfg)
		if engineErr != nil {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("jsondump task creation failed: %s (%s)", ifaceAndIndex, engineErr))
			continue // abort all JSON setup for this device
		}

		pcapWriters := []pcap.PcapWriter{}

		if *jsondump {
			// writing JSON PCAP file is only enabled if `jsondump` is enabled
			jsondumpWriter, writerErr = pcap.NewPcapWriter(ctx, &ifaceAndIndex, &output, &jsondumpCfg.Extension, timezone, *interval)
		} else {
			jsondumpWriter, writerErr = nil, errJSONLogDisabled
		}
		if writerErr == nil {
			pcapWriters = append(pcapWriters, jsondumpWriter)
			jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured JSON '%s' writer for iface: %s", output, ifaceAndIndex))
		} else if *jsondump {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("jsondump GCS writer creation failed: %s (%s)", ifaceAndIndex, writerErr))
		}

		// add `/dev/stdout` as an additional PCAP writer
		if *jsonlog {
			jsonlogWriter, writerErr = pcap.NewStdoutPcapWriter(ctx, &ifaceAndIndex)
		} else {
			jsonlogWriter, writerErr = nil, errJSONLogDisabled
		}
		if writerErr == nil {
			pcapWriters = append(pcapWriters, jsonlogWriter)
			jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured JSON 'stdout' writer for iface: %s", ifaceAndIndex))
		} else if *jsonlog {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("jsondump stdout writer creation failed: %s (%s)", ifaceAndIndex, writerErr))
		}

		// handle GAE JSON logger
		gaeOutput := ""
		if isGAE {
			gaeOutput = fmt.Sprintf(gaeFileOutput, netIface.Index, netIface.Name)
			gaejsonWriter, writerErr = pcap.NewPcapWriter(ctx, &ifaceAndIndex, &gaeOutput, &jsondumpCfg.Extension, timezone, *interval)
		} else {
			gaejsonWriter, writerErr = nil, errGaeDisabled
		}
		if writerErr == nil {
			pcapWriters = append(pcapWriters, gaejsonWriter)
			jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured GAE JSON '%s' writer for iface: %s", gaeOutput, ifaceAndIndex))
		} else if isGAE {
			jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("jsondump GAE json writer creation failed: %s (%s)", ifaceAndIndex, errGaeDisabled))
		}

		jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("configured 'jsondump' for iface: %s", ifaceAndIndex))
		tasks = append(tasks, &pcapTask{engine: jsondumpEngine, writers: pcapWriters, iface: iface})
	}

	return tasks
}

func startTCPListener(ctx context.Context, port *uint, job *tcpdumpJob, stopChannel chan<- bool) {
	tcpListener, tcpListenerErr := net.Listen("tcp", fmt.Sprintf(":%d", *port))

	if tcpListenerErr != nil {
		jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("failed to start the TCP listener: %v", tcpListenerErr))
		os.Exit(5)
	}

	for {
		select {
		case <-ctx.Done():
			var err error
			if err = tcpListener.Close(); err != nil {
				jlog(ERROR, job, fmt.Sprintf("failed to stop TCP listener: %d | %v", *port, err))
			} else {
				jlog(INFO, job, fmt.Sprintf("stopped TCP listener: %d", *port))
			}
			stopChannel <- (err == nil)
			return

		// accept connections until context is done
		default:
			conn, err := tcpListener.Accept()
			if err == nil {
				conn.Close()
			}
		}
	}
}

func waitDone(job *tcpdumpJob, pcapMutex *flock.Flock, exitSignal *string) {
	// wait for all PCAP tasks to be gracefully stopped
	wg.Wait()

	for _, task := range job.tasks {
		for _, writer := range task.writers {
			writer.Rotate()
			writer.Close()
		}
	}

	// `TCPDUMPW_EXITED` file creation signals `pcapfsn` to start its own termination process
	terminationSignal, err := os.OpenFile(*exitSignal, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)

	if err == nil {
		jlog(INFO, job, fmt.Sprintf("'tcpdumpw' termination signal created: %s", terminationSignal.Name()))
		terminationSignal.Close()
	} else {
		jlog(ERROR, job, fmt.Sprintf("'tcpdumpw' termination signal creation failed: %s | %s", *exitSignal, err.Error()))
	}

	if unlockErr := pcapMutex.Unlock(); unlockErr != nil {
		jlog(ERROR, job, fmt.Sprintf("failed to release PCAP lock file: %v", unlockErr))
	} else {
		jlog(INFO, job, fmt.Sprintf("released PCAP lock file: %s", pcapLockFile))
	}
}

func appendFilter(
	ctx context.Context,
	filters []pcap.PcapFilterProvider,
	compatFilters pcap.PcapFilters,
	rawFilter *string,
	factory pcapFilter.PcapFilterProviderFactory,
) []pcap.PcapFilterProvider {
	select {
	case <-ctx.Done():
		return filters
	default:
		if *rawFilter == "" ||
			strings.EqualFold(*rawFilter, "ALL") ||
			strings.EqualFold(*rawFilter, "ANY") {
			return filters
		}
	}

	filter := factory(rawFilter, compatFilters)
	filters = append(filters, filter)
	jlog(INFO, &emptyTcpdumpJob, stringFormatter.Format("using filter: {0}", filter.String()))

	return filters
}

func parseEphemeralPorts(ephemerals *string) *pcap.PcapEphemeralPorts {
	// default ephemeral ports range
	ephemeralPortRange := &pcap.PcapEphemeralPorts{
		Min: pcap.PCAP_MIN_EPHEMERAL_PORT,
		Max: pcap.PCAP_MAX_EPHEMERAL_PORT,
	}

	if *ephemerals == "" {
		return ephemeralPortRange
	}

	ephemeralPorts := strings.SplitN(*ephemerals, ",", 2)

	if len(ephemeralPorts) != 2 {
		return ephemeralPortRange
	}

	for i, valueStr := range ephemeralPorts {
		if value, err := strconv.ParseUint(valueStr, 10, 16); err != nil && value >= 0x0400 && value <= 0xFFFF {
			// see: https://datatracker.ietf.org/doc/html/rfc6056#page-5
			// a valid `ephemeral port` must be within RFC 6056 range: [1024/0x4000,65535/0xFFFF]
			port := uint16(value)
			if i == 0 && port < ephemeralPortRange.Max {
				ephemeralPortRange.Min = uint16(value)
			} else if port > ephemeralPortRange.Min {
				ephemeralPortRange.Max = uint16(value)
			}
		}
	}

	return ephemeralPortRange
}

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if r := recover(); r != nil {
			jlog(FATAL, &emptyTcpdumpJob, stringFormatter.Format("panic: {0}", r))
			fmt.Fprintln(os.Stderr, string(debug.Stack()))
		}
	}()

	jid.Store(uuid.Nil)
	xid.Store(uuid.Nil)

	if *compat || strings.EqualFold(*filter, "DISABLED") {
		*filter = ""
	} else {
		*filter = strings.TrimSpace(*filter)
	}

	compatFilters := pcap.NewPcapFilters()
	filters := []pcap.PcapFilterProvider{}

	if *compat || *filter == "" {
		// if complex filter is empty, build it using 'Simple PCAP filters'
		filters = appendFilter(ctx, filters, compatFilters, l3_protos, pcapFilter.NewL3ProtoFilterProvider)
		filters = appendFilter(ctx, filters, compatFilters, l4_protos, pcapFilter.NewL4ProtoFilterProvider)
		filters = appendFilter(ctx, filters, compatFilters, ports, pcapFilter.NewPortsFilterProvider)
		filters = appendFilter(ctx, filters, compatFilters, tcp_flags, pcapFilter.NewTCPFlagsFilterProvider)

		ipFilterProvider := pcapFilter.NewIPFilterProvider(ipv4, ipv6, hosts, compatFilters)
		if _, ok := ipFilterProvider.Get(ctx); ok {
			jlog(INFO, &emptyTcpdumpJob, stringFormatter.Format("using filter: {0}", ipFilterProvider.String()))
			filters = append(filters, ipFilterProvider)
		}

		if len(filters) == 0 && !*compat {
			// if no simple filters are available:
			//   - use a default 'catch-all' filter
			//   		- but only if compat mode is disabled
			*filter = string(pcap.PcapDefaultFilter)
		}
	}

	noProcsInterval := *no_procs_interval
	if noProcsInterval > maxNoProcsInterval {
		noProcsInterval = maxNoProcsInterval
	}
	processFilter := pcapFilter.NewProcessFilterProvider(supervisor, no_procs, uint8(noProcsInterval), *no_procs_debug, compatFilters)
	// initialize `ProcessFilterProvider` for its side effects
	filters = append(filters, processFilter.Initialize(ctx))

	ephemeralPortRange := parseEphemeralPorts(ephemerals)

	pcapVerbosity := parsePcapVerbosity(pcap_verbosity)

	tasks := createTasks(ctx, pcap_iface, timezone, directory, extension,
		filter, filters, compatFilters, snaplen, interval, compat, pcap_debug, tcp_dump,
		json_dump, json_log, ordered, conntrack, gcp_gae, ephemeralPortRange, pcapVerbosity)

	if len(tasks) == 0 {
		jlog(FATAL, &emptyTcpdumpJob, "no PCAP tasks available")
		os.Exit(1)
	}

	pcapMutex := flock.New(pcapLockFile)
	if locked, lockErr := pcapMutex.TryLock(); !locked || lockErr != nil {
		jlog(FATAL, &emptyTcpdumpJob, fmt.Sprintf("failed to acquire PCAP lock | locked: %t | %v", locked, lockErr))
		os.Exit(2)
	}

	jobs = haxmap.New[string, *tcpdumpJob]()

	timeout := time.Duration(*duration) * time.Second
	jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("parsed timeout: %v", timeout))

	// the file to be created when `tcpdumpw` exists
	exitSignal := fmt.Sprintf("%s/TCPDUMPW_EXITED", *directory)

	// receives status of TCP listener termination: `true` means successful
	tcpStopChannel := make(chan bool, 1)

	// create empty job: used if CRON is not enabled
	job := &tcpdumpJob{
		Jid:   uuid.Nil.String(),
		tasks: tasks,
		debug: *pcap_debug,
	}

	jlog(INFO, job, fmt.Sprintf("acquired PCAP lock: %s", pcapLockFile))

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		signal := <-signals
		jlog(INFO, job, fmt.Sprintf("signaled: %v", signal))
		cancel()
		// unblock TCP listener; next iteration will find `ctx` done
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", *hc_port))
		if err == nil {
			conn.Close()
		}
	}()

	// Skip scheduling, execute `tcpdump` immediately
	if !*use_cron {
		id := uuid.New().String()
		ctx = context.WithValue(ctx, pcap.PcapContextID, id)
		logName := fmt.Sprintf("projects/%s/pcaps/%s", os.Getenv("PROJECT_ID"), id)
		ctx = context.WithValue(ctx, pcap.PcapContextLogName, logName)
		ctx = context.WithValue(ctx, pcap.PcapContextDebug, *pcap_debug)
		ctx = context.WithValue(ctx, pcap.PcapContextVerbosity, pcapVerbosity)
		// start the TCP listener for health checks
		go startTCPListener(ctx, hc_port, job, tcpStopChannel)
		start(ctx, &timeout, job)
		waitDone(job, pcapMutex, &exitSignal)
		<-tcpStopChannel
		close(tcpStopChannel)
		return
	}

	// The `timezone` to be used when scheduling `tcpdump` cron jobs
	location, err := time.LoadLocation(*timezone)
	if err != nil {
		*timezone = "UTC"
		location = time.UTC
		jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("could not load timezone '%s': %v", *timezone, err))
	}
	jlog(INFO, &emptyTcpdumpJob, fmt.Sprintf("parsed timezone: %v", location))

	// Create a scheduler using the requested timezone.
	// no more than 1 packet capturing job (all its tasks) should ever be executed.
	s, err := gocron.NewScheduler(
		gocron.WithLimitConcurrentJobs(1, gocron.LimitModeReschedule),
		gocron.WithLocation(location),
		gocron.WithGlobalJobOptions(
			gocron.WithTags(
				os.Getenv("PROJECT_ID"),
				os.Getenv("APP_SERVICE"),
				os.Getenv("GCP_REGION"),
				os.Getenv("APP_REVISION"),
				os.Getenv("INSTANCE_ID"),
			),
		),
	)
	if err != nil {
		jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("failed to create scheduler: %v", err))
		os.Exit(3)
	}

	// Use the provided `cron` expression ro schedule the packet capturing job
	j, err := s.NewJob(
		gocron.CronJob(fmt.Sprintf("TZ=%s %s", *timezone, *cron_exp), true),
		gocron.NewTask(tcpdump, timeout, *pcap_debug, pcapVerbosity),
		gocron.WithName("tcpdump"),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
		gocron.WithEventListeners(
			gocron.AfterJobRuns(afterTcpdump),
			gocron.BeforeJobRuns(beforeTcpdump),
		),
	)
	if err != nil {
		jlog(ERROR, &emptyTcpdumpJob, fmt.Sprintf("failed to create scheduled job: %v", err))
		s.Shutdown()
		os.Exit(4)
	}

	jid.Store(j.ID())

	// redefine default `job` with the scheduled one
	job = &tcpdumpJob{
		ctx:   ctx,
		tasks: tasks,
		Jid:   j.ID().String(),
		Name:  j.Name(),
		Tags:  j.Tags(),
		j:     &j,
	}
	jobs.Set(job.Jid, job)
	jlog(INFO, job, "scheduled job")

	// Start the packet capturing scheduler
	s.Start()

	nextRun, _ := j.NextRun()
	jlog(INFO, job, fmt.Sprintf("next execution: %v", nextRun))

	// start the TCP listener for health checks
	go startTCPListener(ctx, hc_port, job, tcpStopChannel)

	// Block main goroutine until a signal is received
	<-ctx.Done()

	s.StopJobs()
	s.RemoveJob(j.ID())
	s.Shutdown()
	jlog(INFO, job, "scheduler terminated")

	waitDone(job, pcapMutex, &exitSignal)
	<-tcpStopChannel
	close(tcpStopChannel)
}
