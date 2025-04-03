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
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/avast/retry-go/v4"
	"github.com/fsnotify/fsnotify"
	"github.com/gofrs/flock"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type (
	pcapEvent string

	fsnEvent struct {
		Source string `json:"source,omitempty"`
		Target string `json:"target,omitempty"`
		Bytes  int64  `json:"bytes,omitempty"`
	}
)

const (
	PCAP_FSNINI pcapEvent = "PCAP_FSNINI"
	PCAP_FSNEND pcapEvent = "PCAP_FSNEND"
	PCAP_FSNERR pcapEvent = "PCAP_FSNERR"
	PCAP_CREATE pcapEvent = "PCAP_CREATE"
	PCAP_EXPORT pcapEvent = "PCAP_EXPORT"
	PCAP_QUEUED pcapEvent = "PCAP_QUEUED"
	PCAP_OSWMEM pcapEvent = "PCAP_OSWMEM"
	PCAP_SIGNAL pcapEvent = "PCAP_SIGNAL"
	PCAP_FSLOCK pcapEvent = "PCAP_FSLOCK"
)

const (
	cgroupMemoryUtilization       = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
	dockerCgroupMemoryUtilization = "/sys/fs/cgroup/memory.current"
	procSysVmDropCaches           = "/proc/sys/vm/drop_caches"
	pcapLockFile                  = "/var/lock/pcap.lock"
)

var (
	src_dir       = flag.String("src_dir", "/pcap-tmp", "pcaps source directory")
	gcs_dir       = flag.String("gcs_dir", "/pcap", "pcaps destination directory")
	pcap_ext      = flag.String("pcap_ext", "pcap", "pcap files extension")
	gzip_pcaps    = flag.Bool("gzip", false, "compress pcap files")
	gcp_env       = flag.String("env", "run", "literal ID of the execution environment; any of: run, gae, gke")
	gcp_run       = flag.Bool("run", true, "Cloud Run execution environment")
	gcp_gae       = flag.Bool("gae", false, "App Engine execution environment")
	gcp_gke       = flag.Bool("gke", false, "Kubernetes Engine execution environment")
	interval      = flag.Uint("interval", 60, "seconds after which tcpdump rotates PCAP files")
	retries_max   = flag.Uint("retries_max", 5, "times a failed copy-to-GCS operation should be retried")
	retries_delay = flag.Uint("retries_delay", 2, "seconds between retries for copy-to-GCS operations")
	compat        = flag.Bool("compat", false, "apply filters in Cloud Run gen1 mode")
	rt_env        = flag.String("rt_env", "cloud_run_gen2", "runtime where PCAP sidecar is used")
	pcap_debug    = flag.Bool("debug", false, "enable debug logs")
)

var (
	projectID  string = os.Getenv("PROJECT_ID")
	gcpRegion  string = os.Getenv("GCP_REGION")
	service    string = os.Getenv("APP_SERVICE")
	version    string = os.Getenv("APP_VERSION")
	sidecar    string = os.Getenv("APP_SIDECAR")
	instanceID string = os.Getenv("INSTANCE_ID")
	module     string = os.Getenv("PROC_NAME")
	gcpGAE     string = os.Getenv("PCAP_GAE")
)

var tags []string = []string{projectID, service, gcpRegion, version, instanceID}

var logger, _ = zap.Config{
	Encoding:    "json",
	Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
	OutputPaths: []string{"stdout"},
	EncoderConfig: zapcore.EncoderConfig{
		MessageKey:  "message",
		LevelKey:    "severity",
		EncodeLevel: zapcore.CapitalLevelEncoder,
		TimeKey:     "time",
		EncodeTime:  zapcore.ISO8601TimeEncoder,
	},
}.Build()
var sugar = logger.Sugar()

var (
	counters *haxmap.Map[string, *atomic.Uint64]
	lastPcap *haxmap.Map[string, string]
)

var isActive atomic.Bool

func logEvent(
	level zapcore.Level,
	message string,
	event pcapEvent,
	data map[string]interface{},
	err error,
) {
	now := time.Now()
	_data := map[string]interface{}{
		"event": event,
	}
	if err != nil {
		_data["error"] = err.Error()
	}
	if len(data) > 0 {
		maps.Copy(_data, data)
	}
	sugar.Logw(level, message, "sidecar", sidecar, "module", module, "tags", tags, "data", _data,
		"timestamp", map[string]interface{}{"seconds": now.Unix(), "nanos": now.Nanosecond()})
}

func logFsEvent(level zapcore.Level, message string, event pcapEvent, src, tgt string, by int64, err error) {
	data := map[string]interface{}{
		"fs": fsnEvent{
			Source: src,
			Target: tgt,
			Bytes:  by,
		},
	}
	logEvent(level, message, event, data, err)
}

func movePcapToGcs(
	ctx context.Context,
	srcPcap *string,
	dstDir *string,
	compress, delete bool,
) (*string, *int64, error) {
	// Define name of destination PCAP file, prefixed by its ordinal and destination directory
	pcapName := filepath.Base(*srcPcap)
	tgtPcap := filepath.Join(*dstDir, pcapName)
	// If compressing PCAP files is enabled, add `gz` siffux to the destination PCAP file path
	if compress {
		tgtPcap = fmt.Sprintf("%s.gz", tgtPcap)
	}

	var (
		err                   error
		inputPcap, outputPcap *os.File
		pcapBytes             int64 = 0
	)

	// Open source PCAP file: the one thas is being moved to the destination directory
	inputPcap, err = os.OpenFile(*srcPcap, os.O_RDONLY|os.O_EXCL, 0)
	if err != nil {
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("failed to OPEN file %s", *srcPcap), PCAP_EXPORT, *srcPcap, tgtPcap, 0, err)
		return &tgtPcap, &pcapBytes, fmt.Errorf("failed to open source pcap: %s", *srcPcap)
	}
	// logFsEvent(zapcore.InfoLevel, fmt.Sprintf("OPENED: %s", *srcPcap), PCAP_EXPORT, *srcPcap, tgtPcap, 0)

	// Create destination PCAP file ( export to the GCS Bucket )
	outputPcap, err = os.OpenFile(tgtPcap, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("failed to CREATE file: %s", tgtPcap), PCAP_EXPORT, *srcPcap, tgtPcap, 0, err)
		return &tgtPcap, &pcapBytes, fmt.Errorf("failed to create destination pcap: %s", tgtPcap)
	}
	// logFsEvent(zapcore.InfoLevel, fmt.Sprintf("CREATED: %s", tgtPcap), PCAP_EXPORT, *srcPcap, tgtPcap, 0)

	pcapBytes, err = retry.DoWithData(func() (int64, error) {
		// Copy source PCAP into destination PCAP, compressing destination PCAP is optional
		if compress {
			gzipPcap := gzip.NewWriter(outputPcap)
			defer gzipPcap.Close() // this is still required; `Close()` on parent `Writer` does not trigger `Close()` at `gzip`
			defer gzipPcap.Flush()
			return io.Copy(gzipPcap, inputPcap)
		} else {
			return io.Copy(outputPcap, inputPcap)
		}
	},
		retry.Context(ctx),
		retry.Attempts(*retries_max),
		retry.Delay(time.Duration(*retries_delay)*time.Second),
		retry.DelayType(retry.FixedDelay),
		retry.OnRetry(func(n uint, err error) {
			logFsEvent(zapcore.WarnLevel,
				fmt.Sprintf("failed to COPY file at attempt %d: %v", n+1, *srcPcap), PCAP_EXPORT, *srcPcap, tgtPcap, 0, err)
		}))

	inputPcap.Close()
	outputPcap.Close()

	if err != nil {
		logFsEvent(zapcore.ErrorLevel,
			fmt.Sprintf("failed to COPY file: %v", *srcPcap), PCAP_EXPORT, *srcPcap, tgtPcap, 0, err)
		return &tgtPcap, &pcapBytes,
			fmt.Errorf("failed to copy '%s' into '%s'", *srcPcap, tgtPcap)
	}
	logFsEvent(zapcore.InfoLevel,
		fmt.Sprintf("COPIED: %s", *srcPcap), PCAP_EXPORT, *srcPcap, tgtPcap, pcapBytes, nil)

	if delete {
		// remove the source PCAP file if copying is sucessful
		err = os.Remove(*srcPcap)
		if err != nil {
			logFsEvent(zapcore.ErrorLevel,
				fmt.Sprintf("failed to DELETE file: %s", *srcPcap), PCAP_EXPORT, *srcPcap, tgtPcap, pcapBytes, err)
		} else {
			logFsEvent(zapcore.InfoLevel,
				fmt.Sprintf("DELETED: %s", *srcPcap), PCAP_EXPORT, *srcPcap, tgtPcap, pcapBytes, nil)
		}
	}

	return &tgtPcap, &pcapBytes, nil
}

func getCurrentMemoryUtilization(isGAE bool) (uint64, error) {
	var err error
	var memoryUtilizationFilePath string

	if isGAE {
		memoryUtilizationFilePath = dockerCgroupMemoryUtilization
	} else {
		memoryUtilizationFilePath = cgroupMemoryUtilization
	}

	memoryUtilizationFile, err := os.OpenFile(memoryUtilizationFilePath, os.O_RDONLY, 0o444 /* -r--r--r-- */)
	if err != nil {
		return 0, err
	}

	var memoryUtilization int
	_, err = fmt.Fscanf(memoryUtilizationFile, "%d\n", &memoryUtilization)
	if err != nil {
		if err == io.EOF {
			return uint64(memoryUtilization), nil
		}
		return 0, err
	}
	return uint64(memoryUtilization), nil
}

func flushBuffers() (int, error) {
	cmd := exec.Command("sync")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
	// see: https://www.kernel.org/doc/Documentation/sysctl/vm.txt
	fd, err := os.OpenFile(procSysVmDropCaches,
		os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o200 /* --w------- */)
	if err != nil {
		return 0, err
	}
	defer fd.Close()
	return fmt.Fprintln(fd, "3")
}

func exportPcapFile(
	ctx context.Context,
	wg *sync.WaitGroup,
	pcapDotExt *regexp.Regexp,
	srcFile *string,
	compress, delete, flush bool,
) bool {
	defer wg.Done()

	if flush && isActive.Load() {
		return false
	}

	rMatch := pcapDotExt.FindStringSubmatch(*srcFile)
	if len(rMatch) == 0 || len(rMatch) < 3 {
		return false
	}

	iface := fmt.Sprintf("%s:%s", rMatch[1], rMatch[2])
	ext := rMatch[3]
	key := strings.Join(rMatch[1:], "/")

	lastPcapFileName, loaded := lastPcap.Get(key)

	// `flushing` is the only thread-safe PCAP export operation.
	if flush {
		logFsEvent(zapcore.InfoLevel,
			fmt.Sprintf("flushing PCAP file: [%s] (%s/%s) %s", key, ext, iface, *srcFile), PCAP_EXPORT, *srcFile, "" /* target PCAP file */, 0, nil)
		tgtPcapFileName, pcapBytes, moveErr := movePcapToGcs(ctx, srcFile, gcs_dir, compress, delete)
		if moveErr != nil {
			logFsEvent(zapcore.ErrorLevel,
				fmt.Sprintf("failed to flush PCAP file: (%s/%s) %s", ext, iface, *srcFile), PCAP_FSNERR, *srcFile, *tgtPcapFileName /* target PCAP file */, 0, moveErr)
			return false
		}
		logFsEvent(zapcore.InfoLevel,
			fmt.Sprintf("flushed PCAP file: (%s/%s) %s", ext, iface, *tgtPcapFileName), PCAP_EXPORT, *srcFile, *tgtPcapFileName, *pcapBytes, nil)
		return true
	}

	counter, _ := counters.GetOrCompute(key,
		func() *atomic.Uint64 {
			return new(atomic.Uint64)
		})
	iteration := (*counter).Add(1)

	logFsEvent(zapcore.InfoLevel,
		fmt.Sprintf("new PCAP file detected: [%s] (%s/%s/%d) %s", key, ext, iface, iteration, *srcFile), PCAP_CREATE, *srcFile, "" /* target PCAP file */, 0, nil)

	// Skip 1st PCAP, start moving PCAPs as soon as TCPDUMP rolls over into the 2nd file.
	// The outcome of this implementation is that the directory in which TCPDUMP writes
	// PCAP files will contain at most 2 files, the current one, and the one being moved
	// into the destination directory ( `gcs_dir` ). Otherwise it will contain all PCAPs.
	if iteration == 1 {
		lastPcap.Set(key, *srcFile)
		return false
	}

	if !loaded || lastPcapFileName == "" {
		lastPcap.Set(key, *srcFile)
		logFsEvent(zapcore.ErrorLevel, fmt.Sprintf("PCAP file [%s] (%s/%s/%d) unavailable", key, ext, iface, iteration), PCAP_EXPORT, "" /* source PCAP File */, *srcFile /* target PCAP file */, 0, nil)
		return false
	}

	logFsEvent(zapcore.InfoLevel,
		fmt.Sprintf("exporting PCAP file: (%s/%s/%d) %s", ext, iface, iteration, *srcFile), PCAP_EXPORT, lastPcapFileName, "" /* target PCAP file */, 0, nil)
	// move non-current PCAP file into `gcs_dir` which means that:
	// 1. the GCS Bucket should have already been mounted
	// 2. the directory hierarchy to store PCAP files already exists
	tgtPcapFileName, pcapBytes, moveErr := movePcapToGcs(ctx, &lastPcapFileName, gcs_dir, compress, delete)
	if moveErr == nil {
		logFsEvent(zapcore.InfoLevel,
			fmt.Sprintf("exported PCAP file: (%s/%s/%d) %s", ext, iface, iteration, *tgtPcapFileName), PCAP_EXPORT, lastPcapFileName, *tgtPcapFileName, *pcapBytes, nil)
	} else {
		logFsEvent(zapcore.ErrorLevel,
			fmt.Sprintf("failed to export PCAP file: (%s/%s/%d) %s", ext, iface, iteration, lastPcapFileName), PCAP_EXPORT, lastPcapFileName, *tgtPcapFileName /* target PCAP file */, 0, moveErr)
	}

	// current PCAP file is the next one to be moved
	if !lastPcap.CompareAndSwap(key, lastPcapFileName, *srcFile) {
		logFsEvent(zapcore.ErrorLevel,
			fmt.Sprintf("leaked PCAP file: [%s] (%s/%s/%d) %s", key, ext, iface, iteration, *srcFile), PCAP_FSNERR, *srcFile, "" /* target PCAP file */, 0, nil)
		lastPcap.Set(key, *srcFile)
	}
	logFsEvent(zapcore.InfoLevel,
		fmt.Sprintf("queued PCAP file: (%s/%s/%d) %s", ext, iface, iteration, *srcFile), PCAP_QUEUED, *srcFile, "" /* target PCAP file */, 0, nil)

	return moveErr == nil
}

func flushSrcDir(
	ctx context.Context,
	wg *sync.WaitGroup,
	pcapDotExt *regexp.Regexp,
	sync, compress, delete bool,
	validator func(fs.FileInfo) bool,
) uint32 {
	pendingPcapFiles := uint32(0)
	if sync {
		flushBuffers()
	}
	filepath.Walk(*src_dir, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if err != nil {
			logEvent(zapcore.ErrorLevel, "failed to flush PCAP files", PCAP_FSNERR, nil, err)
			return nil
		}
		if validator(info) {
			pendingPcapFiles += 1
			wg.Add(1)
			go exportPcapFile(ctx, wg, pcapDotExt, &path, compress, delete, true /* flush */)
		}
		return nil
	})
	return pendingPcapFiles
}

func main() {
	isActive.Store(false)

	flag.Parse()

	defer logger.Sync()

	counters = haxmap.New[string, *atomic.Uint64]()
	lastPcap = haxmap.New[string, string]()

	isGAE, isGAEerr := strconv.ParseBool(gcpGAE)
	isGAE = (isGAEerr == nil && isGAE) || *gcp_gae

	ext := strings.Join(strings.Split(*pcap_ext, ","), "|")
	pcapDotExt := regexp.MustCompile(`^` + *src_dir + `/part__(\d+?)_(.+?)__\d{8}T\d{6}\.(` + ext + `)$`)
	tcpdumpwExitSignal := regexp.MustCompile(`^` + *src_dir + `/TCPDUMPW_EXITED$`)

	// must match the value of `PCAP_ROTATE_SECS`
	watchdogInterval := time.Duration(*interval) * time.Second

	args := map[string]interface{}{
		"src_dir":  *src_dir,
		"gcs_dir":  *gcs_dir,
		"pcap_ext": pcapDotExt.String(),
		"gzip":     *gzip_pcaps,
		"interval": watchdogInterval.String(),
	}

	logEvent(zapcore.InfoLevel, "starting PCAP filesystem watcher", PCAP_FSNINI, args, nil)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)

	// Create new watcher.
	watcher, err := fsnotify.NewBufferedWatcher(100)
	if err != nil {
		logEvent(zapcore.FatalLevel, fmt.Sprintf("failed to create FS watcher: %v", err), PCAP_FSNINI, nil, nil)
		os.Exit(1)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	// Watch the PCAP files source directory for FS events.
	if isActive.CompareAndSwap(false, true) {
		if err = watcher.Add(*src_dir); err != nil {
			logEvent(zapcore.ErrorLevel, fmt.Sprintf("failed to watch directory '%s': %v", *src_dir, err), PCAP_FSNERR, nil, err)
			isActive.Store(false)
		}
	}

	ticker := time.NewTicker(watchdogInterval)

	// Start listening for FS events at PCAP files source directory.
	go func(wg *sync.WaitGroup, watcher *fsnotify.Watcher, ticker *time.Ticker) {
		for isActive.Load() {
			select {

			case event, ok := <-watcher.Events:
				if !ok { // Channel was closed (i.e. Watcher.Close() was called)
					return
				}
				// Skip events which are not CREATE, and all which are not related to PCAP files
				if event.Has(fsnotify.Create) && pcapDotExt.MatchString(event.Name) {
					wg.Add(1)
					exportPcapFile(ctx, wg, pcapDotExt, &event.Name, *gzip_pcaps /* compress */, true /* delete */, false /* flush */)
				} else if event.Has(fsnotify.Create) && tcpdumpwExitSignal.MatchString(event.Name) && isActive.CompareAndSwap(true, false) {
					// `tcpdumpw` signals its termination by creating the file `TCPDUMPW_EXITED` is the source directory
					tcpdumpwExitTS := time.Now()
					logEvent(zapcore.InfoLevel,
						"detected 'tcpdumpw' termination signal",
						PCAP_SIGNAL,
						map[string]interface{}{
							"event":     PCAP_SIGNAL,
							"signal":    event.Name,
							"timestamp": tcpdumpwExitTS.Format(time.RFC3339Nano),
						}, nil)
					// delete `tcpdumpw` termination signal
					os.Remove(event.Name)
					// when `tcpdumpw` signal is detected:
					//   - cancel the context which triggers final PCAP files flushing
					cancel()
					return
				}

			case fsnErr, ok := <-watcher.Errors:
				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
					ticker.Stop()
					return
				}
				logEvent(zapcore.ErrorLevel, "FS watcher failed", PCAP_FSNERR, map[string]interface{}{"closed": ok}, fsnErr)

			}
		}
	}(&wg, watcher, ticker)

	go func(watcher *fsnotify.Watcher, ticker *time.Ticker) {
		for isActive.Load() {
			select {

			case <-ctx.Done():
				return

			case <-ticker.C:
				// packet capturing is write intensive
				// OS buffers memory must be fluhsed often to prevent memory saturation
				// flushing OS file write buffers is safe: 'non-destructive operation and will not free any dirty objects'
				// additionally, PCAP files are [write|append]-only
				memoryBefore, _ := getCurrentMemoryUtilization(isGAE)
				_, memFlushErr := flushBuffers()
				memoryAfter, _ := getCurrentMemoryUtilization(isGAE)
				if memFlushErr != nil {
					continue
				}
				releasedMemory := int64(memoryBefore) - int64(memoryAfter)
				logEvent(zapcore.InfoLevel,
					fmt.Sprintf("flushed OS file write buffers: memory[before=%d|after=%d] / released=%d", memoryBefore, memoryAfter, releasedMemory),
					PCAP_OSWMEM, map[string]interface{}{"before": memoryBefore, "after": memoryAfter, "released": releasedMemory}, nil)

			}
		}
	}(watcher, ticker)

	go func(watcher *fsnotify.Watcher, ticker *time.Ticker) {
		signal := <-sigChan

		signalTS := time.Now()
		deadline := 3 * time.Second

		logEvent(zapcore.InfoLevel,
			fmt.Sprintf("signaled: %v", signal),
			PCAP_SIGNAL,
			map[string]interface{}{
				"signal":    signal,
				"timestamp": signalTS.Format(time.RFC3339Nano),
			}, nil)

		timer := time.AfterFunc(deadline-time.Since(signalTS), func() {
			if isActive.CompareAndSwap(true, false) {
				// cancel the context after 3s regardless of `tcpdumpw` termination signal:
				//   - this is effectively the `max_wait_time` for `tcpdumpw` termination signal.
				cancel()
			}
		})

		pcapMutex := flock.New(pcapLockFile)
		lockData := map[string]interface{}{"lock": pcapLockFile}
		logEvent(zapcore.InfoLevel, "waiting for PCAP lock file", PCAP_FSLOCK, lockData, nil)
		lockCtx, lockCancel := context.WithTimeout(ctx, deadline-time.Since(signalTS))
		defer lockCancel()
		// `tcpdumpq` will unlock the PCAP lock file when all PCAP engines have stopped
		if locked, lockErr := pcapMutex.TryLockContext(lockCtx, 10*time.Millisecond); !locked || lockErr != nil {
			lockData["latency"] = time.Since(signalTS).String()
			logEvent(zapcore.ErrorLevel, "failed to acquire PCAP lock file", PCAP_FSLOCK, lockData, lockErr)
		} else if isActive.CompareAndSwap(true, false) {
			timer.Stop()
			lockData["latency"] = time.Since(signalTS).String()
			cancel()
			logEvent(zapcore.InfoLevel, "acquired PCAP lock file", PCAP_FSLOCK, lockData, nil)
		}
	}(watcher, ticker)

	if err == nil {
		logEvent(zapcore.InfoLevel, fmt.Sprintf("watching directory: %s", *src_dir), PCAP_FSNINI, nil, nil)
	} else if isActive.CompareAndSwap(true, false) {
		logEvent(zapcore.InfoLevel, fmt.Sprintf("error at initialization: %v", err), PCAP_FSNINI, nil, err)
		watcher.Close()
		ticker.Stop()
		cancel()
	}

	<-ctx.Done() // wait for context to be cancelled

	ticker.Stop()
	watcher.Remove(*src_dir)
	watcher.Close()

	// wait for all regular export operations to terminate
	wg.Wait()

	ctx = context.Background()
	ctx, cancel = context.WithTimeout(ctx, 5*time.Second)

	flushStart := time.Now()
	// flush remaining PCAP files after context is done
	// compression & deletion are disabled when exiting in order to speed up the process
	pendingPcapFiles := flushSrcDir(ctx, &wg, pcapDotExt,
		true /* sync */, false /* compress */, false, /* delete */
		func(_ fs.FileInfo) bool { return true },
	)

	logEvent(zapcore.InfoLevel,
		fmt.Sprintf("waiting for %d PCAP files to be flushed", pendingPcapFiles),
		PCAP_FSNEND,
		map[string]interface{}{
			"files":     pendingPcapFiles,
			"timestamp": flushStart.Format(time.RFC3339Nano),
		}, nil)

	wg.Wait() // wait for remaining PCAP failes to be flushed
	flushLatency := time.Since(flushStart)

	logEvent(zapcore.InfoLevel,
		fmt.Sprintf("flushed %d PCAP files", pendingPcapFiles),
		PCAP_FSNEND,
		map[string]interface{}{
			"files":   pendingPcapFiles,
			"latency": flushLatency.String(),
		}, nil)
}
