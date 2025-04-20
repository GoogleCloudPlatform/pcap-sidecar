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
	"flag"
	"fmt"
	"io"
	"io/fs"
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

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/constants"
	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/gcs"
	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/log"
	"github.com/alphadose/haxmap"
	"github.com/fsnotify/fsnotify"
	"github.com/gofrs/flock"
	"go.uber.org/zap/zapcore"
)

type (
	pcapEvent = constants.PcapEvent
)

const (
	PCAP_FSNINI = constants.PCAP_FSNINI
	PCAP_FSNEND = constants.PCAP_FSNEND
	PCAP_FSNERR = constants.PCAP_FSNERR
	PCAP_CREATE = constants.PCAP_CREATE
	PCAP_EXPORT = constants.PCAP_EXPORT
	PCAP_QUEUED = constants.PCAP_QUEUED
	PCAP_OSWMEM = constants.PCAP_OSWMEM
	PCAP_SIGNAL = constants.PCAP_SIGNAL
	PCAP_FSLOCK = constants.PCAP_FSLOCK
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
	gcs_export    = flag.Bool("gcs_export", true, "export PCAP files to GCS")
	gcs_fuse      = flag.Bool("gcs_fuse", true, "export PCAP files using GCS Fuse")
	gcs_bucket    = flag.String("gcs_bucket", "", "export PCAP files to this GCS bucket")
	instance_id   = flag.String("instance_id", "", "compute resource hosting the PCAP sidecar")
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

var (
	logger   = log.NewLogger(projectID, service, gcpRegion, version, instanceID, sidecar, module)
	exporter = gcs.NewNilExporter(logger)

	counters *haxmap.Map[string, *atomic.Uint64]
	lastPcap *haxmap.Map[string, string]
)

var isActive atomic.Bool

func movePcapToGcs(
	ctx context.Context,
	srcPcap *string,
	compress, delete bool,
) (*string, *int64, error) {
	return exporter.Export(ctx, srcPcap, compress, delete)
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
		logger.LogFsEvent(zapcore.InfoLevel,
			fmt.Sprintf("flushing PCAP file: [%s] (%s/%s) %s", key, ext, iface, *srcFile), PCAP_EXPORT, *srcFile, "" /* target PCAP file */, 0, nil)
		tgtPcapFileName, pcapBytes, moveErr := movePcapToGcs(ctx, srcFile, compress, delete)
		if moveErr != nil {
			logger.LogFsEvent(zapcore.ErrorLevel,
				fmt.Sprintf("failed to flush PCAP file: (%s/%s) %s", ext, iface, *srcFile), PCAP_FSNERR, *srcFile, *tgtPcapFileName /* target PCAP file */, 0, moveErr)
			return false
		}
		logger.LogFsEvent(zapcore.InfoLevel,
			fmt.Sprintf("flushed PCAP file: (%s/%s) %s", ext, iface, *tgtPcapFileName), PCAP_EXPORT, *srcFile, *tgtPcapFileName, *pcapBytes, nil)
		return true
	}

	counter, _ := counters.GetOrCompute(key,
		func() *atomic.Uint64 {
			return new(atomic.Uint64)
		})
	iteration := (*counter).Add(1)

	logger.LogFsEvent(zapcore.InfoLevel,
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
		logger.LogFsEvent(zapcore.ErrorLevel, fmt.Sprintf("PCAP file [%s] (%s/%s/%d) unavailable", key, ext, iface, iteration), PCAP_EXPORT, "" /* source PCAP File */, *srcFile /* target PCAP file */, 0, nil)
		return false
	}

	logger.LogFsEvent(zapcore.InfoLevel,
		fmt.Sprintf("exporting PCAP file: (%s/%s/%d) %s", ext, iface, iteration, *srcFile), PCAP_EXPORT, lastPcapFileName, "" /* target PCAP file */, 0, nil)
	// move non-current PCAP file into `gcs_dir` which means that:
	// 1. the GCS Bucket should have already been mounted
	// 2. the directory hierarchy to store PCAP files already exists
	tgtPcapFileName, pcapBytes, moveErr := movePcapToGcs(ctx, &lastPcapFileName, compress, delete)
	if moveErr == nil {
		logger.LogFsEvent(zapcore.InfoLevel,
			fmt.Sprintf("exported PCAP file: (%s/%s/%d) %s", ext, iface, iteration, *tgtPcapFileName), PCAP_EXPORT, lastPcapFileName, *tgtPcapFileName, *pcapBytes, nil)
	} else {
		logger.LogFsEvent(zapcore.ErrorLevel,
			fmt.Sprintf("failed to export PCAP file: (%s/%s/%d) %s", ext, iface, iteration, lastPcapFileName), PCAP_EXPORT, lastPcapFileName, *tgtPcapFileName /* target PCAP file */, 0, moveErr)
	}

	// current PCAP file is the next one to be moved
	if !lastPcap.CompareAndSwap(key, lastPcapFileName, *srcFile) {
		logger.LogFsEvent(zapcore.ErrorLevel,
			fmt.Sprintf("leaked PCAP file: [%s] (%s/%s/%d) %s", key, ext, iface, iteration, *srcFile), PCAP_FSNERR, *srcFile, "" /* target PCAP file */, 0, nil)
		lastPcap.Set(key, *srcFile)
	}
	logger.LogFsEvent(zapcore.InfoLevel,
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
			logger.LogEvent(zapcore.ErrorLevel, "failed to flush PCAP files", PCAP_FSNERR, nil, err)
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

	args := map[string]any{
		"src_dir":    *src_dir,
		"gcs_dir":    *gcs_dir,
		"gcs_export": *gcs_export,
		"gcs_fuse":   *gcs_fuse,
		"gcs_bucket": *gcs_bucket,
		"pcap_ext":   pcapDotExt.String(),
		"interval":   watchdogInterval.String(),
		"gzip":       *gzip_pcaps,
		"rt_env":     *rt_env,
		"pcap_debug": *pcap_debug,
	}

	logger.LogEvent(zapcore.InfoLevel, "starting PCAP filesystem watcher", PCAP_FSNINI, args, nil)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)

	// Create new watcher.
	watcher, err := fsnotify.NewBufferedWatcher(100)
	if err != nil {
		logger.LogEvent(zapcore.FatalLevel, fmt.Sprintf("failed to create FS watcher: %v", err), PCAP_FSNINI, nil, nil)
		os.Exit(1)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())

	if *gcs_export {
		// if GCS export is disabled, the PCAP files `exporter` is already initialized using `NewNilExporter`
		if *gcs_fuse {
			exporter = gcs.NewFuseExporter(logger, *gcs_dir, *retries_max, *retries_delay)
		} else {
			exporter = gcs.NewClientLibraryExporter(ctx, logger, projectID, service, instanceID, *gcs_bucket, *gcs_dir, *retries_max, *retries_delay)
		}
	}

	var wg sync.WaitGroup

	// Watch the PCAP files source directory for FS events.
	if isActive.CompareAndSwap(false, true) {
		if err = watcher.Add(*src_dir); err != nil {
			logger.LogEvent(zapcore.ErrorLevel, fmt.Sprintf("failed to watch directory '%s': %v", *src_dir, err), PCAP_FSNERR, nil, err)
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
					logger.LogEvent(zapcore.InfoLevel,
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
				logger.LogEvent(zapcore.ErrorLevel, "FS watcher failed", PCAP_FSNERR, map[string]interface{}{"closed": ok}, fsnErr)

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
				logger.LogEvent(zapcore.InfoLevel,
					fmt.Sprintf("flushed OS file write buffers: memory[before=%d|after=%d] / released=%d", memoryBefore, memoryAfter, releasedMemory),
					PCAP_OSWMEM, map[string]interface{}{"before": memoryBefore, "after": memoryAfter, "released": releasedMemory}, nil)

			}
		}
	}(watcher, ticker)

	go func(watcher *fsnotify.Watcher, ticker *time.Ticker) {
		signal := <-sigChan

		signalTS := time.Now()
		deadline := 3 * time.Second

		logger.LogEvent(zapcore.InfoLevel,
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
		logger.LogEvent(zapcore.InfoLevel, "waiting for PCAP lock file", PCAP_FSLOCK, lockData, nil)
		lockCtx, lockCancel := context.WithTimeout(ctx, deadline-time.Since(signalTS))
		defer lockCancel()
		// `tcpdumpq` will unlock the PCAP lock file when all PCAP engines have stopped
		if locked, lockErr := pcapMutex.TryLockContext(lockCtx, 10*time.Millisecond); !locked || lockErr != nil {
			lockData["latency"] = time.Since(signalTS).String()
			logger.LogEvent(zapcore.ErrorLevel, "failed to acquire PCAP lock file", PCAP_FSLOCK, lockData, lockErr)
		} else if isActive.CompareAndSwap(true, false) {
			timer.Stop()
			lockData["latency"] = time.Since(signalTS).String()
			cancel()
			logger.LogEvent(zapcore.InfoLevel, "acquired PCAP lock file", PCAP_FSLOCK, lockData, nil)
		}
	}(watcher, ticker)

	if err == nil {
		logger.LogEvent(zapcore.InfoLevel, fmt.Sprintf("watching directory: %s", *src_dir), PCAP_FSNINI, nil, nil)
	} else if isActive.CompareAndSwap(true, false) {
		logger.LogEvent(zapcore.InfoLevel, fmt.Sprintf("error at initialization: %v", err), PCAP_FSNINI, nil, err)
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

	logger.LogEvent(zapcore.InfoLevel,
		fmt.Sprintf("waiting for %d PCAP files to be flushed", pendingPcapFiles),
		PCAP_FSNEND,
		map[string]interface{}{
			"files":     pendingPcapFiles,
			"timestamp": flushStart.Format(time.RFC3339Nano),
		}, nil)

	wg.Wait() // wait for remaining PCAP failes to be flushed
	flushLatency := time.Since(flushStart)

	logger.LogEvent(zapcore.InfoLevel,
		fmt.Sprintf("flushed %d PCAP files", pendingPcapFiles),
		PCAP_FSNEND,
		map[string]interface{}{
			"files":   pendingPcapFiles,
			"latency": flushLatency.String(),
		}, nil)
}
