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

package transformer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/panjf2000/ants/v2"
	concurrently "github.com/tejzpr/ordered-concurrently/v3"
)

var transformerLogger = log.New(os.Stderr, "[transformer] - ", log.LstdFlags)

type (
	PcapTranslatorFactory = func(context.Context, bool, *PcapIface, *PcapEmphemeralPorts) PcapTranslator

	PcapTranslatorFmt uint8

	PcapTranslator interface {
		next(context.Context, *PcapIface, *uint64, *gopacket.Packet) fmt.Stringer
		translateEthernetLayer(context.Context, *layers.Ethernet) fmt.Stringer
		translateARPLayer(context.Context, *layers.ARP) fmt.Stringer
		translateIPv4Layer(context.Context, *layers.IPv4) fmt.Stringer
		translateIPv6Layer(context.Context, *layers.IPv6) fmt.Stringer
		translateICMPv4Layer(context.Context, *layers.ICMPv4) fmt.Stringer
		translateICMPv6Layer(context.Context, *layers.ICMPv6) fmt.Stringer
		translateICMPv6EchoLayer(context.Context, fmt.Stringer, *layers.ICMPv6Echo) fmt.Stringer
		translateICMPv6RedirectLayer(context.Context, fmt.Stringer, *layers.ICMPv6Redirect) fmt.Stringer
		translateICMPv6L3HeaderLayer(context.Context, fmt.Stringer, *layers.ICMPv6) fmt.Stringer
		translateUDPLayer(context.Context, *layers.UDP) fmt.Stringer
		translateTCPLayer(context.Context, *layers.TCP) fmt.Stringer
		translateTLSLayer(context.Context, *layers.TLS) fmt.Stringer
		translateDNSLayer(context.Context, *layers.DNS) fmt.Stringer
		merge(context.Context, fmt.Stringer, fmt.Stringer) (fmt.Stringer, error)
		finalize(context.Context, netIfaceIndex, *PcapIface, *uint64, *gopacket.Packet, bool, fmt.Stringer) (fmt.Stringer, error)
		write(context.Context, io.Writer, *fmt.Stringer) (int, error)
		done(context.Context)
	}

	netIfaceIndex map[string]*PcapIface

	PcapTransformer struct {
		ctx             context.Context
		iface           *PcapIface
		ifaces          netIfaceIndex
		ephemerals      *PcapEmphemeralPorts
		loggerPrefix    *string
		ich             chan concurrently.WorkFunction
		och             <-chan concurrently.OrderedOutput
		translator      PcapTranslator
		translatorPool  *ants.PoolWithFunc
		writerPool      *ants.MultiPoolWithFunc
		writers         []io.Writer
		numWriters      *uint8
		writeQueues     []chan *fmt.Stringer
		writeQueuesDone []chan struct{}
		wg              *sync.WaitGroup
		preserveOrder   bool
		connTracking    bool
		apply           func(*pcapTranslatorWorker) error
		counter         *atomic.Int64
		filters         PcapFilters
		debug, compat   bool
	}

	IPcapTransformer interface {
		WaitDone(context.Context, *time.Duration)
		Apply(context.Context, *gopacket.Packet, *uint64) error
	}

	pcapWriteTask struct {
		ctx         context.Context
		writer      *uint8
		translation *fmt.Stringer
	}

	PcapIface struct {
		Index uint8
		Name  string
		Addrs mapset.Set[string]
	}

	PcapEmphemeralPorts struct {
		Min, Max uint16
	}

	ContextKey string
)

const (
	ContextID      = ContextKey("id")
	ContextLogName = ContextKey("logName")
)

//go:generate stringer -type=PcapTranslatorFmt
const (
	TEXT PcapTranslatorFmt = iota
	JSON
	PROTO
)

var pcapTranslatorFmts = map[string]PcapTranslatorFmt{
	"json":  JSON,
	"text":  TEXT,
	"proto": PROTO,
}

var translators sync.Map

const (
	projectIdEnvVarName           = "PROJECT_ID"
	tcpOptionsRegex               = `^TCPOption\((?P<name>.+?):(?P<value>.*?)\)$`
	http11RequestPayloadRegexStr  = `^(?P<method>.+?)\s(?P<url>.+?)\sHTTP/1\.1(?:\r?\n)?.*`
	http11ResponsePayloadRegexStr = `^HTTP/1\.1\s(?P<code>\d{3})\s(?P<status>.+?)(?:\r?\n)?.*`
	http2PrefaceRegexStr          = `^PRI.+?HTTP/2\.0\r?\n\r?\nSM\r?\n\r?\n`
	http11LineSeparator           = "\r\n"
	http2RawFrameRegexStr         = `^\[FrameHeader\s(.+?)\]`
	httpContentLengthHeader       = "Content-Length"
	cloudTraceContextHeader       = "x-cloud-trace-context"
	traceparentHeader             = "traceparent"

	// keeping it in sync with `h2`:
	//   - A stream identifier of zero (0x00) is used for connection control messages
	http11StreamID = uint32(1)

	tcpSynStr = "SYN"
	tcpAckStr = "ACK"
	tcpPshStr = "PSH"
	tcpFinStr = "FIN"
	tcpRstStr = "RST"
	tcpUrgStr = "URG"
	tcpEceStr = "ECE"
	tcpCwrStr = "CWR"
)

var (
	tcpFlags = map[string]uint8{
		tcpFinStr: 0b00000001,
		tcpSynStr: 0b00000010,
		tcpRstStr: 0b00000100,
		tcpPshStr: 0b00001000,
		tcpAckStr: 0b00010000,
		tcpUrgStr: 0b00100000,
		tcpEceStr: 0b01000000,
		tcpCwrStr: 0b10000000,
	}
	tcpFlagNil = uint8(0b00000000)

	tcpSynAckStr    = tcpSynStr + "|" + tcpAckStr
	tcpSynRstStr    = tcpSynStr + "|" + tcpRstStr
	tcpPshAckStr    = tcpPshStr + "|" + tcpAckStr
	tcpFinAckStr    = tcpFinStr + "|" + tcpAckStr
	tcpRstAckStr    = tcpRstStr + "|" + tcpAckStr
	tcpUrgAckStr    = tcpUrgStr + "|" + tcpAckStr
	tcpSynPshAckStr = tcpSynStr + "|" + tcpPshStr + "|" + tcpAckStr
	tcpFinRstAckStr = tcpFinStr + "|" + tcpRstStr + "|" + tcpAckStr

	tcpSyn = tcpFlags[tcpSynStr]
	tcpAck = tcpFlags[tcpAckStr]
	tcpPsh = tcpFlags[tcpPshStr]
	tcpFin = tcpFlags[tcpFinStr]
	tcpRst = tcpFlags[tcpRstStr]
	tcpUrg = tcpFlags[tcpUrgStr]
	tcpEce = tcpFlags[tcpEceStr]
	tcpCwr = tcpFlags[tcpCwrStr]

	tcpSynAck    = tcpSyn | tcpAck
	tcpSynRst    = tcpSyn | tcpRst
	tcpPshAck    = tcpPsh | tcpAck
	tcpFinAck    = tcpFin | tcpAck
	tcpRstAck    = tcpRst | tcpAck
	tcpUrgAck    = tcpUrg | tcpAck
	tcpSynPshAck = tcpSyn | tcpPsh | tcpAck
	tcpFinRstAck = tcpFin | tcpRst | tcpAck

	tcpFlagsStr = map[uint8]string{
		tcpSyn:       tcpSynStr,
		tcpAck:       tcpAckStr,
		tcpPsh:       tcpPshStr,
		tcpFin:       tcpFinStr,
		tcpRst:       tcpRstStr,
		tcpUrg:       tcpUrgStr,
		tcpEce:       tcpEceStr,
		tcpCwr:       tcpCwrStr,
		tcpSynAck:    tcpSynAckStr,
		tcpSynRst:    tcpSynRstStr,
		tcpPshAck:    tcpPshAckStr,
		tcpFinAck:    tcpFinAckStr,
		tcpRstAck:    tcpRstAckStr,
		tcpUrgAck:    tcpUrgAckStr,
		tcpSynPshAck: tcpSynPshAckStr,
		tcpFinRstAck: tcpFinRstAckStr,
	}
)

var (
	tcpOptionRgx                 = regexp.MustCompile(tcpOptionsRegex)
	http11RequestPayloadRegex    = regexp.MustCompile(http11RequestPayloadRegexStr)
	http11ResponsePayloadRegex   = regexp.MustCompile(http11ResponsePayloadRegexStr)
	http2PrefaceRegex            = regexp.MustCompile(http2PrefaceRegexStr)
	http2RawFrameRegex           = regexp.MustCompile(http2RawFrameRegexStr)
	http11Separator              = []byte(http11LineSeparator)
	http11BodySeparator          = []byte(http11LineSeparator + http11LineSeparator)
	http11HeaderSeparator        = []byte(":")
	httpContentLengthHeaderBytes = []byte(httpContentLengthHeader)
	cloudTraceContextHeaderBytes = []byte(cloudTraceContextHeader)
	traceparentHeaderBytes       = []byte(traceparentHeader)
	cloudProjectID               = os.Getenv(projectIdEnvVarName)
	cloudTracePrefix             = "projects/" + cloudProjectID + "/traces/"

	traceAndSpanRegexStr = map[string]string{
		cloudTraceContextHeader: `^(?P<trace>.+?)/(?P<span>.+?)(?:;o=.*)?$`,
		traceparentHeader:       `^.+?-(?P<trace>.+?)-(?P<span>.+?)(?:-.+)?$`,
	}
	traceAndSpanRegex = map[string]*regexp.Regexp{
		cloudTraceContextHeader: regexp.MustCompile(traceAndSpanRegexStr[cloudTraceContextHeader]),
		traceparentHeader:       regexp.MustCompile(traceAndSpanRegexStr[traceparentHeader]),
	}
)

var (
	errUnavailableTranslation = errors.New("packet translation is unavailable")
	errUnavailableTranslator  = errors.New("packet translator is unavailable")
)

func (t *PcapTransformer) writeTranslation(ctx context.Context, task *pcapWriteTask) error {
	defer func() {
		t.counter.Add(-1)
		t.wg.Done()
	}()

	select {
	case <-ctx.Done():
		if *task.writer == 0 {
			// best-effort: dump all non-written translations into `STDERR`
			fmt.Fprintln(os.Stderr, (*task.translation).String())
		}
		return ctx.Err()
	default:
		_, err := t.translator.write(ctx, t.writers[*task.writer], task.translation)
		return err
	}
}

func (t *PcapTransformer) publishTranslation(
	ctx context.Context,
	translation *fmt.Stringer,
) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if translation == nil {
			return fmt.Errorf("%s publishTranslation: %w",
				*t.loggerPrefix, errUnavailableTranslation)
		}
	}

	// fan-out translation into all writers
	for _, translations := range t.writeQueues {
		// if any of the consumers' buffers is full,
		// the saturated/slower one will block and delay iterations.
		// Blocking is more likely when `preserveOrder` is enabled.
		translations <- translation
	}
	return nil
}

func (t *PcapTransformer) produceTranslation(
	ctx context.Context,
	task *pcapTranslatorWorker,
) error {
	translation := task.Run(ctx)
	if translation == nil {
		return nil
	}
	return t.publishTranslation(ctx, translation.(*fmt.Stringer))
}

func (t *PcapTransformer) produceTranslations(ctx context.Context) {
	for translation := range t.och {
		// translations are made available in the enqueued order
		// consume translations and push them into translations consumers
		if err := t.publishTranslation(ctx, translation.Value.(*fmt.Stringer)); err != nil {
			rollbackTranslation(ctx, t)
		}
	}
}

func (t *PcapTransformer) consumeTranslations(ctx context.Context, index *uint8) error {
	// `consumeTranslations` runs in 1 goroutine per writer,
	// so it needs to be context aware to be able to gracefully stop, thus preventing a leak.
	for {
		select {
		case <-ctx.Done():
			// drop translations if context is already done
			droppedTranslations := uint64(0)
			// some translations may have been on-going when context was cancelled:
			//   - fully consume the `writerQueue` and rollback the write commitment,
			//   - block until `close` on the `writerQueue` is called by `WaitDone`
			for translation := range t.writeQueues[*index] {
				// best-effort: dump all non-written translations into `STDERR`
				if *index == 0 {
					fmt.Fprintln(os.Stderr, (*translation).String())
				}
				droppedTranslations += 1
				t.counter.Add(-1)
				t.wg.Done()
			}
			transformerLogger.Printf("%s translations consumer DONE | writer:%d | dropped:%d\n", *t.loggerPrefix, *index+1, droppedTranslations)
			close(t.writeQueuesDone[*index])
			return ctx.Err()

		case translation := <-t.writeQueues[*index]:
			task := &pcapWriteTask{
				ctx:         ctx,
				writer:      index,
				translation: translation,
			}
			if t.preserveOrder || t.connTracking {
				// this is mostly blocking
				t.writeTranslation(ctx, task)
			} else {
				// this is mostly non-blocking
				t.writerPool.Invoke(task)
			}
		}
	}
}

func (t *PcapTransformer) waitForContextDone(ctx context.Context) error {
	<-ctx.Done()
	close(t.ich)
	return ctx.Err()
}

// returns when all packets have been transformed and written
func (t *PcapTransformer) WaitDone(ctx context.Context, timeout *time.Duration) {
	ts := time.Now()
	timer := time.NewTimer(*timeout)

	writeDoneChan := make(chan struct{})

	go func(t *PcapTransformer, writeDone chan struct{}) {
		if !t.preserveOrder && !t.connTracking {
			transformerLogger.Printf("%s gracefully terminating | tp: %d/%d | wp: %d/%d | pending:%d | deadline: %v\n",
				*t.loggerPrefix, t.translatorPool.Running(), t.translatorPool.Waiting(),
				t.writerPool.Running(), t.writerPool.Waiting(), t.counter.Load(), timeout)
		} else {
			transformerLogger.Printf("%s gracefully terminating | pending: %d | deadline: %v\n", *t.loggerPrefix, t.counter.Load(), timeout)
		}
		t.wg.Wait() // wait for all translations to be written
		close(writeDone)
	}(t, writeDoneChan)

	select {
	case <-timer.C:
		if !t.preserveOrder && !t.connTracking {
			transformerLogger.Printf("%s timed out waiting for graceful termination | tp: %d/%d | wp: %d/%d | pending:%d\n",
				*t.loggerPrefix, t.translatorPool.Running(), t.translatorPool.Waiting(), t.writerPool.Running(), t.writerPool.Waiting(), t.counter.Load())
		} else {
			transformerLogger.Printf("%s timed out waiting for graceful termination | pending:%d\n", *t.loggerPrefix, t.counter.Load())
		}
		for _, writeQueue := range t.writeQueues {
			close(writeQueue) // close writer channels
		}
		t.translator.done(ctx)
		return

	case <-writeDoneChan:
		if !timer.Stop() {
			<-timer.C
		}
		transformerLogger.Printf("%s STOPPED | tp: %d/%d | wp: %d/%d | pending:%d | latency: %v\n",
			*t.loggerPrefix, t.translatorPool.Running(), t.translatorPool.Waiting(),
			t.writerPool.Running(), t.writerPool.Waiting(), t.counter.Load(), time.Since(ts))
	}

	for i, writeQueue := range t.writeQueues {
		// unblock `consumeTranslations` goroutines
		close(writeQueue) // close writer channels
		<-t.writeQueuesDone[i]
	}

	_timeout := *timeout - time.Since(ts)
	// if order is not enforced: there are 2 worker pools to be stopped
	if _timeout > 0 && !t.preserveOrder && !t.connTracking {
		transformerLogger.Printf("%s releasing worker pools | deadline: %v\n", *t.loggerPrefix, _timeout)
		var poolReleaserWG sync.WaitGroup
		poolReleaserWG.Add(2)
		go func(t *PcapTransformer, wg *sync.WaitGroup, deadline *time.Duration) {
			t.translatorPool.ReleaseTimeout(*deadline)
			wg.Done()
		}(t, &poolReleaserWG, &_timeout)
		go func(t *PcapTransformer, wg *sync.WaitGroup, deadline *time.Duration) {
			t.writerPool.ReleaseTimeout(*deadline)
			wg.Done()
		}(t, &poolReleaserWG, &_timeout)
		poolReleaserWG.Wait()
		transformerLogger.Printf("%s released worker pools\n", *t.loggerPrefix)
	}

	// only safe to be called when nothing else is running
	t.translator.done(ctx)

	transformerLogger.Printf("%s TERMINATED | latency: %v\n", *t.loggerPrefix, time.Since(ts))
}

func (t *PcapTransformer) Apply(ctx context.Context, packet *gopacket.Packet, serial *uint64) error {
	select {
	case <-ctx.Done():
		// reject applying transformer if context is already done.
		return ctx.Err()
	default:
		// applying transformer will write 1 translation into N>0 writers.
		t.wg.Add(int(*t.numWriters))
		t.counter.Add(int64(*t.numWriters))
	}
	// It is assumed that packets will be produced faster than translations and writing operations, so:
	//   - process/translate packets concurrently in order to avoid blocking `gopacket` packets channel as much as possible.
	worker := newPcapTranslatorWorker(t.ifaces, t.iface, t.filters, serial, packet, t.translator, t.connTracking, t.compat)
	return t.apply(worker)
}

func (t *PcapTransformer) translatePacketFn(ctx context.Context, worker interface{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return t.produceTranslation(ctx, worker.(*pcapTranslatorWorker))
	}
}

func (t *PcapTransformer) writeTranslationFn(ctx context.Context, task interface{}) error {
	return t.writeTranslation(ctx, task.(*pcapWriteTask))
}

func newTranslator(
	ctx context.Context,
	debug bool,
	iface *PcapIface,
	ephemerals *PcapEmphemeralPorts,
	format PcapTranslatorFmt,
) (PcapTranslator, error) {
	if factory, ok := translators.Load(format); ok {
		return factory.(PcapTranslatorFactory)(ctx, debug, iface, ephemerals), nil
	}

	return nil, errors.Join(errUnavailableTranslator,
		fmt.Errorf("[%d/%s] - invalid format: %v",
			iface.Index, iface.Name, format))
}

func rollbackTranslation(
	_ context.Context,
	transformer *PcapTransformer,
) {
	for range *transformer.numWriters {
		transformer.counter.Add(-1)
		transformer.wg.Done()
	}
}

// if preserving packet capture order is not required, translations may be done concurrently
// concurrently translating packets means that translations are not enqueded in packet capture order.
// Similarly, sinking translations into files can be safely done concurrently ( in whatever order goroutines are scheduled )
func provideWorkerPools(ctx context.Context, transformer *PcapTransformer, numWriters *uint8) {
	poolOpts := ants.Options{
		Logger:      transformerLogger,
		PreAlloc:    false,
		Nonblocking: false,
		// see: https://github.com/panjf2000/ants/blob/v2.10.0/worker_loop_queue.go#L74
		ExpiryDuration: time.Duration(10) * time.Second,
		DisablePurge:   true,
	}

	poolOpts.PanicHandler = func(i interface{}) {
		rollbackTranslation(ctx, transformer)
		// if any go routine panics, recover and print the stack
		transformerLogger.Printf("%s panic: %+v\n%s\n",
			*transformer.loggerPrefix, i, string(debug.Stack()))
	}

	poolOptions := ants.WithOptions(poolOpts)

	poolSize := 25 * int(*numWriters)

	translatorPoolFn := func(i interface{}) {
		select {
		case <-ctx.Done():
			rollbackTranslation(ctx, transformer)
			return
		default:
			if err := transformer.translatePacketFn(ctx, i); err != nil {
				transformerLogger.Printf("%s translation failed: %+v\n", *transformer.loggerPrefix, err)
				rollbackTranslation(ctx, transformer)
			}
		}
	}
	translatorPool, _ := ants.NewPoolWithFunc(poolSize, translatorPoolFn, poolOptions)
	transformer.translatorPool = translatorPool

	writerPoolFn := func(i interface{}) {
		transformer.writeTranslationFn(ctx, i)
	}
	// I/O ( writing ) is slow; so there will be more writers than translator routines
	writerPool, _ := ants.NewMultiPoolWithFunc(int(*numWriters), 25, writerPoolFn, ants.LeastTasks, poolOptions)
	transformer.writerPool = writerPool
}

func provideConcurrentQueue(ctx context.Context, connTrack bool, transformer *PcapTransformer, numWriters *uint8) {
	// if connection tracking is enabled, the whole process is synchronous,
	// so the following considerations apply:
	//   - should be enabled only in combination with a very specific filter
	//   - should not be used when high traffic rate is expected:
	//       non-concurrent processing is slower, so more memory is required to buffer packets
	poolSize := 1
	if !connTrack {
		// when `poolSize` is greater than 1: even when written in order,
		// packets are processed concurrently which makes connection tracking
		// a very complex process to be done on-the-fly as order of packet translation
		// is not guaranteed; introducing contention may slow down the whole process.
		poolSize = 30 * int(*numWriters)
	}

	ochOpts := &concurrently.Options{
		PoolSize:         poolSize,
		OutChannelBuffer: 100,
	}

	transformer.ich = make(chan concurrently.WorkFunction, 100)
	transformer.och = concurrently.Process(ctx, transformer.ich, ochOpts)
}

func provideStrategy(
	ctx context.Context,
	transformer *PcapTransformer,
	preserveOrder, connTracking bool,
) {
	var apply func(*PcapTransformer, *pcapTranslatorWorker) error = nil

	if preserveOrder || connTracking {
		// If ordered output is enabled, enqueue translation workers in packet capture order;
		// this will introduce some level of contention as the translation Q starts to fill (saturation):
		// if the next packet to arrive finds a full Q, this method will block until slots are available.
		// The degree of contention is proportial to the Q capacity times translation latency.
		// Order should only be used for not network intersive workloads.
		apply = func(t *PcapTransformer, w *pcapTranslatorWorker) error {
			select {
			case <-ctx.Done():
				rollbackTranslation(ctx, transformer)
				return ctx.Err()
			default:
				t.ich <- w
			}
			return nil
		}
	} else {
		// if ordered output is disabled, translate packets concurrently via translator pool.
		// Order of gorouting execution is not guaranteed, which means
		// that packets will be consumed/written in non-deterministic order.
		// `serial` is aviailable to be used for sorting PCAP files.
		apply = func(t *PcapTransformer, w *pcapTranslatorWorker) error {
			return t.translatorPool.Invoke(w)
		}
	}

	transformer.apply = func(w *pcapTranslatorWorker) error {
		select {
		case <-ctx.Done():
			transformerLogger.Printf("%s #:%d | translation aborted", *w.loggerPrefix, *w.serial)
			// `Apply` commits `transformer` to write the packet translation,
			// so if the context is done, commitment must be rolled back
			rollbackTranslation(ctx, transformer)
			return errors.Join(errUnavailableTranslation, ctx.Err())
		default:
			return apply(transformer, w)
		}
	}
}

// transformers get instances of `io.Writer` instead of `pcap.PcapWriter` to prevent closing.
func newTransformer(
	ctx context.Context,
	iface *PcapIface,
	ephemerals *PcapEmphemeralPorts,
	filters PcapFilters,
	writers []io.Writer,
	format *string,
	preserveOrder,
	connTracking bool,
	debug, compat bool,
) (IPcapTransformer, error) {
	pcapFmt := pcapTranslatorFmts[*format]
	translator, err := newTranslator(ctx, debug, iface, ephemerals, pcapFmt)
	if err != nil {
		return nil, err
	}

	loggerPrefix := fmt.Sprintf("[%d/%s] -", iface.Index, iface.Name)

	numWriters := uint8(len(writers))
	// not using `io.MultiWriter` as it writes to all writers sequentially
	writeQueues := make([]chan *fmt.Stringer, numWriters)
	writeQueuesDone := make([]chan struct{}, numWriters)
	for i := range writers {
		writeQueues[i] = make(chan *fmt.Stringer, 50)
		writeQueuesDone[i] = make(chan struct{})
	}

	// inverted index from `net.Address` to `PcapInterface`
	//   - will allow to find the correct interface in O(1) when the selected interface is `0/any`
	var ifaces netIfaceIndex = make(map[string]*PcapIface)
	if _ifaces, err := net.Interfaces(); err == nil {
		// O(N*M): we must visit all interfaces to get all available IPs
		//   - N: is the number of interfaces
		//   - M: is the number of IPs per interface
		for _, _iface := range _ifaces {

			_addrs, err := _iface.Addrs()
			if err != nil {
				continue
			}

			pcapIface := &PcapIface{
				Index: uint8(_iface.Index),
				Name:  _iface.Name,
				Addrs: mapset.NewSetWithSize[string](len(_addrs)),
			}

			// O(M): M is the number of IPs assigned to this interface
			for _, _addr := range _addrs {
				addr := strings.SplitN(_addr.String(), "/", 2)[0]
				pcapIface.Addrs.Add(addr)
				ifaces[addr] = pcapIface
			}

		}
	}

	// same transformer, multiple strategies
	// via multiple translator implementations
	transformer := &PcapTransformer{
		wg:              new(sync.WaitGroup),
		ctx:             ctx,
		iface:           iface,
		ifaces:          ifaces,
		filters:         filters,
		ephemerals:      ephemerals,
		loggerPrefix:    &loggerPrefix,
		translator:      translator,
		writers:         writers,
		numWriters:      &numWriters,
		writeQueues:     writeQueues,
		writeQueuesDone: writeQueuesDone,
		preserveOrder:   preserveOrder || connTracking,
		connTracking:    connTracking,
		counter:         new(atomic.Int64),
		debug:           debug,
		compat:          compat,
	}

	provideStrategy(ctx, transformer, preserveOrder, connTracking)

	// `preserveOrder==true` causes writes to be sequential and blocking per `io.Writer`.
	// `preserveOrder==true` although blocking at writting, does not cause `transformer.Apply` to block.
	if preserveOrder || connTracking {
		provideConcurrentQueue(ctx, connTracking, transformer, &numWriters)
		go transformer.waitForContextDone(ctx)
		go transformer.produceTranslations(ctx)
	} else {
		provideWorkerPools(ctx, transformer, &numWriters)
	}

	// spawn consumers for all `io.Writer`s
	// 1 consumer goroutine per `io.Writer`
	for i := range writeQueues {
		index := uint8(i)
		go transformer.consumeTranslations(ctx, &index)
	}

	transformerLogger.Printf("%s CREATED | format:%s | writers:%d\n", loggerPrefix, *format, numWriters)

	return transformer, nil
}

func NewOrderedTransformer(
	ctx context.Context,
	iface *PcapIface,
	ephemerals *PcapEmphemeralPorts,
	filters PcapFilters,
	writers []io.Writer,
	format *string,
	debug, compat bool,
) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, ephemerals, filters, writers, format, true /* preserveOrder */, false /* connTracking */, debug, compat)
}

func NewConnTrackTransformer(
	ctx context.Context,
	iface *PcapIface,
	ephemerals *PcapEmphemeralPorts,
	filters PcapFilters,
	writers []io.Writer,
	format *string,
	debug, compat bool,
) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, ephemerals, filters, writers, format, true /* preserveOrder */, true /* connTracking */, debug, compat)
}

func NewDebugTransformer(
	ctx context.Context,
	iface *PcapIface,
	ephemerals *PcapEmphemeralPorts,
	filters PcapFilters,
	writers []io.Writer,
	format *string,
	compat bool,
) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, ephemerals, filters, writers, format, false /* preserveOrder */, false /* connTracking */, true /* debug */, compat)
}

func NewTransformer(
	ctx context.Context,
	iface *PcapIface,
	ephemerals *PcapEmphemeralPorts,
	filters PcapFilters,
	writers []io.Writer,
	format *string,
	debug, compat bool,
) (IPcapTransformer, error) {
	return newTransformer(ctx, iface, ephemerals, filters, writers, format, false /* preserveOrder */, false /* connTracking */, debug, compat)
}
