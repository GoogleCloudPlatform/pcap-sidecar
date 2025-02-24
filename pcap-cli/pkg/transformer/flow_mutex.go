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
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/alphadose/haxmap"
	"github.com/wissance/stringFormatter"
	"github.com/zhangyunhao116/skipmap"
)

type (
	TracedFlowProvider   = func(*uint32) (*TracedFlow, bool)
	TraceAndSpanProvider = func(*uint32) (*traceAndSpan, bool)

	UnlockWithTraceAndSpan = func(
		context.Context,
		*uint8, /* TCP flags */
		bool, /* isHTTP2 */
		[]uint32, []uint32,
		map[uint32]*traceAndSpan,
		map[uint32]*traceAndSpan,
	) (*int64, *time.Duration)
	UnlockWithTCPFlags = func(
		context.Context,
		*uint8, /* TCP flags */
	) (bool, *time.Duration)
	Unlock = func(context.Context) (bool, *time.Duration)

	flowMutex struct {
		Debug                     bool
		MutexMap                  *haxmap.Map[uint64, *flowLockCarrier]
		traceToHttpRequestMap     *haxmap.Map[string, *httpRequest]
		flowToStreamToSequenceMap FTSTSM
	}

	flowLock struct {
		IsHTTP2                func() bool
		Unlock                 Unlock
		UnlockAndRelease       Unlock
		UnlockWithTCPFlags     UnlockWithTCPFlags
		UnlockWithTraceAndSpan UnlockWithTraceAndSpan
	}

	flowLockCarrier struct {
		serial         *uint64
		flowID         *uint64
		mu             *sync.Mutex
		wg             *sync.WaitGroup
		released       *atomic.Bool
		createdAt      *time.Time
		lastLockedAt   *time.Time
		lastUnlockedAt *time.Time
		isHTTP2        bool
		activeRequests *atomic.Int64
	}

	TracedFlow struct {
		serial    *uint64
		flowID    *uint64
		lock      *flowLockCarrier
		ts        *traceAndSpan
		isActive  *atomic.Bool
		unblocker *time.Timer
	}

	STTFM  = *skipmap.Uint32Map[*TracedFlow] // SequenceToTracedFlowMap
	FTSM   = *haxmap.Map[uint32, STTFM]      // FlowToStreamMap
	FTSTSM = *haxmap.Map[uint64, FTSM]       // FlowToStreamToSequenceMap
)

const (
	carrierDeadline  = 600 * time.Second /* 10m */
	trackingDeadline = 10 * time.Second  /* 10s */
)

func newFlowMutex(
	ctx context.Context,
	debug bool,
	flowToStreamToSequenceMap FTSTSM,
	traceToHttpRequestMap *haxmap.Map[string, *httpRequest],
) *flowMutex {
	fm := &flowMutex{
		Debug:                     debug,
		MutexMap:                  haxmap.New[uint64, *flowLockCarrier](),
		flowToStreamToSequenceMap: flowToStreamToSequenceMap,
		traceToHttpRequestMap:     traceToHttpRequestMap,
	}
	// reap orphaned `flowLockCarrier`s
	go fm.startReaper(ctx) // don't fear the reaper
	return fm
}

func (fm *flowMutex) log(
	ctx context.Context,
	serial *uint64,
	flowID *uint64,
	tcpFlags *uint8,
	seq, ack *uint32,
	timestamp *time.Time,
	message *string,
) {
	if !fm.Debug {
		return
	}

	json := gabs.New()

	id := ctx.Value(ContextID)
	logName := ctx.Value(ContextLogName)

	pcap, _ := json.Object("pcap")
	pcap.Set(id, "id")
	pcap.Set(logName, "ctx")

	serialStr := strconv.FormatUint(*serial, 10)
	pcap.Set(serialStr, "num")

	flowIDstr := strconv.FormatUint(*flowID, 10)
	json.Set(flowIDstr, "flow")

	tcpJSON, _ := json.Object("tcp")
	tcpJSON.Set(tcpFlagsStr[*tcpFlags], "flags")
	tcpJSON.Set(*seq, "seq")
	tcpJSON.Set(*ack, "ack")

	timestampJSON, _ := json.Object("timestamp")
	timestampJSON.Set(timestamp.Unix(), "seconds")
	timestampJSON.Set(timestamp.Nanosecond(), "nanos")

	labels, _ := json.Object("logging.googleapis.com/labels")
	labels.Set("pcap", "run.googleapis.com/tool")
	labels.Set(id, "run.googleapis.com/pcap/id")
	labels.Set(logName, "run.googleapis.com/pcap/name")

	operation, _ := json.Object("logging.googleapis.com/operation")
	operation.Set(logName, "producer")
	operation.Set(stringFormatter.Format("{0}/flow/{1}/debug", id, flowIDstr), "id")

	json.Set(stringFormatter.Format("#:{0} | flow:{1} | {2}", serialStr, flowIDstr, *message), "message")

	io.WriteString(os.Stderr, json.String()+"\n")
}

func (fm *flowMutex) startReaper(ctx context.Context) {
	// reaping is necessary as packets translations order is not guaranteed:
	// so if all `FIN+ACK`/`RST+*` are seen before other non-termination combinations within the same flow:
	//   - a new carrier will be created to hold its flow lock, and this carrier will not be organically reaped.
	// additionally: for connection pooling, long running not-used connections should be dropped to reclaim memory.
	ticker := time.NewTicker(carrierDeadline)

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			fm.MutexMap.ForEach(
				func(flowID uint64, carrier *flowLockCarrier) bool {
					if carrier == nil ||
						carrier.lastUnlockedAt == nil ||
						!carrier.mu.TryLock() {
						return true
					}
					defer carrier.mu.Unlock()
					lastUnlocked := time.Since(*carrier.lastUnlockedAt)
					if lastUnlocked >= carrierDeadline {
						fm.untrackConnection(ctx, &flowID, carrier)
						fm.MutexMap.Del(flowID)
						io.WriteString(os.Stderr, fmt.Sprintf("reaped flow '%d' after %v\n", flowID, lastUnlocked))
					}
					return true
				})
		}
	}
}

func (fm *flowMutex) getTracedFlow(
	flowID *uint64,
	seq, ack *uint32,
	local bool,
) (TracedFlowProvider, bool) {
	ref := seq
	if local {
		ref = ack
	}

	streamToSequenceMap, ok := fm.flowToStreamToSequenceMap.Get(*flowID)

	// no HTTP/1.1 request with a `traceID` has been seen for this `flowID`
	if !ok { // it is also possible that packet for HTTP request for this `flowID`
		return func(_ *uint32) (*TracedFlow, bool) { return nil, false }, false
	}

	// [ToDo]: memoize stream to trace mapping
	return func(stream *uint32) (*TracedFlow, bool) {
		// an HTTP/1.1 request with a `traceID` has already been seen for this `flowID`
		var tracedFlow, lastTracedFlow *TracedFlow = nil, nil
		if sttsm, ok := streamToSequenceMap.Get(*stream); ok {
			sttsm.Range(func(r uint32, tf *TracedFlow) bool {
				// Loop over the map keys (ascending sequence numbers) until one greater than `sequence` is found.
				// HTTP/1.1 is not multiplexed, so a new request using the same TCP connection ( i/e: pooling )
				// should be observed (alongside its `traceID`) with a higher sequence number than the previous one;
				// when the key (a sequence number) is greater than the current one, stop looping;
				// the previously analyzed `key` (sequence number) must be pointing to the correct `traceID`.
				// TL;DR: `traceID`s exist within a specific TCP sequence range, which configures a boundary.
				if *ref > r {
					tracedFlow = tf
				}
				lastTracedFlow = tf
				return true
			})

			// TCP sequence number is `uint32` so it is possible
			// for for it to be rolled over if it gets too big.
			// In such case `sequence` was not greater than any `key` in the map,
			// so the last visited `key` might be pointing to the correct `traceID`
			if tracedFlow == nil {
				tracedFlow = lastTracedFlow
			}

			return tracedFlow, true
		}
		return nil, false
	}, true
}

func (fm *flowMutex) trackConnection(
	ctx context.Context,
	lock *flowLockCarrier,
	serial *uint64,
	flowID *uint64,
	tcpFlags *uint8,
	seq, ack *uint32,
	local bool,
	ts *traceAndSpan,
) (*TracedFlow, bool) {
	if ts == nil {
		return nil, false
	}
	var isActive atomic.Bool

	tf := &TracedFlow{
		serial:   serial,
		flowID:   flowID,
		lock:     lock,
		ts:       ts,
		isActive: &isActive,
	}
	isActive.Store(true)
	tf.unblocker = time.AfterFunc(trackingDeadline, func() {
		// allow termination events to continue
		if !isActive.CompareAndSwap(true, false) {
			return
		}
		lock.mu.Lock()
		defer lock.mu.Unlock()
		tsBeforeUnblocling := time.Now()
		msgBeforeUnblocking := "unblocking"
		go fm.log(ctx, serial, flowID, tcpFlags, seq, ack, &tsBeforeUnblocling, &msgBeforeUnblocking)
		if lock.activeRequests.Add(-1) >= 0 {
			lock.wg.Done()
			tsAfterUnblocking := time.Now()
			msgAfterUnblocking := "unblocked"
			go fm.log(ctx, serial, flowID, tcpFlags, seq, ack, &tsAfterUnblocking, &msgAfterUnblocking)
		}
	})

	sequenceToTraceAndSpanMapProvider := func(streamToSequenceMap FTSM) STTFM {
		sequenceToTraceAndSpanMap := skipmap.NewUint32[*TracedFlow]()
		if local {
			sequenceToTraceAndSpanMap.Store(*ack, tf)
		} else {
			sequenceToTraceAndSpanMap.Store(*seq, tf)
		}
		streamToSequenceMap.Set(*ts.streamID, sequenceToTraceAndSpanMap)
		return sequenceToTraceAndSpanMap
	}

	streamToSequenceMap, _ := fm.flowToStreamToSequenceMap.
		GetOrCompute(*flowID, func() FTSM {
			streamToSequenceMap := haxmap.New[uint32, STTFM]()
			sequenceToTraceAndSpanMapProvider(streamToSequenceMap)
			return streamToSequenceMap
		})

	_, _ = streamToSequenceMap.GetOrCompute(*ts.streamID, func() STTFM {
		return sequenceToTraceAndSpanMapProvider(streamToSequenceMap)
	})

	return tf, true
}

func (fm *flowMutex) untrackConnection(
	_ context.Context,
	flowID *uint64,
	lock *flowLockCarrier,
) {
	defer func() {
		if r := recover(); r != nil && fm.Debug {
			transformerLogger.Println("PANIC@untrackConnection: ", r)
		}
	}()

	if ftsm, ok := fm.flowToStreamToSequenceMap.Get(*flowID); ok {
		streams := make([]uint32, ftsm.Len())
		streamIndex := 0
		ftsm.ForEach(func(stream uint32, sttsm STTFM) bool {
			streams[streamIndex] = stream
			sequences := make([]uint32, sttsm.Len())
			sequenceIndex := 0
			sttsm.Range(func(sequence uint32, tf *TracedFlow) bool {
				sequences[sequenceIndex] = sequence
				if tf.isActive.CompareAndSwap(true, false) {
					tf.unblocker.Stop()
				}
				// remove orphaned `traceID`s:
				fm.traceToHttpRequestMap.Del(*tf.ts.traceID)
				sequenceIndex += 1
				return true
			})
			streamIndex += 1
			for i := sequenceIndex - 1; i >= 0; i-- {
				sttsm.Delete(sequences[i])
			}
			return true
		})
		for i := streamIndex - 1; i >= 0; i-- {
			ftsm.Del(streams[i])
		}
		fm.flowToStreamToSequenceMap.Del(*flowID)
	}

	for lock.activeRequests.Load() > 0 {
		lock.wg.Done()
		lock.activeRequests.Add(-1)
	}

	fm.MutexMap.Del(*flowID)
}

func (fm *flowMutex) newFlowLockCarrier(serial, flowID *uint64) *flowLockCarrier {
	var activeRequests atomic.Int64
	var released atomic.Bool

	activeRequests.Store(0)
	released.Store(false)
	createdAt := time.Now()

	return &flowLockCarrier{
		serial:         serial, // packet that created this lock
		flowID:         flowID, // flow that created this lock
		mu:             new(sync.Mutex),
		wg:             new(sync.WaitGroup),
		released:       &released,
		createdAt:      &createdAt,
		activeRequests: &activeRequests,
	}
}

func (fm *flowMutex) lock(
	ctx context.Context,
	serial *uint64,
	flowID *uint64,
	tcpFlags *uint8,
	seq, ack *uint32,
	local bool,
) (
	*flowLock,
	TraceAndSpanProvider,
) {
	carrier, _ := fm.MutexMap.
		GetOrCompute(*flowID,
			func() *flowLockCarrier {
				return fm.newFlowLockCarrier(serial, flowID)
			})

	mu := carrier.mu
	wg := carrier.wg

	// changing the order of `Wait` and `Lock` causes a deadlock
	if isConnectionTermination(tcpFlags) {
		tsBeforeWaiting := time.Now()
		msgBeforeWaiting := "waiting"
		go fm.log(ctx, serial, flowID, tcpFlags, seq, ack, &tsBeforeWaiting, &msgBeforeWaiting)
		// Connection termination events must wait for the flow to stop being trace-tracked.
		// some important considerations:
		//   - If this flow is not trace-tracked ( meaning this termination event acquires the lock ahead of any other TCP segment carrying an HTTP message with trace information ) `Wait()` won't block:
		//       - this could happen because not only packet processing but also layers processing are done concurrently in order to complete packet translations as fast as possible.
		//           - the side effect of this high level of concurrency is that order of execution is not guaranteed and so trace tracking is currently done as best-effort.
		//           - in practice, the common scenario is for connection termination events to arrive at `lock` after TCP segments container tracing information.
		//       - this is currently by design: doing it differently would require to store TCP events in memory which is not great to keep memory footprint small.
		//           - currently the only state stored in memory is: a Map from TCP flow to HTTP stream to TCP sequence that points to its corresponding trace information.
		//   - This is `true` also for TCP segments carrying HTTP responses if those acquire the lock before the ones carrying HTTP requests, but these won't clear/release trace-tracking information.
		// How to do it differently?: we'd need to store semaphores in a table indexable by `FlowID` and have termination events wait on them until the TCP segments carrying tracing information are seen.
		//   - this, however, is a wild assumption, as TCP segments carrying tracing information might never arrive and so the termination events will be locked for no reason.
		//     - if this a price we'd like to pay, then this scenario could be handled by having a watchdog running periodically to unblock termination events after a deadline, but this approach feels clumsy at the moment.
		//     - why we would not want to do this?: waiting on some non-deterministical event to happen means that a go-routine from the packet processing pool will be hijacked maybe for no good reason.

		// if execution is done:
		//   - do not throttle termination packets processing
		//   - release go routines ASAP to allow termination flow to continue
		select {
		case <-ctx.Done():
			break
		default:
			wg.Wait()
		}

		tsAfterWaiting := time.Now()
		msgAfterWaiting := "continue"
		go fm.log(ctx, serial, flowID, tcpFlags, seq, ack, &tsAfterWaiting, &msgAfterWaiting)
	}
	// it is possible that all packets for this flow arrive to `Lock` at almost the same time:
	//   - which means that termination could delete the reference to `FlowLock` from `MutexMap` while non terminating ones are waiting for the lock
	mu.Lock()

	lockAcquiredTS := time.Now()
	carrier.lastLockedAt = &lockAcquiredTS

	tracedFlowProvider, _ := fm.getTracedFlow(flowID, seq, ack, local)

	_unlock := func() {
		defer func(mu *sync.Mutex) {
			if err := recover(); err != nil {
				io.WriteString(os.Stderr,
					fmt.Sprintf("error at flow[%d]: %+v | %+v\n", *flowID, err, mu))
			}
		}(mu)
		defer mu.Unlock()
		lastUnlockedTS := time.Now()
		carrier.lastLockedAt = &lastUnlockedTS
	}

	UnlockAndReleaseFN := func(ctx context.Context) (bool, *time.Duration) {
		defer _unlock()
		// many translations within the same flow may be waiting to acquire the lock;
		// if multiple translations try to release, i/e: 2*`FIN+ACK`,
		// then both will release the lock, but just 1 must yield connection untracking.
		if carrier.activeRequests.Load() == 0 &&
			carrier.released.CompareAndSwap(false, true) {
			// termination packets will clean the tracing info available for each flow:
			//   - give some margin for all other packets to access flow state, and then flush it.
			select {
			case <-ctx.Done():
				// untrack connection immediately if the context is done
				fm.untrackConnection(ctx, flowID, carrier)
			default:
				time.AfterFunc(trackingDeadline, func() {
					timestamp := time.Now()
					message := "untracking"
					go fm.log(ctx, serial, flowID, tcpFlags, seq, ack, &timestamp, &message)
					fm.untrackConnection(ctx, flowID, carrier)
				})
			}
			lockLatency := time.Since(lockAcquiredTS)
			return true, &lockLatency
		}
		lockLatency := time.Since(lockAcquiredTS)
		return false, &lockLatency
	}

	UnlockWithTCPFlagsFN := func(
		ctx context.Context,
		tcpFlags *uint8,
	) (bool, *time.Duration) {
		if isConnectionTermination(tcpFlags) {
			return UnlockAndReleaseFN(ctx)
		}
		defer _unlock()
		lockLatency := time.Since(lockAcquiredTS)
		return false, &lockLatency
	}

	// this is just an alias of `UnlockWithTCPFlagsFN`,
	//   - but it uses the same `tcpFlags` used to acquire the `lock`
	UnlockFn := func(ctx context.Context) (bool, *time.Duration) {
		return UnlockWithTCPFlagsFN(ctx, tcpFlags)
	}

	IsHTTP2FN := func() bool { return carrier.isHTTP2 }

	// since all TCP data is known:
	//   - it is possible to return a `traceID`
	//   - since this is guarded by a lock, it is thread-safe
	// much richer analysis is also possible

	// these are the only methods for consumers to interact with the lock
	lock := &flowLock{
		IsHTTP2:            IsHTTP2FN,
		Unlock:             UnlockFn,
		UnlockAndRelease:   UnlockAndReleaseFN,
		UnlockWithTCPFlags: UnlockWithTCPFlagsFN,
	}

	if *tcpFlags&(tcpSyn|tcpFin|tcpRst) == 0 {
		// provide trace tracking only for TCP `PSH+ACK`.
		// For HTTP/2 multiple streams are delivered over the same TCP connection, so:
		//   - it is possible to observe multiple requests and responses in the same TCP segment,
		//   - `unlock` must handle the scenario where the same TCP segment contains both requests and responses.
		// It is possible to receive requests/responses without `traceID`, so:
		//   - both must be accounted to accurately calculate the total number of `activeRequests`:
		//     - this is regardless of `traceID` being available; otherwise, termination packets are blocked:
		//       - this will not trigger a deadlock as only the termination is being delayed,
		//       - the `unblocker`s will eventually allow termination packets to make progress.
		// The following flow unlocking mechanism tries to:
		//   - prevent trace tracking information removal by connection termination packets
		//   - store trace tracking information for HTTP requests: that will be used to link to HTTP responses
		lock.UnlockWithTraceAndSpan = func(
			ctx context.Context,
			tcpFlags *uint8,
			isHTTP2 bool,
			requestStreams []uint32,
			responseStreams []uint32,
			requestTS map[uint32]*traceAndSpan,
			responseTS map[uint32]*traceAndSpan,
		) (*int64, *time.Duration) {
			carrier.isHTTP2 = isHTTP2
			activeRequests := carrier.activeRequests.Load()

			sizeOfRequestStreams := int64(len(requestStreams))
			sizeOfResponseStreams := int64(len(responseStreams))

			sizeOfRequestTraceAndSpans := len(requestTS)
			// handle flow `unlock` for requests
			if sizeOfRequestTraceAndSpans > 0 || sizeOfRequestStreams > 0 {
				for _, stream := range requestStreams {
					activeRequests = carrier.activeRequests.Add(1)
					if ts, tsAvailable := requestTS[stream]; tsAvailable {
						// tracking connections allows for HTTP responses without trace headers
						// to be correlated with the request that brought them to existence.
						if tf, tracked := fm.trackConnection(ctx,
							carrier, serial, flowID, tcpFlags, seq, ack, local, ts); tracked {
							if activeRequests > 0 {
								// if HTTP more responses are seen before the currently observed requests:
								//   - do block `FIN+ACK` from making progress;
								// another alternative would be to allow the `unblocker` to call `Done()` on `wg`
								wg.Add(1)
							} else if tf.isActive.CompareAndSwap(true, false) {
								// de-activate the `unblocker` for this `TracedFlow`
								tf.unblocker.Stop()
							}
						}
					}
				}
			}

			sizeOfResponseTraceAndSpans := len(responseTS)
			// handle flow `unlock` for responses
			if sizeOfResponseTraceAndSpans > 0 || sizeOfResponseStreams > 0 {
				for _, stream := range responseStreams {
					activeRequests = carrier.activeRequests.Add(-1)
					if ts, tsAvailable := responseTS[stream]; tsAvailable {
						if tf, traceFound := tracedFlowProvider(ts.streamID); traceFound {
							if activeRequests >= 0 &&
								*tf.ts.traceID == *ts.traceID &&
								tf.isActive.CompareAndSwap(true, false) {
								tf.unblocker.Stop()
								wg.Done()
							}
						}
					}
				}
			}

			_, lockLatency := UnlockWithTCPFlagsFN(ctx, tcpFlags)
			return &activeRequests, lockLatency
		}
	} else {
		activeRequests := carrier.activeRequests.Load()
		// do not provide trace tracking for non TCP `PSH+ACK`
		lock.UnlockWithTraceAndSpan = func(
			ctx context.Context,
			tcpFlags *uint8, _ bool,
			_ []uint32, _ []uint32,
			_ map[uint32]*traceAndSpan,
			_ map[uint32]*traceAndSpan,
		) (*int64, *time.Duration) {
			// fallback to unlock by TCP flags
			_, lockLatency := UnlockWithTCPFlagsFN(ctx, tcpFlags)
			return &activeRequests, lockLatency
		}
	}

	return lock, func(streamID *uint32) (*traceAndSpan, bool) {
		if tf, ok := tracedFlowProvider(streamID); ok {
			return tf.ts, ok
		}
		return nil, false
	}
}
