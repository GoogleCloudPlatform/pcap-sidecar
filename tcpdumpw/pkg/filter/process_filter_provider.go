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

package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/pkg/pcap"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ochinchina/supervisord/xmlrpcclient"
	sf "github.com/wissance/stringFormatter"
)

type (
	processInfo struct {
		key  *string
		name *string
		id   int
	}

	tcpSocket struct {
		Protocol   string `json:"f"`
		LocalAddr  string `json:"l"`
		RemoteAddr string `json:"r"`
		Program    string `json:"p"`
		PID        int    `json:"i"`
		FD         int    `json:"d"`
	}

	ProcessFilterProvider struct {
		pcap.PcapFilters
		client        *xmlrpcclient.XMLRPCClient
		supervisorURL *string
		processNames  *string
		interval      time.Duration
		debug         bool
		initialize    sync.Once
		sockets       mapset.Set[string]
	}
)

const (
	networkScripts      = "/scripts/net"
	socketsScript       = "getTCPsockets"
	requiredSocketState = "ESTAB"

	socketTemplate          = "process[name:{0}|id:{1}]/socket[local={2}|remote={3}]"
	socketInfoTemplate      = socketTemplate + " | {4}"
	socketFilteredTemaplate = socketTemplate + "/FILTERED | {4}"
	socketRejectedTemplate  = socketTemplate + "/REJECTED | {4}"

	processTemplate      = "process[name:{0}]"
	processInfoTemplate  = processTemplate + "[id:{1}] | {2}"
	processErrorTemplate = processTemplate + "[id:{1}] | error: {2}"
	processFoundTemplate = processTemplate + " | PID: {1} | KEY: {2}"

	socketRejectedWithInvalidInfo = "invalid pid/name"

	socketFiltered            = "allowed: {0}"
	socketFilteredByLocalPort = socketFiltered + " | by local port '{1}'"
)

func (p *ProcessFilterProvider) logSocketFilter(
	stream io.Writer,
	template string,
	socket *tcpSocket,
	message *string,
) {
	if p.debug {
		fmt.Fprintln(stream,
			sf.Format(template, socket.Program, socket.PID, socket.LocalAddr, socket.RemoteAddr, *message))
	}
}

func (p *ProcessFilterProvider) logSocketFilterRejected(
	socket *tcpSocket,
	err error,
) {
	message := err.Error()
	p.logSocketFilter(os.Stderr, socketRejectedTemplate, socket, &message)
}

func (p *ProcessFilterProvider) logSocketFilterApplied(
	socket *tcpSocket,
	message string,
) {
	p.logSocketFilter(os.Stdout, socketFilteredTemaplate, socket, &message)
}

func (p *ProcessFilterProvider) logSocketFilterInfo(
	socket *tcpSocket,
	message string,
) {
	p.logSocketFilter(os.Stdout, socketInfoTemplate, socket, &message)
}

func (p *ProcessFilterProvider) logProcessFilter(
	stream io.Writer,
	template string,
	process *processInfo,
	message *string,
) {
	if p.debug {
		fmt.Fprintln(stream,
			sf.Format(template, *process.name, process.id, *message))
	}
}

func (p *ProcessFilterProvider) logProcessFilterInfo(
	process *processInfo,
	message string,
) {
	p.logProcessFilter(os.Stdout, processInfoTemplate, process, &message)
}

func (p *ProcessFilterProvider) logProcessFilterError(
	process *processInfo,
	err error,
) {
	message := err.Error()
	p.logProcessFilter(os.Stdout, processErrorTemplate, process, &message)
}

func (p *ProcessFilterProvider) script(
	script *string,
) string {
	return sf.Format("{0}/{1}", networkScripts, *script)
}

func (p *ProcessFilterProvider) execScript(
	ctx context.Context,
	script string,
	args ...string,
) (string, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, p.script(&script), args...)
	// cmd.Stderr = io.Discard
	cmd.Stderr = &stderr

	outputBytes, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, stderr.String())
		return "", err
	}
	return string(outputBytes), err
}

func (p *ProcessFilterProvider) getTCPsockets(
	ctx context.Context,
	process *processInfo,
) ([]*tcpSocket, error) {
	pid := strconv.Itoa(process.id)

	// REQUIRES: [netstat](https://man7.org/linux/man-pages/man8/netstat.8.html)
	output, err := p.execScript(ctx, socketsScript, *process.name, pid, requiredSocketState)
	if err != nil {
		socketsScriptErr := fmt.Errorf(sf.Format("script[{0}] | %v", socketsScript), err)
		p.logProcessFilterError(process, socketsScriptErr)
		return nil, err
	}

	var sockets []*tcpSocket

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		socket := new(tcpSocket)
		if err := json.Unmarshal([]byte(line), socket); err == nil {
			sockets = append(sockets, socket)
			p.logSocketFilterInfo(socket, line)
		} else if p.debug {
			jsonErr := fmt.Errorf("%s | %v", line, err)
			p.logProcessFilterError(process, jsonErr)
		}
	}
	return sockets, err
}

func (p *ProcessFilterProvider) getProcessPID(
	_ context.Context,
) []*processInfo {
	processNames := strings.Split(*p.processNames, ",")

	var processes []*processInfo

	for _, processName := range processNames {
		if processName == "" {
			continue
		}

		defaultKey := p.newProcessKey(processName, 0)

		process := &processInfo{
			name: &processName,
			key:  &defaultKey,
			id:   0,
		}

		if reply, err := p.client.GetProcessInfo(processName); err == nil {
			key := p.newProcessKey(reply.Name, reply.Pid)

			process.key = &key
			process.id = reply.Pid

			processes = append(processes, process)

			p.logProcessFilterInfo(process, reply.GetFullName())
		} else if p.debug {
			p.logProcessFilterError(process, err)
		}
	}

	return processes
}

func (p *ProcessFilterProvider) parsePort(
	socket2tuple string,
) uint16 {
	parts := strings.Split(socket2tuple, ":")

	if port, err := strconv.ParseUint(parts[len(parts)-1], 10, 16); err == nil && port <= 0xFFFF {
		return uint16(port)
	}

	return 0
}

func (p *ProcessFilterProvider) newProcessKey(
	name string,
	id int,
) string {
	return sf.Format("{0}:{1}", name, id)
}

func (p *ProcessFilterProvider) isProcessKey(
	process *processInfo,
	socketKey *string,
) bool {
	prefix := sf.Format("{0}/", *process.key)
	return strings.HasPrefix(*socketKey, prefix)
}

func (p *ProcessFilterProvider) newSocketKey(
	process *processInfo,
	socket *tcpSocket,
) string {
	return sf.Format("{0}/{1}/{2}/{3}", *process.key,
		socket.Protocol, socket.LocalAddr, socket.RemoteAddr)
}

func (p *ProcessFilterProvider) toSocket(
	process *processInfo,
	socketKey *string,
) *tcpSocket {
	parts := strings.SplitN(*socketKey, "/", 4)
	return &tcpSocket{
		Protocol:   parts[1],
		LocalAddr:  parts[2],
		RemoteAddr: parts[3],
		Program:    *process.name,
		PID:        process.id,
	}
}

func (p *ProcessFilterProvider) applyFilter(
	wg *sync.WaitGroup,
	process *processInfo,
	sockets map[string]*tcpSocket,
	socketKey *string,
	allowed bool,
) error {
	defer wg.Done()

	var socket *tcpSocket
	found := false
	if socket, found = sockets[*socketKey]; !found {
		// handle case when a socket is closed:
		//   - `sockets` map only contains sockets in state: 'ESTABLISHED'.
		//   - `socketKey` contains all information to create a `tcpSocket`.
		socket = p.toSocket(process, socketKey)
	}

	// `pcap.PcapFilters` is backed by a thread-safe Set:
	//   - it is safe to update allowed/denied sockets concurrenly.
	if allowed {
		if p.AllowSocket(socket.LocalAddr, socket.RemoteAddr) {
			p.sockets.Remove(*socketKey)
		}
	} else if p.DenySocket(socket.LocalAddr, socket.RemoteAddr) {
		p.sockets.Add(*socketKey)
	}

	p.logSocketFilterApplied(socket, sf.Format(socketFiltered, allowed))

	return nil
}

// Creates a Set containing only keys from process owned sockets.
// The returned Set is effectively a SubSet of `p.sockets`.
func (p *ProcessFilterProvider) processView(
	process *processInfo,
) mapset.Set[string] {
	sockets := mapset.NewThreadUnsafeSet[string]()
	p.sockets.Each(func(key string) bool {
		if p.isProcessKey(process, &key) {
			sockets.Add(key)
		}
		return false
	})
	return sockets
}

func (p *ProcessFilterProvider) filterSockets(
	view mapset.Set[string],
	process *processInfo,
	sockets map[string]*tcpSocket,
) {
	addrs := mapset.NewThreadUnsafeSetFromMapKeys(sockets)

	// see: https://github.com/deckarep/golang-set/blob/v2.7.0/set.go#L76-L85
	// 	- "The returned set will contain all elements of this set that are not also elements of other."
	denied := addrs.Difference(view)
	allowed := view.Difference(addrs)

	p.logProcessFilterInfo(process,
		sf.Format("+sockets: {0}", allowed.ToSlice()))
	p.logProcessFilterInfo(process,
		sf.Format("-sockets: {0}", denied.ToSlice()))

	wg := sync.WaitGroup{}
	wg.Add(denied.Cardinality() + allowed.Cardinality())

	// reject packet translations for new ESTABLISHED connections
	denied.Each(func(socketKey string) bool {
		go p.applyFilter(&wg, process, sockets, &socketKey, false /* allowed */)
		return false
	})

	// allow packet translations for no longer ESTABLISHED connections
	allowed.Each(func(socketKey string) bool {
		go p.applyFilter(&wg, process, sockets, &socketKey, true /* allowed */)
		return false
	})

	wg.Wait()
}

func (p *ProcessFilterProvider) updateFilter(
	ctx context.Context,
	view mapset.Set[string],
	process *processInfo,
	sockets []*tcpSocket,
) {
	socks := make(map[string]*tcpSocket)

	for _, socket := range sockets {
		if socket.PID == process.id || socket.Program == *process.name {
			socks[p.newSocketKey(process, socket)] = socket
		} else if p.debug {
			err := fmt.Errorf(socketRejectedWithInvalidInfo)
			p.logSocketFilterRejected(socket, err)
		}
	}

	p.filterSockets(view, process, socks)
}

func (p *ProcessFilterProvider) setFilter(
	ctx context.Context,
) {
	processes := p.getProcessPID(ctx)

	if len(processes) == 0 {
		return
	}

	for _, process := range processes {
		if sockets, err := p.getTCPsockets(ctx, process); err == nil {
			// get a view of process owned sockets
			view := p.processView(process)
			go p.updateFilter(ctx, view, process, sockets)
		}
	}
}

func (p *ProcessFilterProvider) init(
	ctx context.Context,
) {
	// Process owned sockets are volatile:
	//  - sockets may be closed for many reasons.
	//  - the list of sockets to not-be-tracked changes.
	// It is necessary to update the filter regularly.
	ticker := time.NewTicker(p.interval)

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			p.setFilter(ctx)
		}
	}
}

func (p *ProcessFilterProvider) Initialize(
	ctx context.Context,
) pcap.PcapFilterProvider {
	// see: https://pkg.go.dev/sync#Once
	p.initialize.Do(func() {
		go p.init(ctx)
	})
	return p
}

func (p *ProcessFilterProvider) Get(
	ctx context.Context,
) (*string, bool) {
	_ = p.Initialize(ctx)
	return nil, false
}

func (p *ProcessFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return sf.Format("ProcessFilter[{0}] => ({1})", *p.processNames, *filter)
	}
	return sf.Format("ProcessFilter[{0}] => (nil)", *p.processNames)
}

func (p *ProcessFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newProcessFilterProvider(
	serverURL *string,
	processNames *string,
	refreshSecs uint8,
	debug bool,
	compatFilters pcap.PcapFilters,
) PcapFilterProvider {
	interval := time.Duration(refreshSecs) * time.Second
	client := xmlrpcclient.NewXMLRPCClient(*serverURL, debug)

	provider := &ProcessFilterProvider{
		initialize:    sync.Once{},
		client:        client,
		supervisorURL: serverURL,
		processNames:  processNames,
		interval:      interval,
		debug:         debug,
		PcapFilters:   compatFilters,
		sockets:       mapset.NewSet[string](),
	}

	return provider
}
