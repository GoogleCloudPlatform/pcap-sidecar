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

package pcap

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	ps "github.com/mitchellh/go-ps"
)

var tcpdumpLogger = log.New(os.Stderr, "[tcpdump] - ", log.LstdFlags)

func (t *Tcpdump) IsActive() bool {
	return t.isActive.Load()
}

func (t *Tcpdump) buildArgs(ctx context.Context) []string {
	cfg := t.config

	args := []string{"-n", "-Z", "root", "-i", cfg.Iface, "-s", fmt.Sprintf("%d", cfg.Snaplen)}

	if cfg.Output != "stdout" {
		directory := filepath.Dir(cfg.Output)
		template := filepath.Base(cfg.Output)
		fileNameTemplate := fmt.Sprintf("%s/%s.%s", directory, template, cfg.Extension)
		args = append(args, "-w", fileNameTemplate)
	}

	if cfg.Interval > 0 {
		args = append(args, "-G", fmt.Sprintf("%d", cfg.Interval))
	}

	if cfg.Iface != anyDeviceName {
		if filter := providePcapFilter(ctx,
			&cfg.Filter, cfg.Filters); *filter != "" {
			args = append(args, *filter)
		}
	}

	return args
}

func (t *Tcpdump) kill(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Signal(syscall.SIGTERM)
}

func (t *Tcpdump) findAndKill(pid int) (uint32, uint32, error) {
	processes, err := ps.Processes()
	if err != nil {
		return 0, 0, err
	}

	killCounter := uint32(0)
	procsCounter := uint32(0)
	for _, p := range processes {
		procID := p.Pid()
		execName := p.Executable()
		if execName == "tcpdump" && procID == pid {
			tcpdumpLogger.Printf("killing %s(%d)\n", execName, procID)
			if err := t.kill(procID); err == nil {
				killCounter++
			}
			procsCounter++
		}
	}
	return killCounter, procsCounter, nil
}

func (t *Tcpdump) Start(
	ctx context.Context,
	_ []PcapWriter,
	stopDeadline <-chan *time.Duration,
) error {
	// atomically activate the packet capture
	if !t.isActive.CompareAndSwap(false, true) {
		return fmt.Errorf("already started")
	}

	args := t.buildArgs(ctx)

	cmd := exec.CommandContext(ctx, t.tcpdump, args...)

	// prevent child process from hijacking signals
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, Pgid: 0,
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 1900 * time.Millisecond

	cmdLine := strings.Join(cmd.Args[:], " ")
	if err := cmd.Start(); err != nil {
		tcpdumpLogger.Printf("'%+v' - error: %+v\n", cmdLine, err)
		return err
	}

	pid := cmd.Process.Pid
	tcpdumpLogger.Printf("EXEC(%d): %v\n", pid, cmdLine)

	<-ctx.Done()
	ctxDoneTS := time.Now()

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		tcpdumpLogger.Printf("[pid:%d] - %+v' - error: %+v\n", pid, cmdLine, err)
		cmd.Process.Kill()
	}

	cmdStopChan := make(chan error, 1)
	go func(cmd *exec.Cmd, cmdStopChan chan<- error) {
		cmdStopChan <- cmd.Wait()
	}(cmd, cmdStopChan)

	engineStopDeadline := <-stopDeadline
	engineStopTimeout := *engineStopDeadline - time.Since(ctxDoneTS)
	timer := time.NewTimer(engineStopTimeout)

	var err error
	select {
	case <-timer.C:
		err = context.DeadlineExceeded
	case err = <-cmdStopChan:
		if !timer.Stop() {
			<-timer.C
		}
		close(cmdStopChan)
	}

	// make sure previous execution does not survive
	killedProcs, numProcs, killErr := t.findAndKill(pid)
	tcpdumpLogger.Printf("STOP [tcpdump(%d)] <%d/%d>: %+v\n", pid, killedProcs, numProcs, cmdLine)

	t.isActive.Store(false)

	return errors.Join(ctx.Err(), err, killErr)
}

func NewTcpdump(config *PcapConfig) (PcapEngine, error) {
	tcpdumpBin, err := exec.LookPath("tcpdump")
	if err != nil {
		return nil, fmt.Errorf("tcpdump is unavailable")
	}

	var isActive atomic.Bool
	isActive.Store(false)

	tcpdump := Tcpdump{config: config, tcpdump: tcpdumpBin, isActive: &isActive}
	return &tcpdump, nil
}
