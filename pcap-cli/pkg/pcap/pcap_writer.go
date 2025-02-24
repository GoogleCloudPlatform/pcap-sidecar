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
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"time"
	"unsafe"

	"dario.cat/mergo"
	"github.com/easyCZ/logrotate"
	"github.com/itchyny/timefmt-go"
)

var pcapWriterLogger = log.New(os.Stderr, "[writer] - ", log.LstdFlags)

type (
	PcapWriter interface {
		io.Writer
		io.Closer
		Rotate()
		IsStdOutOrErr() bool
		GetIface() *string
	}

	pcapWriter struct {
		*logrotate.Writer
		iface            *string
		isStdOutOrErr    bool
		v                reflect.Value
		osFile           reflect.Value
		osFileSync       reflect.Value
		bufioWriter      reflect.Value
		bufioWriterFlush reflect.Value
	}

	pcapFileNameProvider struct {
		directory string
		template  string
		location  *time.Location
	}
)

var defaultLogrotateOptions logrotate.Options = logrotate.Options{
	Directory:            "/",
	MaximumFileSize:      0,
	MaximumLifetime:      0,
	FlushAfterEveryWrite: false,
	FileNameFunc:         func() string { return "" },
}

//go:linkname rotate github.com/easyCZ/logrotate.(*Writer).rotate
func rotate(w *logrotate.Writer)

func makeSetable(v reflect.Value) reflect.Value {
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

func getField(v reflect.Value, field string) reflect.Value {
	return v.Elem().FieldByName(field)
}

func getSetableField(v reflect.Value, field string) reflect.Value {
	return makeSetable(getField(v, field))
}

func (w *pcapWriter) Rotate() {
	// if `PcapWriter` encapsulates `std[out|err]` do not rotate,
	// just call `Flush` on the underlying `bufio.Writer` for `os.Std{out|err}`
	if w.isStdOutOrErr {
		return
	}

	// see: https://pkg.go.dev/cmd/compile#:~:text=//-,go%3Alinkname,-localname%20%5Bimportpath.name
	rotate(w.Writer)
}

func (w *pcapWriter) GetIface() *string {
	return w.iface
}

func (w *pcapWriter) IsStdOutOrErr() bool {
	return w.isStdOutOrErr
}

func (p *pcapFileNameProvider) get() string {
	fileName := timefmt.Format(time.Now().In(p.location), p.template)
	pcapWriterLogger.Printf("new file: %s\n", fileName)
	return fileName
}

func getPcapWriterLocationForTimezone(timezone *string) *time.Location {
	location, err := time.LoadLocation(*timezone)
	if err != nil {
		return time.UTC
	}
	return location
}

func newPcapWriterFileNameProvider(template, timezone *string) *pcapFileNameProvider {
	fileNameTemplate := *template
	return &pcapFileNameProvider{
		directory: filepath.Dir(fileNameTemplate),
		template:  filepath.Base(fileNameTemplate),
		location:  getPcapWriterLocationForTimezone(timezone),
	}
}

func newPcapWriterForStdout(logger *log.Logger) (*logrotate.Writer, error) {
	return logrotate.New(logger, defaultLogrotateOptions)
}

func newPcapWriter(logger *log.Logger, template, extension, timezone *string, interval *int) (*logrotate.Writer, error) {
	var fileMaxLifetime time.Duration = 0 // time.Minute
	if *interval > 0 {
		fileMaxLifetime = time.Duration(*interval) * time.Second
	}

	fileNameTemplate := fmt.Sprintf("%s.%s", *template, *extension)
	fileNameProvider := newPcapWriterFileNameProvider(&fileNameTemplate, timezone)

	options := logrotate.Options{
		Directory:       fileNameProvider.directory,
		MaximumLifetime: fileMaxLifetime,
		FileNameFunc:    func() string { return fileNameProvider.get() },
	}

	if err := mergo.Merge(&options, defaultLogrotateOptions); err != nil {
		return nil, err
	}

	return logrotate.New(logger, options)
}

func isStdoutPcapWriter(template, extension *string, interval *int) bool {
	return ((template == nil && extension == nil) || (*template == "stdout" || *template == "stderr")) && *interval == 0
}

func NewStdoutPcapWriter(ctx context.Context, ifaceAndIndex *string) (PcapWriter, error) {
	return NewPcapWriter(ctx, ifaceAndIndex, nil, nil, nil, 0)
}

func NewPcapWriter(ctx context.Context, ifaceAndInfex, template, extension, timezone *string, interval int) (PcapWriter, error) {
	isStdOutOrErr := isStdoutPcapWriter(template, extension, &interval)

	loggerPrefix := fmt.Sprintf("[pcap/writer] - [%s] – ", *ifaceAndInfex)
	if isStdOutOrErr {
		loggerPrefix += "[stdout] – "
	} else {
		loggerPrefix = fmt.Sprintf("%s[%s] - ", loggerPrefix, *extension)
	}
	logger := log.New(os.Stderr, loggerPrefix, log.LstdFlags)

	var err error
	var writer *logrotate.Writer

	if isStdOutOrErr {
		// Using `logrotate` to make `os.Stdout` safe to be concurrently written by PCAP engines
		writer, err = newPcapWriterForStdout(logger)
	} else {
		writer, err = newPcapWriter(logger, template, extension, timezone, &interval)
	}

	if err != nil {
		return nil, err
	}

	// `logrotate` does not provide handles to `*bufio.Writer::Flush`/`*os.File::Syinc`
	// the underlying Writer/File so it is necessary to get handles on them.
	// Since PCAP engines are started atomically and current execution must complete
	// before a new one can be started; it is safe to `flush` and `sync` PCAP files.
	// https://github.com/easyCZ/logrotate/blob/master/writer.go
	v := reflect.ValueOf(writer)
	osFile := getSetableField(v, "f")
	osFileSync := osFile.MethodByName("Sync")
	bufioWriter := getSetableField(v, "bw")
	bufioWriterFlush := bufioWriter.MethodByName("Flush")

	if isStdOutOrErr {
		// injecting `os.Stdout` into `logrotate.Writer` instance
		osFile.Set(reflect.ValueOf(os.Stdout))
		bufioWriter.Set(reflect.ValueOf(bufio.NewWriterSize(os.Stdout, 1)))
	}

	w := &pcapWriter{writer, ifaceAndInfex, isStdOutOrErr, v, osFile, osFileSync, bufioWriter, bufioWriterFlush}

	go func(ctx context.Context, writer *logrotate.Writer, block bool) {
		if !block {
			return
		}
		<-ctx.Done()
		logger.Println("- ROTATE")
		rotate(writer)
	}(ctx, writer, !isStdOutOrErr)

	logger.Println("- created")

	return w, nil
}
