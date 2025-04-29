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

package gcs

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/constants"
	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/log"
	"github.com/pkg/errors"
	sf "github.com/wissance/stringFormatter"
	"go.uber.org/zap/zapcore"
)

type (
	ClosableWriter interface {
		io.Writer
		io.Closer
	}

	Exporter interface {
		Export(
			ctx context.Context,
			srcPcap *string,
			compress bool,
			delete bool,
		) (*string, *int64, error)
	}

	exporter struct {
		directory    string
		maxRetries   uint
		retriesDelay time.Duration
		logger       *log.Logger
	}

	nilExporter struct {
		*exporter
	}

	exportCallback func(
		cw ClosableWriter,
		srcPcapFile *string,
		tgtPcapFile *string,
		pcapBytes *int64,
	) error
)

const (
	PCAP_EXPORT = constants.PCAP_EXPORT
)

var nilExporterError = fmt.Errorf("GCS export is disabled")

func newExporter(
	logger *log.Logger,
	directory string,
	maxRetries uint,
	retriesDelay uint,
) *exporter {
	return &exporter{
		directory:    directory,
		maxRetries:   maxRetries,
		retriesDelay: time.Duration(retriesDelay) * time.Second,
		logger:       logger,
	}
}

func NewNilExporter(
	logger *log.Logger,
) Exporter {
	return &nilExporter{
		exporter: newExporter(logger, "", 0, 0),
	}
}

func (x *nilExporter) Export(
	ctx context.Context,
	srcPcapFile *string,
	compress bool,
	delete bool,
) (*string, *int64, error) {
	tgtPcap := ""
	pcapBytes := int64(0)

	err := errors.Wrap(
		nilExporterError,
		sf.Format("not exported: {0}", *srcPcapFile),
	)

	x.logger.LogEvent(
		zapcore.WarnLevel,
		sf.Format("lost PCAP file: {0}", *srcPcapFile),
		PCAP_EXPORT,
		map[string]any{
			"source": *srcPcapFile,
			"target": x.toTargetPcapFile(srcPcapFile, compress),
		},
		err)

	return &tgtPcap, &pcapBytes, err
}

func (x *exporter) toTargetPcapFile(
	srcPcapFile *string,
	compress bool,
) string {
	pcapFileName := filepath.Base(*srcPcapFile)
	tgtPcapFile := filepath.Join(x.directory, pcapFileName)
	// If compressing PCAP files is enabled, add `gz` siffux to the destination PCAP file path
	if compress {
		return sf.Format("{0}.gz", tgtPcapFile)
	}
	return tgtPcapFile
}

func (x *exporter) export(
	srcPcapFile *string,
	tgtPcapFile *string,
	outputPcapWriter ClosableWriter,
	compress bool,
	delete bool,
	callback exportCallback,
) (int64, error) {
	pcapBytes := int64(0)

	// Open source PCAP file: the one thas is being moved to the destination directory
	inputPcapWriter, err := os.OpenFile(*srcPcapFile, os.O_RDONLY|os.O_EXCL, 0)
	if err != nil {
		x.logger.LogFsEvent(
			zapcore.ErrorLevel,
			sf.Format("failed to OPEN file {0}", *srcPcapFile),
			PCAP_EXPORT,
			*srcPcapFile,
			*tgtPcapFile,
			0,
			err)
		return pcapBytes, errors.Wrap(err,
			sf.Format("failed to open source pcap: {0}", *srcPcapFile))
	}

	// Copy source PCAP into destination PCAP, compressing destination PCAP is optional
	if compress {
		// see: https://pkg.go.dev/compress/gzip#NewWriter
		gzipPcap := gzip.NewWriter(outputPcapWriter)
		pcapBytes, err = io.Copy(gzipPcap, inputPcapWriter)
		gzipPcap.Flush()
		gzipPcap.Close() // this is still required; `Close()` on parent `Writer` does not trigger `Close()` at `gzip`
	} else {
		pcapBytes, err = io.Copy(outputPcapWriter, inputPcapWriter)
	}

	if err != nil {
		inputPcapWriter.Close()
		x.logger.LogFsEvent(
			zapcore.ErrorLevel,
			sf.Format("failed to COPY file: {0}", *srcPcapFile),
			PCAP_EXPORT,
			*srcPcapFile,
			*tgtPcapFile,
			0,
			err)
		return pcapBytes, errors.Wrapf(err, "failed to COPY file: %s", *srcPcapFile)
	}

	// closing `outputPcapWriter` is responsibility of the caller of this method
	inputPcapWriter.Close()

	if err != nil {
		x.logger.LogFsEvent(
			zapcore.ErrorLevel,
			sf.Format("failed to EXPORT file: {0}", *srcPcapFile),
			PCAP_EXPORT,
			*srcPcapFile,
			*tgtPcapFile,
			pcapBytes,
			err)
		return pcapBytes, errors.Wrap(err,
			sf.Format("failed to COPY file: {0}", *srcPcapFile))
	}

	if err = callback(
		outputPcapWriter,
		srcPcapFile,
		tgtPcapFile,
		&pcapBytes,
	); err != nil {
		x.logger.LogFsEvent(
			zapcore.ErrorLevel,
			sf.Format(
				"failed to EXPORT file: {0}",
				*srcPcapFile,
			),
			PCAP_EXPORT,
			*srcPcapFile,
			*tgtPcapFile,
			pcapBytes,
			err)
		return pcapBytes, errors.Wrap(err,
			sf.Format("failed to EXPORT file: {0}", *srcPcapFile))
	}

	x.logger.LogFsEvent(
		zapcore.InfoLevel,
		sf.Format("EXPORTED: {0}", *srcPcapFile),
		PCAP_EXPORT,
		*srcPcapFile,
		*tgtPcapFile,
		pcapBytes,
		nil)

	if delete {
		// remove the source PCAP file if copying is sucessful
		err = os.Remove(*srcPcapFile)
		if err != nil {
			x.logger.LogFsEvent(
				zapcore.ErrorLevel,
				sf.Format(
					"failed to DELETE file: {0}",
					*srcPcapFile,
				),
				PCAP_EXPORT,
				*srcPcapFile,
				*tgtPcapFile,
				pcapBytes,
				err)
		} else {
			x.logger.LogFsEvent(
				zapcore.InfoLevel,
				sf.Format(
					"DELETED: {0}",
					*srcPcapFile,
				),
				PCAP_EXPORT,
				*srcPcapFile,
				*tgtPcapFile,
				pcapBytes,
				nil)
		}
	}

	return pcapBytes, nil
}
