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
	"go.uber.org/zap/zapcore"
)

type (
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

	err := errors.Wrapf(nilExporterError, "not exported: %s", *srcPcapFile)

	x.logger.LogEvent(
		zapcore.WarnLevel,
		fmt.Sprintf("lost PCAP file: %s", *srcPcapFile),
		PCAP_EXPORT,
		map[string]any{
			"src": *srcPcapFile,
			"tgt": x.toTargetPcapFile(srcPcapFile, compress),
		},
		err)

	return &tgtPcap, &pcapBytes, err
}

func (x *exporter) toTargetPcapFile(
	srcPcapFile *string,
	compress bool,
) string {
	tgtPcapFile := filepath.Join(x.directory, *srcPcapFile)
	// If compressing PCAP files is enabled, add `gz` siffux to the destination PCAP file path
	if compress {
		return fmt.Sprintf("%s.gz", tgtPcapFile)
	}
	return tgtPcapFile
}

func (x *exporter) export(
	srcPcapFile *string,
	tgtPcapFile *string,
	outputPcapWriter io.Writer,
	compress bool,
	delete bool,
) (int64, error) {
	pcapBytes := int64(0)

	// Open source PCAP file: the one thas is being moved to the destination directory
	inputPcapWriter, err := os.OpenFile(*srcPcapFile, os.O_RDONLY|os.O_EXCL, 0)
	if err != nil {
		x.logger.LogFsEvent(
			zapcore.ErrorLevel,
			fmt.Sprintf("failed to OPEN file %s", *srcPcapFile),
			PCAP_EXPORT,
			*srcPcapFile,
			*tgtPcapFile,
			0,
			err)
		return pcapBytes, errors.Wrapf(err, "failed to open source pcap: %s", *srcPcapFile)
	}

	// Copy source PCAP into destination PCAP, compressing destination PCAP is optional
	if compress {
		gzipPcap := gzip.NewWriter(outputPcapWriter)
		defer gzipPcap.Close() // this is still required; `Close()` on parent `Writer` does not trigger `Close()` at `gzip`
		defer gzipPcap.Flush()
		pcapBytes, err = io.Copy(gzipPcap, inputPcapWriter)
	} else {
		pcapBytes, err = io.Copy(outputPcapWriter, inputPcapWriter)
	}

	defer inputPcapWriter.Close()

	if err != nil {
		x.logger.LogFsEvent(
			zapcore.ErrorLevel,
			fmt.Sprintf("failed to EXPORT file: %s", *srcPcapFile),
			PCAP_EXPORT,
			*srcPcapFile,
			*tgtPcapFile,
			0,
			err)
		return pcapBytes, errors.Wrapf(err, "failed to EXPORT file: %s", *srcPcapFile)
	}

	x.logger.LogFsEvent(
		zapcore.InfoLevel,
		fmt.Sprintf("EXPORTED: %s", *srcPcapFile),
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
				fmt.Sprintf("failed to DELETE file: %s", *srcPcapFile),
				PCAP_EXPORT,
				*srcPcapFile,
				*tgtPcapFile,
				pcapBytes,
				err)
		} else {
			x.logger.LogFsEvent(
				zapcore.InfoLevel,
				fmt.Sprintf("DELETED: %s", *srcPcapFile),
				PCAP_EXPORT,
				*srcPcapFile,
				*tgtPcapFile,
				pcapBytes,
				nil)
		}
	}

	return pcapBytes, nil
}
