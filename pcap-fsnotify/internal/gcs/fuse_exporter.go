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
	"context"
	"fmt"
	"os"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/log"
	"github.com/avast/retry-go/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
)

type (
	fuseExporter struct {
		*exporter
	}
)

func (x *fuseExporter) newFile(
	srcPcapFile *string,
	tgtPcapFile *string,
) (*os.File, error) {
	return os.OpenFile(
		*tgtPcapFile,
		os.O_RDWR|os.O_CREATE|os.O_EXCL,
		0o666,
	)
}

func (x *fuseExporter) Export(
	ctx context.Context,
	srcPcapFile *string,
	compress bool,
	delete bool,
) (*string, *int64, error) {
	tgtPcapFile := x.toTargetPcapFile(srcPcapFile, compress)

	var pcapBytes int64 = 0

	// Create destination PCAP file ( when using Fuse this is the same as exporting to the GCS Bucket )
	pcapFileWriter, err := x.newFile(srcPcapFile, &tgtPcapFile)
	if err != nil {
		x.logger.LogFsEvent(
			zapcore.ErrorLevel,
			fmt.Sprintf("failed to CREATE file: %s", tgtPcapFile),
			PCAP_EXPORT,
			*srcPcapFile,
			tgtPcapFile,
			0,
			err)
		return &tgtPcapFile, &pcapBytes, errors.Wrapf(err, "failed to create destination pcap: %s", tgtPcapFile)
	}
	// x.logger.logFsEvent(zapcore.InfoLevel, fmt.Sprintf("CREATED: %s", tgtPcap), PCAP_EXPORT, *srcPcap, tgtPcap, 0)

	pcapBytes, err = retry.DoWithData(func() (int64, error) {
		// Copy source PCAP into destination PCAP directory, compressing destination PCAP is optional
		return x.export(srcPcapFile, &tgtPcapFile, pcapFileWriter, compress, delete)
	},
		retry.Context(ctx),
		retry.Attempts(x.maxRetries),
		retry.Delay(x.retriesDelay),
		retry.DelayType(retry.FixedDelay),
		retry.OnRetry(func(n uint, err error) {
			x.logger.LogFsEvent(
				zapcore.WarnLevel,
				fmt.Sprintf("failed to COPY file at attempt %d: %v", n+1, *srcPcapFile),
				PCAP_EXPORT,
				*srcPcapFile,
				tgtPcapFile,
				0,
				err)
		}))

	pcapFileWriter.Close()

	return &tgtPcapFile, &pcapBytes, nil
}

func NewFuseExporter(
	logger *log.Logger,
	directory string,
	maxRetries uint,
	retriesDelay uint,
) Exporter {
	x := newExporter(logger, directory, maxRetries, retriesDelay)
	return &fuseExporter{
		exporter: x,
	}
}
