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
	"os"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/log"
	"github.com/avast/retry-go/v4"
	"github.com/pkg/errors"
	sf "github.com/wissance/stringFormatter"
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
			sf.Format("failed to CREATE file: {0}", tgtPcapFile),
			PCAP_EXPORT,
			*srcPcapFile,
			tgtPcapFile,
			0,
			err)
		return &tgtPcapFile, &pcapBytes, errors.Wrap(err,
			sf.Format("failed to create destination pcap: {0}", tgtPcapFile))
	}
	// x.logger.logFsEvent(zapcore.InfoLevel, fmt.Sprintf("CREATED: %s", tgtPcap), PCAP_EXPORT, *srcPcap, tgtPcap, 0)

	pcapBytes, err = retry.DoWithData(func() (int64, error) {
		// Copy source PCAP into destination PCAP directory, compressing destination PCAP is optional
		return x.export(
			srcPcapFile, &tgtPcapFile,
			pcapFileWriter,
			compress, delete,
			func(
				src *string,
				tgt *string,
				size *int64,
			) error {
				x.logger.LogFsEvent(
					zapcore.InfoLevel,
					sf.Format("copied {0} bytes into file: {1}", *size, *tgt),
					PCAP_EXPORT,
					*src,
					*tgt,
					*size,
					nil)

				return pcapFileWriter.Close()
			})
	},
		retry.Context(ctx),
		retry.Attempts(x.maxRetries),
		retry.Delay(x.retriesDelay),
		retry.DelayType(retry.FixedDelay),
		retry.OnRetry(func(attempt uint, err error) {
			x.logger.LogEvent(
				zapcore.WarnLevel,
				sf.Format("failed to COPY file at attempt {0}: {1}", attempt+1, *srcPcapFile),
				PCAP_EXPORT,
				map[string]any{
					"source":  *srcPcapFile,
					"target":  tgtPcapFile,
					"attempt": attempt + 1,
				},
				err)
		}))

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
