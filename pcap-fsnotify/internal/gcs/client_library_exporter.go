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
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/log"
	"github.com/googleapis/gax-go/v2"
	"github.com/googleapis/gax-go/v2/callctx"
	"github.com/pkg/errors"
	sf "github.com/wissance/stringFormatter"
	"go.uber.org/zap/zapcore"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type (
	libraryExporter struct {
		*exporter
		projectID  string
		service    string
		instanceID string
		bucket     string
		client     *storage.Client
		handle     *storage.BucketHandle
	}
)

func (x *libraryExporter) onIntialized(
	client *storage.Client,
	handle *storage.BucketHandle,
	attrs *storage.BucketAttrs,
) *libraryExporter {
	x.client = client
	x.handle = handle.UserProject(x.projectID)

	bucketName := string(attrs.Name)
	x.bucket = bucketName

	data := map[string]any{
		"bucket": bucketName,
	}
	for label, value := range attrs.Labels {
		data[label] = value
	}

	x.logger.LogEvent(
		zapcore.InfoLevel,
		sf.Format("initialized GCS client library exporter with bucket: {0}", bucketName),
		PCAP_EXPORT,
		data,
		nil,
	)

	return x
}

func (x *libraryExporter) setBucketHandle(
	ctx context.Context,
	client *storage.Client,
) (*libraryExporter, error) {
	bucket := string(x.bucket)

	bucketHandle := client.Bucket(bucket)
	if bucketHandle == nil {
		return x, fmt.Errorf("GCS bucket is unavailable: %s", bucket)
	}

	if attrs, err := bucketHandle.Attrs(ctx); err == nil {
		return x.onIntialized(client, bucketHandle, attrs), nil
	} else {
		x.logger.LogEvent(
			zapcore.ErrorLevel,
			sf.Format("failed to initialize GCS client library exporter with bucket: {0}", bucket),
			PCAP_EXPORT,
			map[string]any{
				"bucket": bucket,
			},
			err)
		return x, err
	}
}

func (x *libraryExporter) initialize(
	ctx context.Context,
) (*libraryExporter, error) {
	client, err := storage.NewGRPCClient(ctx,
		option.WithGRPCDialOption(
			grpc.WithNoProxy(),
		),
		option.WithGRPCDialOption(
			grpc.WithLocalDNSResolution(),
		),
		option.WithGRPCDialOption(
			grpc.WithIdleTimeout(5*time.Minute),
		),
		option.WithGRPCDialOption(
			grpc.WithKeepaliveParams(
				keepalive.ClientParameters{
					Time:                30 * time.Second,
					Timeout:             10 * time.Second,
					PermitWithoutStream: true,
				},
			),
		),
		option.WithGRPCConnectionPool(3),
		option.WithQuotaProject(x.projectID),
		option.WithRequestReason("pcap-sidecar"),
		option.WithUserAgent("pcap-sidecar"),
		option.WithTelemetryDisabled(),
	)
	if err != nil {
		return x, errors.Wrap(err, "failed to create GCS client")
	}

	return x.setBucketHandle(ctx, client)
}

func (x *libraryExporter) newObject(
	srcPcapFile *string,
	tgtPcapFile *string,
) *storage.ObjectHandle {
	attempts := uint8(0)

	return x.handle.
		Object(*tgtPcapFile).
		Retryer(
			storage.WithBackoff(gax.Backoff{
				Initial: 2 * time.Second,
				Max:     time.Duration(x.maxRetries) * x.retriesDelay,
			}),
			storage.WithMaxAttempts(int(x.maxRetries)),
			storage.WithErrorFunc(func(err error) bool {
				x.logger.LogFsEvent(
					zapcore.WarnLevel,
					fmt.Sprintf("failed to COPY file at attempt %d: %s", attempts+1, *srcPcapFile),
					PCAP_EXPORT,
					*srcPcapFile,
					*tgtPcapFile,
					0,
					err)
				attempts += 1
				return true
			}),
			storage.WithPolicy(storage.RetryAlways),
		)
}

func (x *libraryExporter) setHeaders(
	ctx context.Context,
) context.Context {
	// [ToDo]: add details about: execution-environment.
	// see: https://cloud.google.com/storage/docs/audit-logging
	return callctx.SetHeaders(ctx,
		"x-goog-custom-audit-project", x.projectID,
		"x-goog-custom-audit-service", x.service,
		"x-goog-custom-audit-instance-id", x.instanceID,
		"x-goog-custom-audit-gcs-bucket", x.bucket,
	)
}

func (x *libraryExporter) newObjectName(
	srcPcapFile *string,
	compress bool,
) string {
	tgtPcapFile := x.toTargetPcapFile(srcPcapFile, compress)
	parts := strings.Split(tgtPcapFile, "/")
	// skip local directory: `${0}/${1:PCAP_DIR}/...`
	return strings.Join(parts[2:], "/")
}

func (x *libraryExporter) Export(
	ctx context.Context,
	srcPcapFile *string,
	compress bool,
	delete bool,
) (*string, *int64, error) {
	tgtPcapFile := x.newObjectName(srcPcapFile, compress)

	object := x.newObject(srcPcapFile, &tgtPcapFile)

	gcsObjectWriter := object.NewWriter(x.setHeaders(ctx))

	pcapBytes, err := x.export(srcPcapFile, &tgtPcapFile, gcsObjectWriter, compress, delete)

	// see:
	//  - https://pkg.go.dev/cloud.google.com/go/storage#Writer.Close
	//  - https://pkg.go.dev/cloud.google.com/go/storage#Writer.Write
	/**
	* Literal client library doc comments:
	*	Since writes happen asynchronously, Write may return a nil error even though the write failed (or will fail).
	*	Always use the error returned from Writer.Close to determine if the upload was successful.
	**/
	err = gcsObjectWriter.Close()
	if err != nil {
		x.logger.LogFsEvent(
			zapcore.ErrorLevel,
			fmt.Sprintf("failed to EXPORT file: %s", *srcPcapFile),
			PCAP_EXPORT,
			*srcPcapFile,
			tgtPcapFile,
			0,
			err)
	}

	return &tgtPcapFile, &pcapBytes, err
}

func NewClientLibraryExporter(
	ctx context.Context,
	logger *log.Logger,
	projectID string,
	service string,
	instanceID string,
	bucket string,
	directory string,
	maxRetries uint,
	retriesDelay uint,
) Exporter {
	x := newExporter(logger, directory, maxRetries, retriesDelay)

	exporter := &libraryExporter{
		exporter:   x,
		projectID:  projectID,
		service:    service,
		instanceID: instanceID,
		bucket:     bucket,
	}

	if exporter, err := exporter.
		initialize(ctx); err == nil {
		return exporter
	} else {
		logger.LogEvent(
			zapcore.ErrorLevel,
			"failed to create PCAP files exporter",
			PCAP_EXPORT,
			map[string]any{
				"bucket": bucket,
			},
			err)
	}

	// return the NIL exporter by default
	return NewNilExporter(logger)
}
