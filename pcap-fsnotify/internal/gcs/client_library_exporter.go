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
	"maps"
	"net"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/log"
	"github.com/avast/retry-go/v4"
	"github.com/googleapis/gax-go/v2"
	"github.com/googleapis/gax-go/v2/callctx"
	"github.com/pkg/errors"
	sf "github.com/wissance/stringFormatter"
	"go.uber.org/zap/zapcore"
	"google.golang.org/api/googleapi"
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
		dialer     *net.Dialer
		keepalive  keepalive.ClientParameters
	}

	contextKey string
)

const (
	sourcePcapFile = contextKey("source_pcap_file")
	targetPcapFile = contextKey("target_pcap_file")

	// see: https://pkg.go.dev/google.golang.org/grpc#WithContextDialer
	gcsEndpoint = "passthrough:storage.googleapis.com"
	gcsPort     = uint16(443)
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
		nil)

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

func (x *libraryExporter) gcsRemoteAddr(
	gcsEndpoint *string,
) string {
	return sf.Format("{0}:{1}", *gcsEndpoint, gcsPort)
}

func (x *libraryExporter) connect(
	ctx context.Context,
	address *string,
) (net.Conn, error) {
	addr := *address

	return retry.DoWithData(
		func() (net.Conn, error) {
			// [ToDo]: set network to `tcp4` only when VPC for ALL egress networking is used; otherwise, use `tcp`:
			//   - when VPC is used for ALL egress networking, IPv4 is the only protocol supported for external hosts
			//   - network is currently set to `tcp4` to support ALL egress networking configurations.
			return x.dialer.DialContext(ctx, "tcp4", addr)
		},
		retry.Context(ctx),
		retry.Attempts(30),
		retry.Delay(1*time.Second),
		retry.DelayType(retry.FixedDelay),
		retry.OnRetry(func(
			attempt uint,
			err error,
		) {
			_attempt := (attempt + 1)
			x.logger.LogEvent(
				zapcore.WarnLevel,
				sf.Format("failed to connect at attempt {0}: {1}", _attempt, addr),
				PCAP_EXPORT,
				map[string]any{
					"address": *address,
					"attempt": addr,
				},
				err)
		}),
	)
}

func (x *libraryExporter) dialContext(
	ctx context.Context,
	addr string,
) (net.Conn, error) {
	address := x.gcsRemoteAddr(&addr)

	data := map[string]any{
		"endpoint": addr,
		"address":  address,
		"bucket":   x.bucket,
	}

	if conn, err := x.connect(ctx, &address); err != nil {
		x.logger.LogEvent(
			zapcore.ErrorLevel,
			sf.Format("failed to connect to GCS: {0}", address),
			PCAP_EXPORT,
			data,
			err)
		return nil, err
	} else {
		remoteAddrStr := conn.RemoteAddr().String()

		info := map[string]any{
			"local":  conn.LocalAddr().String(),
			"remote": remoteAddrStr,
		}
		maps.Copy(info, data)

		x.logger.LogEvent(
			zapcore.InfoLevel,
			sf.Format("connected to GCS via: {0} => {1}", address, remoteAddrStr),
			PCAP_EXPORT,
			info,
			nil)

		return conn, nil
	}
}

func (x *libraryExporter) streamInterceptor(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	target := cc.CanonicalTarget()

	x.logger.LogEvent(
		zapcore.InfoLevel,
		sf.Format("GCS operation: {0}{1}", target, method),
		PCAP_EXPORT,
		map[string]any{
			"target": target,
			"stream": desc.StreamName,
			"state":  cc.GetState().String(),
			"bucket": x.bucket,
		},
		nil)

	return streamer(ctx, desc, cc, method, opts...)
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
			grpc.WithContextDialer(x.dialContext),
		),
		option.WithGRPCDialOption(
			grpc.WithKeepaliveParams(x.keepalive),
		),
		option.WithGRPCDialOption(
			grpc.WithStreamInterceptor(x.streamInterceptor),
		),
		option.WithGRPCConnectionPool(2),
		option.WithQuotaProject(x.projectID),
		option.WithEndpoint(gcsEndpoint),
		option.WithRequestReason("pcap-sidecar"),
		option.WithUserAgent("pcap-sidecar"),
		option.WithTelemetryDisabled(),
		storage.WithDisabledClientMetrics(),
	)
	if err != nil {
		return x, errors.Wrap(err, "failed to create gRPC GCS client")
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
				Max:     time.Duration(x.maxRetries) * x.retriesDelay * time.Second,
			}),
			storage.WithMaxAttempts(int(x.maxRetries)),
			storage.WithErrorFunc(func(err error) bool {
				// see: https://pkg.go.dev/cloud.google.com/go/storage#WithErrorFunc
				// GCS client always calls this function, even when `err` is `nil`
				if err == nil {
					// if `err` is `nil`, then prevent retyring by returning `false`:
					//   - which we assume is the logical thing to do if there is no error...
					return false
				}

				attempts += 1

				x.logger.LogEvent(
					zapcore.WarnLevel,
					sf.Format("failed to EXPORT file at attempt {0}: {1}", attempts, *srcPcapFile),
					PCAP_EXPORT,
					map[string]any{
						"source":  *srcPcapFile,
						"target":  tgtPcapFile,
						"attempt": attempts,
					},
					err,
				)

				return true
			}),
			storage.WithPolicy(storage.RetryAlways),
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

func (x *libraryExporter) newWriter(
	ctx context.Context,
	srcPcapFile *string,
	tgtPcapFile *string,
	object *storage.ObjectHandle,
) *storage.Writer {
	// see: https://github.com/googleapis/google-cloud-go/blob/storage/v1.51.0/storage/storage.go#L1233
	writer := object.NewWriter(x.setHeaders(ctx))

	writer.Bucket = x.bucket

	writer.Name = *tgtPcapFile

	writer.Metadata = map[string]string{
		"creator":  "pcap-sidecar",
		"project":  x.projectID,
		"instance": x.instanceID,
	}

	writer.ChunkSize = googleapi.DefaultUploadChunkSize

	return writer
}

func (x *libraryExporter) onExported(
	cw ClosableWriter,
	src *string,
	tgt *string,
	size *int64,
) error {
	x.logger.LogFsEvent(
		zapcore.InfoLevel,
		sf.Format("sent {0} bytes into gs://{1}/{2}", *size, x.bucket, *tgt),
		PCAP_EXPORT,
		*src,
		*tgt,
		*size,
		nil)

	return cw.Close()
}

func (x *libraryExporter) Export(
	ctx context.Context,
	srcPcapFile *string,
	compress bool,
	delete bool,
) (*string, *int64, error) {
	ctx = context.WithValue(ctx, sourcePcapFile, *srcPcapFile)

	tgtPcapFile := x.newObjectName(srcPcapFile, compress)
	ctx = context.WithValue(ctx, targetPcapFile, tgtPcapFile)

	object := x.newObject(srcPcapFile, &tgtPcapFile)

	writer := x.newWriter(ctx, srcPcapFile, &tgtPcapFile, object)

	pcapBytes, err := x.export(srcPcapFile, &tgtPcapFile, writer, compress, delete, x.onExported)

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
		dialer: &net.Dialer{
			Timeout: 5 * time.Minute,
			KeepAliveConfig: net.KeepAliveConfig{
				Enable:   true,
				Idle:     30 * time.Second,
				Interval: 15 * time.Second,
				Count:    2,
			},
		},
		keepalive: keepalive.ClientParameters{
			Time:                60 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		},
	}

	if exporter, err := exporter.
		initialize(ctx); err == nil {
		return exporter
	} else {
		logger.LogEvent(
			zapcore.ErrorLevel,
			"failed to create PCAP files client library exporter",
			PCAP_EXPORT,
			map[string]any{
				"project": projectID,
				"bucket":  bucket,
			},
			err)
	}

	// return the NIL exporter by default
	return NewNilExporter(logger)
}
