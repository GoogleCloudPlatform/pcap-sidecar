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

package log

import (
	"maps"
	"time"

	constants "github.com/GoogleCloudPlatform/pcap-sidecar/pcap-fsnotify/internal/constants"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type (
	pcapEvent = constants.PcapEvent

	fsnEvent struct {
		Source string `json:"source,omitempty"`
		Target string `json:"target,omitempty"`
		Bytes  int64  `json:"bytes,omitempty"`
	}

	Logger struct {
		*zap.Logger
		sidecar string
		module  string
		tags    []string
	}
)

var (
	l, _ = zap.Config{
		Encoding:    "json",
		Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
		OutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:  "message",
			LevelKey:    "severity",
			EncodeLevel: zapcore.CapitalLevelEncoder,
			TimeKey:     "time",
			EncodeTime:  zapcore.ISO8601TimeEncoder,
		},
	}.Build()

	sugar = l.Sugar()
)

func NewLogger(
	projectID string,
	service string,
	gcpRegion string,
	version string,
	instanceID string,
	sidecar string,
	module string,
) *Logger {
	return &Logger{
		Logger:  l,
		sidecar: sidecar,
		module:  module,
		tags: []string{
			projectID,
			service,
			gcpRegion,
			version,
			instanceID,
		},
	}
}

func (l *Logger) LogEvent(
	level zapcore.Level,
	message string,
	event pcapEvent,
	data map[string]any,
	err error,
) {
	now := time.Now()
	_data := map[string]any{
		"event": event,
	}
	if err != nil {
		_data["error"] = err.Error()
	}
	if len(data) > 0 {
		maps.Copy(_data, data)
	}
	sugar.Logw(level, message,
		"sidecar", l.sidecar,
		"module", l.module,
		"tags", l.tags,
		"data", _data,
		"timestamp", map[string]interface{}{
			"seconds": now.Unix(),
			"nanos":   now.Nanosecond(),
		})
}

func (l *Logger) LogFsEvent(
	level zapcore.Level,
	message string,
	event pcapEvent,
	src, tgt string,
	by int64,
	err error,
) {
	e := fsnEvent{
		Source: src,
		Target: tgt,
	}
	if by > 0 {
		e.Bytes = by
	}
	data := map[string]any{
		"fs": e,
	}
	l.LogEvent(level, message, event, data, err)
}
