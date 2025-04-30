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

package config

import (
	sf "github.com/wissance/stringFormatter"
)

type (
	CtxKey string

	ctxVarType string

	ctxVar struct {
		path     string
		typ      ctxVarType
		required bool
	}
)

const (
	GcpRegionKey      = CtxKey("gcp/region")
	ProjectIDKey      = CtxKey("gcp/project/id")
	ProjectNumKey     = CtxKey("gcp/project/number")
	InstanceIDKey     = CtxKey("env/instance/id")
	ExecEnvKey        = CtxKey("env/id")
	GcsMountPointKey  = CtxKey("gcp/storage/mount-point")
	GcsTempDirKey     = CtxKey("gcp/storage/temp-dir")
	GcsDirKey         = CtxKey("gcp/storage/directory")
	GcsBucketKey      = CtxKey("gcp/storage/bucket")
	GcsExportKey      = CtxKey("gcp/storage/export")
	GzipKey           = CtxKey("feature/gzip")
	TcpdumpKey        = CtxKey("feature/tcpdump")
	JsondumpKey       = CtxKey("feature/json/dump")
	JsonlogKey        = CtxKey("feature/json/log")
	FsNotifyKey       = CtxKey("feature/fs-notify")
	CronKey           = CtxKey("feature/cron/enabled")
	CronExpressionKey = CtxKey("feature/cron/expression")
	OrderedKey        = CtxKey("feature/ordered")
	ConntrackKey      = CtxKey("feature/conntrack")
	HealthcheckKey    = CtxKey("feature/healthcheck/port")
	DebugKey          = CtxKey("feature/debug")
	SupervisorPortKey = CtxKey("supervisor/port")
	FilterKey         = CtxKey("filter/bpf")
	L3ProtosFilterKey = CtxKey("filter/protos/l3")
	L4ProtosFilterKey = CtxKey("filter/protos/l4")
	IPv4FilterKey     = CtxKey("filter/ip/v4")
	IPv6FilterKey     = CtxKey("filter/ip/v6")
	HostsFilterKey    = CtxKey("filter/hosts")
	PortsFilterKey    = CtxKey("filter/ports")
	TcpFlagsFilterKey = CtxKey("filter/tcp/flags")
	DirectoryKey      = CtxKey("directory")
	IfaceKey          = CtxKey("iface")
	SnaplenKey        = CtxKey("snaplen")
	TimezoneKey       = CtxKey("timezone")
	TimeoutKey        = CtxKey("timeout")
	RotateSecsKey     = CtxKey("rotate-secs")
	VerbosityKey      = CtxKey("verbosity")
	ExtensionKey      = CtxKey("extension")
)

const ctxKeyTemplate = "pcap/cfg/{0}"

const (
	TYPE_LIST = "[]{0}"
	TYPE_MAP  = "map[{0}]{1}"

	TYPE_STRING  = ctxVarType("string")
	TYPE_BOOLEAN = ctxVarType("boolean")
	TYPE_INTEGER = ctxVarType("int")
	TYPE_UINT8   = ctxVarType("uint8")
	TYPE_UINT16  = ctxVarType("uint16")
	TYPE_UINT32  = ctxVarType("uint32")
	TYPE_UINT64  = ctxVarType("uint64")
)

var (
	TYPE_LIST_STRING  = listCtxVarTypeOf(TYPE_STRING)
	TYPE_LIST_INTEGER = listCtxVarTypeOf(TYPE_INTEGER)
)

func listCtxVarTypeOf(
	valueType ctxVarType,
) ctxVarType {
	return ctxVarType(sf.Format(TYPE_LIST, valueType))
}

func mapCtxVarTypeOf(
	keyType ctxVarType,
	valueType ctxVarType,
) ctxVarType {
	return ctxVarType(sf.Format(TYPE_MAP, keyType, valueType))
}

func (k *CtxKey) ToCtxKey() string {
	return sf.Format(ctxKeyTemplate, string(*k))
}
