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

	CtxVarType string

	ctxVar struct {
		typ CtxVarType
		req bool
	}
)

const (
	BuildKey          = CtxKey("build")
	VersionKey        = CtxKey("version")
	SupervisorPortKey = CtxKey("supervisor/port")
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
	GzipKey           = CtxKey("features/gzip")
	TcpdumpKey        = CtxKey("features/tcpdump")
	JsondumpKey       = CtxKey("features/json/dump")
	JsonlogKey        = CtxKey("features/json/log")
	FsNotifyKey       = CtxKey("features/fs-notify")
	CronKey           = CtxKey("features/cron/enabled")
	CronExpressionKey = CtxKey("features/cron/expression")
	OrderedKey        = CtxKey("features/ordered")
	ConntrackKey      = CtxKey("features/conntrack")
	HealthcheckKey    = CtxKey("features/healthcheck/port")
	DebugKey          = CtxKey("features/debug")
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

const (
	CtxKeyTemplate = CtxKeyPrefix + "/cfg/{0}"
	KtxKeyTemplate = CtxKeyPrefix + "/{0}"
)

const (
	TYPE_LIST = "[]{0}"
	TYPE_MAP  = "map[{0}]{1}"

	TYPE_STRING  = CtxVarType("string")
	TYPE_BOOLEAN = CtxVarType("boolean")
	TYPE_INTEGER = CtxVarType("int")
	TYPE_UINT8   = CtxVarType("uint8")
	TYPE_UINT16  = CtxVarType("uint16")
	TYPE_UINT32  = CtxVarType("uint32")
	TYPE_UINT64  = CtxVarType("uint64")
)

var (
	TYPE_LIST_STRING  = listCtxVarTypeOf(TYPE_STRING)
	TYPE_LIST_INTEGER = listCtxVarTypeOf(TYPE_INTEGER)
	TYPE_LIST_UINT16  = listCtxVarTypeOf(TYPE_UINT16)
)

func listCtxVarTypeOf(
	valueType CtxVarType,
) CtxVarType {
	return CtxVarType(sf.Format(TYPE_LIST, valueType))
}

func mapCtxVarTypeOf(
	keyType CtxVarType,
	valueType CtxVarType,
) CtxVarType {
	return CtxVarType(sf.Format(TYPE_MAP, keyType, valueType))
}

func (k *CtxKey) toString(
	template string,
) string {
	return sf.Format(template, string(*k))
}

func (k *CtxKey) ToCtxKey() string {
	return k.toString(CtxKeyTemplate)
}

func (k *CtxKey) ToKtxKey() string {
	return k.toString(KtxKeyTemplate)
}
