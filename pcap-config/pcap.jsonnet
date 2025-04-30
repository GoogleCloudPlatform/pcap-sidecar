local extVarNamePrefix = "ext__PCAP";

local stringToBoolean(str) =
  if str == "true" then true
  else if str == "false" then false
  else error "invalid boolean: " + std.manifestJson(str);

local extVarName(name) =
  std.join("_", [extVarNamePrefix, std.asciiUpper(name)]);

/* 
  wrap return value with `std.trim` when `v0.21.0` is released.
  see: https://jsonnet.org/ref/stdlib.html#std-trim
*/
local extVar(name) =
  std.extVar(extVarName(name));

local extListVar(name) =
  std.split(extVar(name), ",");

local extSetVar(name) =
  std.set(extListVar(name));

local extBooleanVar(name) =
  stringToBoolean(extVar(name));

local extIntegerVar(name) =
  std.parseInt(extVarName(name));

local pcap_build = extVar("build");
local pcap_version = extVar("version");
local pcap_debug = extBooleanVar("debug");
local pcap_exec_env = extVar("exec_env");
local pcap_instance_id = extVar("instance_id");
local pcap_verbosity = extVar("verbosity");
local pcap_l3_protos = extSetVar("l3_protos");
local pcap_l4_protos = extSetVar("l4_protos");

{
  pcap: {
    version: pcap_version,
    build: pcap_build,
    env: {
      id: pcap_exec_env,
      instance: {
        id: pcap_instance_id,
      },
    },
    debug: pcap_debug,
    verbosity: pcap_verbosity,
    filter: {
      protos: {
        l3: pcap_l3_protos,
        l4: pcap_l4_protos,
      },
    },
  }
}
