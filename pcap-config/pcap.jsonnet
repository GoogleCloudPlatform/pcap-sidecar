local extVarNamePrefix = "ext__PCAP";

local minPort = std.parseHex("0001");
local maxPort = std.parseHex("FFFF");

local allOrAny = std.set(["any", "ANY", "all", "ALL"]);
local l3Protos = std.set(["arp", "ip", "ip6"]);
local l4Protos = std.set(["icmp", "icmp6", "tcp", "udp"]);
local tcpFlags = std.set(["syn", "ack", "psh", "fin", "rst"]);

local identity(value) = value;

local always(value) = true;

local never(value) = false;

local stringToBoolean(str) =
  /*
    use `std.equalsIgnoreCase` when `v0.21.0` is released.
    see: https://jsonnet.org/ref/stdlib.html#std-equalsIgnoreCase
  */
  if std.isBoolean(str) then str
  else if str == "true" || str == "TRUE" then true
  else if str == "false" || str == "FALSE" then false
  else false;

local stringToUint(value) =
  if std.isNumber(value) then
    local v = std.parseInt(value);
    if v < 0 then 0
    else v
  else 0;

local stringToPort(value) =
  local port = stringToUint(value);
  if port < minPort || port > maxPort then 0
  else port;

local contains(list=[], value) =
  if std.length(list) == 0 then false
  /* 
    use `std.contains` when `v0.21.0` is released.
    see: https://jsonnet.org/ref/stdlib.html#std-contains
  */
  else std.length(std.setInter(list, [value])) > 0;

local isAllOrAny(value) = contains(allOrAny, value);
local notIsAllOrAny(value) = !isAllOrAny(value);

local isValidPort(port) = port >= minPort && port <= maxPort;

local isVaidL3Proto(proto) = contains(l3Protos, proto);

local isVaidL4Proto(proto) = contains(l4Protos, proto);

local isValidTCPflag(flag) = contains(tcpFlags, flag);

local extVarName(name) =
  std.join("_", [extVarNamePrefix, std.asciiUpper(name)]);

local extVar(name) =
  /* 
    wrap return value with `std.trim` when `v0.21.0` is released.
    see: https://jsonnet.org/ref/stdlib.html#std-trim
  */
  std.extVar(extVarName(name));

local extVarOrDefault(name, defaultValue)=
  local value = extVar(name);
  if std.isEmpty(value) then defaultValue
  else value;

local extListVar(name) =
  std.split(extVar(name), ",");

local extSetVar(name, mapper=identity, filter=always) =
  local values = std.set(extListVar(name));
  std.filter(filter, std.map(mapper, values));

local extUintSetVar(name, filter=always) =
  extSetVar(name, stringToUint, filter);

local extBooleanVar(name) =
  stringToBoolean(extVar(name));

local extIntegerVar(name) =
  std.parseInt(extVarName(name));

local pcap_build = extVar("build");
local pcap_version = extVar("version");
local pcap_debug = extBooleanVar("debug");
local pcap_exec_env = extVar("exec_env");
local pcap_instance_id = extVar("instance_id");
local pcap_verbosity = extVarOrDefault("verbosity", "DEBUG");
local pcap_filter = extVarOrDefault("filter", "DISABLED");
local pcap_hosts = extSetVar("hosts", std.asciiLower, notIsAllOrAny);
local pcap_ports = extUintSetVar("ports", isValidPort);
local pcap_l3_protos = extSetVar("l3_protos", std.asciiLower, isVaidL3Proto);
local pcap_l4_protos = extSetVar("l4_protos", std.asciiLower, isVaidL4Proto);
local pcap_tcp_flags = extSetVar("tcp_flags", std.asciiLower, isValidTCPflag);

{
  pcap: {
    version: 'v' + pcap_version,
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
      bpf: pcap_filter,
      hosts: pcap_hosts,
      ports: pcap_ports,
      protos: {
        l3: pcap_l3_protos,
        l4: pcap_l4_protos,
      },
      tcp: {
        flags: pcap_tcp_flags,
      },
    },
    modules: {
      cli:{},
      fsnotify:{},
      tcpdumpw:{},
    },
  },

}
