local stringToBoolean(str) =
  if str == "true" then true
  else if str == "false" then false
  else error "invalid boolean: " + std.manifestJson(str);

local pcap_exec_env = '' + std.extVar("ext__PCAP_EXEC_ENV");
local pcap_instance_id = '' + std.extVar("ext__PCAP_INSTANCE_ID");
local pcap_debug = stringToBoolean(std.extVar("ext__PCAP_DEBUG"));
local pcap_verbosity = '' + std.extVar("ext__PCAP_VERBOSITY");
local pcap_l3_protos = '' + std.extVar("ext__PCAP_L3_PROTOS");
local pcap_l4_protos = '' + std.extVar("ext__PCAP_L4_PROTOS");

{
  pcap: {
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
        l3: std.split(pcap_l3_protos, ","),
        l4: std.split(pcap_l4_protos, ","),
      },
    },
  }
}
