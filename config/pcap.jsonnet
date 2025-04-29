local stringToBoolean(str) =
  if str == "true" then true
  else if str == "false" then false
  else error "invalid boolean: " + std.manifestJson(str);

local pcap_debug = stringToBoolean(std.extVar("ext__PCAP_DEBUG"));
local pcap_verbosity = '' + std.extVar("ext__PCAP_VERBOSITY");

{
  pcap: {
    debug: pcap_debug,
    verbosity: pcap_verbosity,
  }
}
