local stringToBool(str) =
  if str == "true" then true
  else if str == "false" then false
  else error "invalid boolean: " + std.manifestJson(str);

local pcap_debug = stringToBool(std.extVar("env__PCAP_DEBUG"));
local pcap_verbosity = '' + std.extVar("env__PCAP_VERBOSITY");

{
  pcap: {
    debug: pcap_debug,
    verbosity: pcap_verbosity,
  }
}
