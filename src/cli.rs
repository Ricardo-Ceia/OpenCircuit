pub const USAGE: &str = "Usage:
  opencircuit normalize <ipv4-cidr>
  opencircuit info <ipv4-cidr>
  opencircuit contains <ipv4-cidr> <ipv4-address>
  opencircuit usable <ipv4-cidr> <ipv4-address>
  opencircuit next <ipv4-address>
  opencircuit prev <ipv4-address>
  opencircuit classify <ipv4-address>
  opencircuit classify-cidr <ipv4-cidr>
  opencircuit summary <ipv4-cidr>
  opencircuit masks <ipv4-cidr>
  opencircuit range <ipv4-cidr>
  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>
  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>
  opencircuit scan <ipv4-cidr>

Scan Options:
  --all                                 Show offline records too
  --no-dns                              Disable DNS/mDNS/NetBIOS hostname probes
  --fast | --balanced | --deep          Scan profile (default: --deep)
  --ports <csv>                         Override TCP ports list (example: 22,80,443)
  --timeout-ms <n>                      Per-probe timeout in milliseconds
  --concurrency <n>                     Concurrent host probes
  --recent-minutes <n>                  Keep recently seen devices visible
  --state-file <path>                   Local state cache file path
  --dhcp-leases <path>                  Local DHCP lease file (authoritative source)
  --dhcp-leases-ssh <user@host:/path>   Fetch DHCP leases via SSH

Help:
  opencircuit help
  opencircuit --help
  opencircuit -h";

pub fn is_help_arg(arg: &str) -> bool {
    arg == "help" || arg == "--help" || arg == "-h"
}
