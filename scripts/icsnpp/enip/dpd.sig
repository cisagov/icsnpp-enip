# These signatures have not been thoroughly tested.
# New signatures based on information at
# https://github.com/nimbuscontrols/EIPScanner/
# "enable" targets are defined in <repo_root>/src/Plugin.cc
# Note: ENIP uses little-endian byte order rather than network byte order
# Header:
#   Command (uint16)
#     Valid Values (network byte order):
#       0x0000, 0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006F,
#       0x0070, 0x0072, 0x0073
#   Length (uint16)
#   Session Handle (uint32)
#   Status Code (uint32)
#     Valid Values (network byte order):
#       0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x00000064, 0x00000069
#   Context (uint8)
#   Options (uint32)

signature dpd_enip_tcp {
  ip-proto == tcp
  payload /^[\x00\x04\x63\x64\x65\x66\x6f\x70\x72\x73]\x00[\x00-\xff]{6}[\x00\x01\x02\x03\x64\x69]\x00{3}[\x00-\xff][\x00-\xff]{4}/
  enable "ENIP_TCP"
}

signature dpd_enip_udp {
  ip-proto == udp
  payload /^[\x00\x04\x63\x64\x65\x66\x6f\x70\x72\x73]\x00[\x00-\xff]{6}[\x00\x01\x02\x03\x64\x69]\x00{3}[\x00-\xff][\x00-\xff]{4}/
  enable "ENIP_UDP"
}

