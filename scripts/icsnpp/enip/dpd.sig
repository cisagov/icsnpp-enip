# These signatures have not been thoroughly tested.

signature dpd_enip_tcp_client {
  ip-proto == tcp
  payload /^\x65\x00.{2}.{4}\x00{4}/
}

signature dpd_enip_tcp_server {
  ip-proto == tcp
  payload /^\x65\x00/
  requires-signature dpd_enip_tcp_client
  enable "ENIP_TCP"
}

