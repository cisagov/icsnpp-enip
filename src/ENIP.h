// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#pragma once

#if __has_include(<zeek/zeek-version.h>)
#include <zeek/zeek-version.h>
#else
#include <zeek/zeek-config.h>
#endif

#include <zeek/analyzer/protocol/tcp/TCP.h>
#if ZEEK_VERSION_NUMBER >= 40100
#include <zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h>
#else
#include <zeek/analyzer/protocol/udp/UDP.h>
#endif

#include "enip_pac.h"

#include <cstdint>
#include <vector>

namespace zeek::analyzer::enip {
  class ENIP_TCP_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer
  {
      public:
          ENIP_TCP_Analyzer(Connection* conn);
          virtual ~ENIP_TCP_Analyzer();

          virtual void Done();
          virtual void DeliverStream(int len, const u_char* data, bool orig);
          virtual void Undelivered(uint64_t seq, int len, bool orig);

          virtual void EndpointEOF(bool is_orig);

          static analyzer::Analyzer* Instantiate(Connection* conn)
          {
              return new ENIP_TCP_Analyzer(conn);
          }

      protected:
          binpac::ENIP::ENIP_Conn* interp;

          // Per-direction: true while we are looking for the next encapsulation
          // header after a content gap. Replaces the write-only
          // `had_gap`, which nothing read.
          bool resync_orig;
          bool resync_resp;

          // Reassembly buffers for length-prefixed ENIP-over-TCP framing.
          // Zeek reassembles the TCP stream, but a single encapsulation PDU
          // can still span multiple DeliverStream calls (or several PDUs can be
          // pipelined into one). We accumulate per direction and hand the
          // (datagram) parser only complete PDUs. See DeliverStream.
          std::vector<u_char> orig_buffer;
          std::vector<u_char> resp_buffer;

          void ProcessTCPData(std::vector<u_char>& buffer, bool orig);

          // Drop bytes at the front of *buffer* until it starts on something
          // that can be an encapsulation header. Returns false when no
          // candidate is present yet (buffer trimmed to what a header could
          // still straddle).
          bool ResyncToHeader(std::vector<u_char>& buffer);
  };

  class ENIP_UDP_Analyzer : public analyzer::Analyzer
  {

      public:
          ENIP_UDP_Analyzer(Connection* conn);
          virtual ~ENIP_UDP_Analyzer();
          virtual void Done();

          virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen);

          static analyzer::Analyzer* Instantiate(Connection* conn)
          {
              return new ENIP_UDP_Analyzer(conn);
          }

      protected:
          binpac::ENIP::ENIP_Conn* interp;

  };
} // namespace zeek::analyzer::enip
