// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#include "ENIP.h"
#include <zeek/analyzer/protocol/tcp/TCP_Reassembler.h>
#include <zeek/Reporter.h>
#include "events.bif.h"

namespace {
const char* BinpacExceptionMessage(const binpac::Exception& e)
{
#if ZEEK_VERSION_NUMBER >= 90000
    return e.what();
#else
    return e.c_msg();
#endif
}
} // namespace

namespace zeek::analyzer::enip {
  ENIP_TCP_Analyzer::ENIP_TCP_Analyzer(Connection* c): analyzer::tcp::TCP_ApplicationAnalyzer("ENIP_TCP", c)
  {
      interp = new binpac::ENIP::ENIP_Conn(this);
      had_gap = false;
  }

  ENIP_TCP_Analyzer::~ENIP_TCP_Analyzer()
  {
      delete interp;
  }

  void ENIP_TCP_Analyzer::Done()
  {
      analyzer::tcp::TCP_ApplicationAnalyzer::Done();
      interp->FlowEOF(true);
      interp->FlowEOF(false);
  }

  void ENIP_TCP_Analyzer::EndpointEOF(bool is_orig)
  {
      analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
      interp->FlowEOF(is_orig);
  }

  void ENIP_TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
  {
      analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
      assert(TCP());

      // ENIP over TCP is length-prefixed: a fixed 24-byte encapsulation header
      // whose bytes 2-3 (little-endian) give the length of the data that
      // follows, so a whole PDU is 24 + that length. Zeek reassembles the TCP
      // stream, but a single PDU can still be split across DeliverStream calls,
      // and several PDUs can be pipelined into one delivery. The binpac flow
      // parses each NewData buffer as one complete PDU, so accumulate per
      // direction and hand it only whole PDUs — otherwise a segment-spanning
      // PDU parses partially and is dropped (out_of_bound), and any PDU after
      // the first in a delivery is never seen.
      std::vector<u_char>& buffer = orig ? orig_buffer : resp_buffer;
      buffer.insert(buffer.end(), data, data + len);
      ProcessTCPData(buffer, orig);
  }

  void ENIP_TCP_Analyzer::ProcessTCPData(std::vector<u_char>& buffer, bool orig)
  {
      static constexpr size_t ENIP_HEADER_LEN = 24;
      // Encapsulation length is a uint16, so a PDU is at most 24 + 0xFFFF.
      static constexpr size_t ENIP_MAX_PDU_LEN = ENIP_HEADER_LEN + 0xFFFF;

      size_t offset = 0;
      while ( buffer.size() - offset >= ENIP_HEADER_LEN )
      {
          const u_char* pdu = buffer.data() + offset;
          size_t enc_len = pdu[2] | (static_cast<size_t>(pdu[3]) << 8);
          size_t pdu_len = ENIP_HEADER_LEN + enc_len;

          if ( buffer.size() - offset < pdu_len )
              break;  // wait for the rest of this PDU

          try
          {
              interp->NewData(orig, pdu, pdu + pdu_len);
          }
          catch(const binpac::Exception& e)
          {
              #if ZEEK_VERSION_NUMBER < 40200
              ProtocolViolation(util::fmt("Binpac exception: %s", BinpacExceptionMessage(e)));

              #else
              AnalyzerViolation(util::fmt("Binpac exception: %s", BinpacExceptionMessage(e)));

              #endif
          }

          offset += pdu_len;
      }

      if ( offset > 0 )
          buffer.erase(buffer.begin(), buffer.begin() + offset);

      // Bound memory if we're wedged mid-PDU on an implausible length field
      // (e.g. non-ENIP traffic on the port); resync on the next header.
      if ( buffer.size() > ENIP_MAX_PDU_LEN )
          buffer.clear();
  }

  void ENIP_TCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
  {
      analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
      had_gap = true;
      // A TCP gap desynchronizes PDU framing: drop the partial buffer for this
      // direction so we resync on the next complete header rather than treating
      // post-gap bytes as a continuation of the pre-gap PDU.
      (orig ? orig_buffer : resp_buffer).clear();
      interp->NewGap(orig, len);
  }

  ENIP_UDP_Analyzer::ENIP_UDP_Analyzer(Connection* c): analyzer::Analyzer("ENIP_UDP", c)
  {
      interp = new binpac::ENIP::ENIP_Conn(this);
  }

  ENIP_UDP_Analyzer::~ENIP_UDP_Analyzer()
  {
      delete interp;
  }

  void ENIP_UDP_Analyzer::Done()
  {
      zeek::analyzer::Analyzer::Done();
  }

  void ENIP_UDP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip, int caplen)
  {
      zeek::analyzer::Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

      try
      {
          interp->NewData(orig, data, data + len);
      }
      catch ( const binpac::Exception& e )
      {
          #if ZEEK_VERSION_NUMBER < 40200
          ProtocolViolation(util::fmt("Binpac exception: %s", BinpacExceptionMessage(e)));

          #else
          AnalyzerViolation(util::fmt("Binpac exception: %s", BinpacExceptionMessage(e)));

          #endif
      }
  }
}
