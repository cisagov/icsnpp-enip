// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#include "ENIP.h"
#include <zeek/analyzer/protocol/tcp/TCP_Reassembler.h>
#include <zeek/Reporter.h>
#include "events.bif.h"

namespace {
  // CIP Vol 2 encapsulation header, 24 bytes, little-endian:
  //   0-1  command   2-3  length   4-7  session handle   8-11 status
  //   12-19 sender context        20-23 options (shall be 0)
  constexpr size_t ENIP_HEADER_LEN = 24;
  // `length` counts only the data AFTER the header. Bounding it so that
  // header + data still fits a uint16 (0xFFFF - 24 = 65511) is the largest
  // single PDU the encapsulation layer can describe. Weak as a filter on its
  // own -- it rejects 24 of 65536 values -- but free, and it stops the parse
  // loop from parking on a 64 KB phantom.
  constexpr size_t ENIP_MAX_DATA_LEN = 0xFFFF - ENIP_HEADER_LEN;

  // The command codes this package's own grammar models (src/consts.pac
  // `command_codes`), MINUS NOP (0x0000). NOP is legal, but `00 00` is far too
  // common in binary payload to lock onto during a resync, and a NOP carries no
  // data — skipping one costs nothing, locking onto a false one costs a PDU.
  // Deliberately derived from the grammar's enum, not from the spec at large:
  // a header this check accepts but the grammar cannot parse would trade a
  // silent skip for an analyzer violation.
  inline bool plausible_command(uint16_t command)
  {
      switch ( command )
      {
          case 0x0004:  // ListServices
          case 0x0063:  // ListIdentity
          case 0x0064:  // ListInterfaces
          case 0x0065:  // RegisterSession
          case 0x0066:  // UnRegisterSession
          case 0x006F:  // SendRRData
          case 0x0070:  // SendUnitData
          case 0x00C8:  // StartDTLS
              return true;
          default:
              return false;
      }
  }

  // Three independent constraints: a modelled command (8 of 65536 values,
  // ~2^-13), a length inside the encapsulation bound (near-free), and a zero
  // Options field (2^-32), which CIP Vol 2 requires to be 0 for every command.
  // Roughly 2^-45 of arbitrary payload passes, which is what makes scanning
  // byte-by-byte for a boundary safe rather than a way to invent PDUs.
  inline bool looks_like_encap_header(const u_char* p)
  {
      const uint16_t command = static_cast<uint16_t>(p[0] | (p[1] << 8));
      if ( ! plausible_command(command) )
          return false;
      const size_t length = p[2] | (static_cast<size_t>(p[3]) << 8);
      if ( length > ENIP_MAX_DATA_LEN )
          return false;
      return p[20] == 0 && p[21] == 0 && p[22] == 0 && p[23] == 0;
  }
}

namespace zeek::analyzer::enip {
  ENIP_TCP_Analyzer::ENIP_TCP_Analyzer(Connection* c): analyzer::tcp::TCP_ApplicationAnalyzer("ENIP_TCP", c)
  {
      interp = new binpac::ENIP::ENIP_Conn(this);
      resync_orig = false;
      resync_resp = false;
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

      // After a gap the first post-gap byte is a PDU boundary only by luck —
      // the old code assumed it was one, read bytes 2-3 of whatever landed there as
      // a length, and then either handed binpac a garbage PDU (an analyzer
      // violation, and it ate the real PDUs behind it) or wedged until the
      // 64 KB bound clears the buffer. Skip to a real header instead.
      bool& resync = orig ? resync_orig : resync_resp;
      if ( resync )
      {
          if ( ! ResyncToHeader(buffer) )
              return;
          resync = false;
      }

      ProcessTCPData(buffer, orig);
  }

  bool ENIP_TCP_Analyzer::ResyncToHeader(std::vector<u_char>& buffer)
  {
      if ( buffer.size() >= ENIP_HEADER_LEN )
      {
          const size_t last = buffer.size() - ENIP_HEADER_LEN;
          for ( size_t off = 0; off <= last; ++off )
          {
              if ( looks_like_encap_header(buffer.data() + off) )
              {
                  buffer.erase(buffer.begin(), buffer.begin() + off);
                  return true;
              }
          }
      }

      // No candidate yet. Keep only what a header could still straddle, so a
      // direction that never resynchronises costs 23 bytes, not the rest of
      // the connection.
      if ( buffer.size() > ENIP_HEADER_LEN - 1 )
          buffer.erase(buffer.begin(), buffer.end() - (ENIP_HEADER_LEN - 1));
      return false;
  }

  void ENIP_TCP_Analyzer::ProcessTCPData(std::vector<u_char>& buffer, bool orig)
  {
      // ENIP_HEADER_LEN and the PDU bound come from the anonymous namespace
      // above so the framing constants cannot drift between the parse loop and
      // the resync scan.
      constexpr size_t ENIP_MAX_PDU_LEN = ENIP_HEADER_LEN + 0xFFFF;

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
              ProtocolViolation(util::fmt("Binpac exception: %s", e.c_msg()));

              #else
              AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));

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
      // A TCP gap desynchronizes PDU framing: drop the partial buffer for this
      // direction so we resync on the next complete header rather than treating
      // post-gap bytes as a continuation of the pre-gap PDU. The peer direction
      // is untouched and keeps parsing.
      (orig ? orig_buffer : resp_buffer).clear();
      (orig ? resync_orig : resync_resp) = true;
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
          ProtocolViolation(util::fmt("Binpac exception: %s", e.c_msg()));

          #else
          AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));

          #endif
      }
  }
}