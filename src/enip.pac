%include zeek/binpac.pac
%include zeek/zeek.pac

%extern{
    #include "events.bif.h"
%}

analyzer ENIP withcontext {
    connection: ENIP_Conn;
    flow:       ENIP_Flow;
};

connection ENIP_Conn(zeek_analyzer: ZeekAnalyzer) {
    upflow   = ENIP_Flow(true);
    downflow = ENIP_Flow(false);
};

%include enip-protocol.pac

flow ENIP_Flow(is_orig: bool) {
    datagram = ENIP_PDU(is_orig) withcontext(connection, this);
}

%include enip-analyzer.pac