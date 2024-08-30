##! main.zeek
##!
##! Binpac Ethernet/IP (ENIP) Analyzer - Contains the base script-layer functionality for
##!                                      processing events emitted from the analyzer.
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

module ENIP;

export{
    redef enum Log::ID += { LOG_ENIP,
                            LOG_CIP,
                            LOG_CIP_IO,
                            LOG_CIP_IDENTITY };

    ###############################################################################################
    ##################################  ENIP_Header -> enip.log  ##################################
    ###############################################################################################
    type ENIP_Header: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        is_orig                 : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &log;   # Source IP Address
        source_p                : port      &log;   # Source Port
        destination_h           : addr      &log;   # Destination IP Address
        destination_p           : port      &log;   # Destination Port
        packet_correlation_id   : string    &log;   # A correlation ID that ties ENIP headers to associated CIP packets (packet rather than connection based)
        enip_command_code       : string    &log;   # Ethernet/IP Command Code (in hex)
        enip_command            : string    &log;   # Ethernet/IP Command Name (see enip_commands)
        length                  : count     &log;   # Length of ENIP data following header
        session_handle          : string    &log;   # Sesesion identifier
        enip_status             : string    &log;   # Status code (see enip_statuses)
        sender_context          : string    &log;   # Sender context
        options                 : string    &log;   # Options flags
    };
    global log_enip: event(rec: ENIP_Header);
    global log_policy_enip: Log::PolicyHook;

    ###############################################################################################
    ###################################  CIP_Header -> cip.log  ###################################
    ###############################################################################################
    type CIP_Header: record {
        ts                          : time      &log;   # Timestamp of event
        uid                         : string    &log;   # Zeek unique ID for connection
        id                          : conn_id   &log;   # Zeek connection struct (addresses and ports)
        is_orig                     : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                    : addr      &log;   # Source IP Address
        source_p                    : port      &log;   # Source Port
        destination_h               : addr      &log;   # Destination IP Address
        destination_p               : port      &log;   # Destination Port
        packet_correlation_id       : string    &log;   # A correlation ID that ties ENIP headers to associated CIP packets (packet rather than connection based)
        cip_sequence_count          : count     &log;   # CIP sequence number for transport
        direction                   : string    &log;   # Request or Response
        cip_service_code            : string    &log;   # CIP service code (in hex)
        cip_service                 : string    &log;   # CIP service name (see cip_services)
        cip_status_code             : string    &log;   # CIP status code (in hex)
        cip_status                  : string    &log;   # CIP status description (see cip_statuses)
        cip_extended_status_code    : string    &log;   # CIP extended status code (in hex)
        cip_extended_status         : string    &log;   # CIP extended status description (see cip_extended_statuses)
        class_id                    : string    &log;   # CIP Request Path - Class ID
        class_name                  : string    &log;   # CIP Request Path - Class Name (see cip_classes)
        instance_id                 : string    &log;   # CIP Request Path - Instance ID
        attribute_id                : string    &log;   # CIP Request Path - Attribute ID
    };
    global log_cip: event(rec: CIP_Header);
    global log_policy_cip: Log::PolicyHook;

    ###############################################################################################
    ##################################  CIP_IO_Log -> cip_io.log  #################################
    ###############################################################################################
    type CIP_IO_Log: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        is_orig                 : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &log;   # Source IP Address
        source_p                : port      &log;   # Source Port
        destination_h           : addr      &log;   # Destination IP Address
        destination_p           : port      &log;   # Destination Port
        packet_correlation_id   : string    &log;   # A correlation ID that ties ENIP headers to associated CIP packets (packet rather than connection based)
        connection_id           : string    &log;   # CIP Connection Identifier
        sequence_number         : count     &log;   # CIP Sequence Number with Connection
        data_length             : count     &log;   # Length of io_data field
        io_data                 : string    &log;   # CIP IO Data
    };
    global log_cip_io: event(rec: CIP_IO_Log);
    global log_policy_cip_io: Log::PolicyHook;

    ###############################################################################################
    #########################  CIP_Identity_Item_Log -> cip_identity.log  #########################
    ###############################################################################################
    type CIP_Identity_Item_Log: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        is_orig                 : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &log;   # Source IP Address
        source_p                : port      &log;   # Source Port
        destination_h           : addr      &log;   # Destination IP Address
        destination_p           : port      &log;   # Destination Port
        packet_correlation_id   : string    &log;   # A correlation ID that ties ENIP headers to associated CIP packets (packet rather than connection based)
        encapsulation_version   : count     &log;   # Encapsulation protocol version supported
        socket_address          : addr      &log;   # Socket address IP address
        socket_port             : count     &log;   # Socket address port number
        vendor_id               : count     &log;   # Vendor ID
        vendor_name             : string    &log;   # Name of Vendor (see cip_vendors)
        device_type_id          : count     &log;   # Device type ID
        device_type_name        : string    &log;   # Name of device type (see cip_device_types)
        product_code            : count     &log;   # Product code assigned to device
        revision                : string    &log;   # Device revision (major.minor)
        device_status           : string    &log;   # Current status of device (see cip_statuses)
        serial_number           : string    &log;   # Serial number of device
        product_name            : string    &log;   # Human readable description of device
        device_state            : string    &log;   # Current state of the device
    };
    global log_cip_identity: event(rec: CIP_Identity_Item_Log);
    global log_policy_cip_identity: Log::PolicyHook;
}

# Defines ENIP/CIP ports
const ports = {
    2222/udp,
    44818/tcp,
    44818/udp,
};

# Defines ENIP/CIP UDP ports
const udp_ports = {
    2222/udp,
    44818/udp,
};

# Defines Implicit UDP ENIP/CIP I/O ports
const udp_implicit_ports = {
    2222/udp,
};

# Defines ENIP/CIP TCP ports
const tcp_ports = {
    44818/tcp,
};
redef likely_server_ports += { ports };

###################################################################################################
################  Defines Log Streams for enip.log, cip.log, and cip_identity.log  ################
###################################################################################################
event zeek_init() &priority=5 {
    Log::create_stream(ENIP::LOG_ENIP, [$columns=ENIP_Header,
                                        $ev=log_enip,
                                        $path="enip",
                                        $policy=log_policy_enip]);

    Log::create_stream(ENIP::LOG_CIP, [$columns=CIP_Header,
                                       $ev=log_cip,
                                       $path="cip",
                                       $policy=log_policy_cip]);

    Log::create_stream(ENIP::LOG_CIP_IO, [$columns=CIP_IO_Log,
                                          $ev=log_cip_io,
                                          $path="cip_io",
                                          $policy=log_policy_cip_io]);

    Log::create_stream(ENIP::LOG_CIP_IDENTITY, [$columns=CIP_Identity_Item_Log,
                                                $ev=log_cip_identity,
                                                $path="cip_identity",
                                                $policy=log_policy_cip_identity]);
    #Analyzer::register_for_ports(Analyzer::ANALYZER_ENIP_TCP, tcp_ports);
    #Analyzer::register_for_ports(Analyzer::ANALYZER_ENIP_UDP, udp_ports);
    # Monitor only the UDP Port assigned to implicit ENIP/CIP IO Messages
    Analyzer::register_for_ports(Analyzer::ANALYZER_ENIP_UDP, udp_implicit_ports);
}

###################################################################################################
#######  Ensure that conn.log:service is set if it has not already been                     #######
###################################################################################################
function set_service(c: connection, service: string) {
    if ((!c?$service) || (|c$service| == 0))
        add c$service[service];
}

###################################################################################################
#######################  Defines logging of enip_header event -> enip.log  ########################
###################################################################################################
event enip_header(c: connection,
                  is_orig: bool,
                  packet_correlation_id: string,
                  command: count,
                  length: count,
                  session_handle: count,
                  status: count,
                  sender_context: string,
                  options: count) {

    set_service(c, "enip");
    local enip_item: ENIP_Header;
    enip_item$ts  = network_time();
    enip_item$uid = c$uid;
    enip_item$id  = c$id;
    enip_item$is_orig  = is_orig;

    if(is_orig)
    {
        enip_item$source_h = c$id$orig_h;
        enip_item$source_p = c$id$orig_p;
        enip_item$destination_h = c$id$resp_h;
        enip_item$destination_p = c$id$resp_p;
    }else
    {
        enip_item$source_h = c$id$resp_h;
        enip_item$source_p = c$id$resp_p;
        enip_item$destination_h = c$id$orig_h;
        enip_item$destination_p = c$id$orig_p;
    }

    enip_item$packet_correlation_id = packet_correlation_id;
    enip_item$enip_command_code = fmt("0x%02x",command);
    enip_item$enip_command = enip_commands[command];
    enip_item$length = length;
    enip_item$session_handle = fmt("0x%08x", session_handle);
    enip_item$enip_status = enip_statuses[status];
    enip_item$sender_context = fmt("0x%s", bytestring_to_hexstr(sender_context));
    enip_item$options = fmt("0x%08x", options);

    Log::write(LOG_ENIP, enip_item);
}

###################################################################################################
########################  Defines logging of cip_header event -> cip.log  #########################
###################################################################################################
event cip_header(c: connection,
                 is_orig: bool,
                 packet_correlation_id: string,
                 cip_sequence_count: count,
                 service: count,
                 response: bool,
                 status: count,
                 status_extended: count,
                 class_id: count,
                 instance_id: count,
                 attribute_id: count){

    set_service(c, "cip");
    local cip_header_item: CIP_Header;
    cip_header_item$ts  = network_time();
    cip_header_item$uid = c$uid;
    cip_header_item$id  = c$id;
    cip_header_item$is_orig  = is_orig;

    if(is_orig)
    {
        cip_header_item$source_h = c$id$orig_h;
        cip_header_item$source_p = c$id$orig_p;
        cip_header_item$destination_h = c$id$resp_h;
        cip_header_item$destination_p = c$id$resp_p;
    }else
    {
        cip_header_item$source_h = c$id$resp_h;
        cip_header_item$source_p = c$id$resp_p;
        cip_header_item$destination_h = c$id$orig_h;
        cip_header_item$destination_p = c$id$orig_p;
    }

    if (cip_sequence_count != 0)
        cip_header_item$cip_sequence_count = cip_sequence_count;

    cip_header_item$packet_correlation_id = packet_correlation_id;
    cip_header_item$cip_service_code = fmt("0x%02x",service);
    cip_header_item$cip_service = cip_services[service];

    if(response)
    {
        cip_header_item$direction = "response";
        if (status != UINT32_MAX )
        {
            cip_header_item$cip_status_code = fmt("0x%02x", status);
            cip_header_item$cip_status = cip_statuses[status];
        }

        if (status_extended != UINT32_MAX )
        {
            cip_header_item$cip_extended_status_code = fmt("0x%04x", status_extended);
            cip_header_item$cip_extended_status = cip_extended_status[status_extended];
        }
    }else
    {
        cip_header_item$direction = "request";

        if(class_id != UINT32_MAX){
            cip_header_item$class_id = fmt("0x%02x",class_id);
            cip_header_item$class_name = cip_classes[class_id];
        }

        if(instance_id != UINT32_MAX)
            cip_header_item$instance_id = fmt("0x%02x",instance_id);

        if(attribute_id != UINT32_MAX)
            cip_header_item$attribute_id = fmt("0x%02x",attribute_id);

    }

    Log::write(LOG_CIP, cip_header_item);
}

###################################################################################################
#########################  Defines logging of cip_io event -> cip_io.log  #########################
###################################################################################################
event cip_io(c: connection,
             is_orig: bool,
             packet_correlation_id: string,
             connection_identifier: count,
             sequence_number: count,
             data_length: count,
             data: string){

    set_service(c, "cip");
    local cip_io_item: CIP_IO_Log;
    cip_io_item$ts  = network_time();
    cip_io_item$uid = c$uid;
    cip_io_item$id  = c$id;
    cip_io_item$is_orig  = is_orig;

    if(is_orig)
    {
        cip_io_item$source_h = c$id$orig_h;
        cip_io_item$source_p = c$id$orig_p;
        cip_io_item$destination_h = c$id$resp_h;
        cip_io_item$destination_p = c$id$resp_p;
    }else
    {
        cip_io_item$source_h = c$id$resp_h;
        cip_io_item$source_p = c$id$resp_p;
        cip_io_item$destination_h = c$id$orig_h;
        cip_io_item$destination_p = c$id$orig_p;
    }

    cip_io_item$packet_correlation_id = packet_correlation_id;
    cip_io_item$connection_id = fmt("0x%08x", connection_identifier);;
    cip_io_item$sequence_number = sequence_number;
    cip_io_item$data_length = data_length;
    cip_io_item$io_data = bytestring_to_hexstr(data);

    Log::write(LOG_CIP_IO, cip_io_item);
}

###################################################################################################
###################  Defines logging of cip_identity event -> cip_identity.log  ###################
###################################################################################################
event cip_identity(c: connection, 
                   is_orig: bool,
                   packet_correlation_id: string,
                   encapsulation_version: count,
                   socket_address: count,
                   socket_port: count,
                   vendor_id: count,
                   device_type: count,
                   product_code: count,
                   revision_major: count,
                   revision_minor: count,
                   status: count,
                   serial_number: count,
                   product_name: string,
                   state: count ){

    set_service(c, "cip");
    local cip_identity_item: CIP_Identity_Item_Log;
    cip_identity_item$ts  = network_time();
    cip_identity_item$uid = c$uid;
    cip_identity_item$id  = c$id;
    cip_identity_item$is_orig  = is_orig;

    if(is_orig)
    {
        cip_identity_item$source_h = c$id$orig_h;
        cip_identity_item$source_p = c$id$orig_p;
        cip_identity_item$destination_h = c$id$resp_h;
        cip_identity_item$destination_p = c$id$resp_p;
    }else
    {
        cip_identity_item$source_h = c$id$resp_h;
        cip_identity_item$source_p = c$id$resp_p;
        cip_identity_item$destination_h = c$id$orig_h;
        cip_identity_item$destination_p = c$id$orig_p;
    }

    cip_identity_item$packet_correlation_id = packet_correlation_id;

    cip_identity_item$encapsulation_version = encapsulation_version;
    cip_identity_item$socket_address = count_to_v4_addr(socket_address);
    cip_identity_item$socket_port = socket_port;
    cip_identity_item$vendor_id = vendor_id;
    cip_identity_item$vendor_name = cip_vendors[vendor_id];
    cip_identity_item$device_type_id = device_type;
    cip_identity_item$device_type_name = cip_device_types[device_type];
    cip_identity_item$product_code = product_code;
    cip_identity_item$revision = fmt("%d.%d", revision_major, revision_minor);
    cip_identity_item$device_status = fmt("0x%04x", status);
    cip_identity_item$serial_number = fmt("0x%08x", serial_number);
    cip_identity_item$product_name = product_name;
    cip_identity_item$device_state = fmt("0x%04x", state);
    Log::write(LOG_CIP_IDENTITY, cip_identity_item);
}
