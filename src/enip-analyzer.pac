## enip-analyzer.pac
##
## Binpac Ethernet/IP (ENIP) Analyzer - Adds processing functions to ENIP_Flow to generate events.
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%header{

    typedef struct CIP_Request_Path {
        uint32 class_id, instance_id, attribute_id;

        CIP_Request_Path(){
            class_id = UINT32_MAX;
            instance_id = UINT32_MAX;
            attribute_id = UINT32_MAX;
        }

    }CIP_Request_Path;

    uint32 get_number(uint8 size, uint8 x, const_bytestring data);
    CIP_Request_Path parse_request_path(const_bytestring data);
    CIP_Request_Path parse_request_multiple_service_packet(const_bytestring data, uint16 starting_location);

%}

%code{

    // Get uint32 number from data in request path
    uint32 get_number(uint8 size, uint16 x, const_bytestring data)
    {
        if(size == 0)
            return data[x];
        else if (size == 1)
            return (data[x+1] << 8) | data[x];
        else if (size == 2)
            return (data[x+3] << 24) | (data[x+2] << 13) | (data[x+1] << 8) | data[x];

        return UINT32_MAX;
    }

    // Parse request path and return CIP_Request_Path struct
    CIP_Request_Path parse_request_path(const_bytestring data)
    {
        CIP_Request_Path request_path;

        uint16 x = 0;
        uint16 data_length = data.length();

        while( (x+1) < data_length )
        {
            if ((data[x] >> 5) == 1)
            {
                uint16 choice = (data[x] & 0x1c) >> 2;
                uint16 size = data[x] & 3;
                x += 1;
                if(size > 0)
                    x += 1;

                if(choice == 0)
                    request_path.class_id = get_number(size, x, data);
                else if(choice == 1)
                    request_path.instance_id = get_number(size, x, data);
                else if(choice == 4)
                    request_path.attribute_id = get_number(size, x, data);

                if(size == 0)
                    x += 1;
                else if(size == 1)
                    x += 2;
                else
                    x += 4;
            }
            else
            {
                return request_path;
            }
        }
        return request_path;
    }

    // Parse request path from multiple service packet and return CIP_Request_Path struct
    CIP_Request_Path parse_request_multiple_service_packet(const_bytestring data, uint16 starting_location)
    {
        CIP_Request_Path request_path;

        uint16 x = starting_location;
        uint16 data_length = starting_location + (data[x] * 2) + 1;
        x += 1;

        while( (x + 1) < data_length )
        {
            if ((data[x] >> 5) == 1)
            {
                uint16 choice = (data[x] & 0x1c) >> 2;
                uint16 size = data[x] & 3;
                x += 1;
                if(size > 0)
                    x += 1;

                if(choice == 0)
                    request_path.class_id = get_number(size, x, data);
                else if(choice == 1)
                    request_path.instance_id = get_number(size, x, data);
                else if(choice == 4)
                    request_path.attribute_id = get_number(size, x, data);

                if(size == 0)
                    x += 1;
                else if(size == 1)
                    x += 2;
                else
                    x += 4;
            }
            else
            {
                return request_path;
            }

        }
        return request_path;
    }

%}

refine flow ENIP_Flow += {

    ###############################################################################################
    ############################  Process data for enip_header event  #############################
    ###############################################################################################
    function process_enip_header(enip_header: ENIP_Header): bool
        %{
            if ( ::enip_header )
            {
                zeek::BifEvent::enqueue_enip_header(connection()->zeek_analyzer(),
                                                    connection()->zeek_analyzer()->Conn(),
                                                    ${enip_header.is_originator},
                                                    ${enip_header.command},
                                                    ${enip_header.length},
                                                    ${enip_header.session_handle},
                                                    ${enip_header.status},
                                                    to_stringval(${enip_header.sender_context}),
                                                    ${enip_header.options});
            }
            return true;
        %}

    ###############################################################################################
    #############################  Process data for cip_header event  #############################
    ###############################################################################################
    function process_cip_header(cip_header: CIP_Header): bool
        %{
            if ( ::cip_header )
            {
                // MULTIPLE_SERVICE CIP header data is parsed in process_multiple_service_request 
                // and process_multiple_service_response functions, so no need to duplicate
                // parsing here
                if(${cip_header.service_code} == MULTIPLE_SERVICE)
                    return true;

                CIP_Request_Path request_path;

                if(${cip_header.request_or_response} != 1)
                    request_path = parse_request_path(${cip_header.request_path.request_path});

                zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                   connection()->zeek_analyzer()->Conn(),
                                                   ${cip_header.is_originator},
                                                   ${cip_header.cip_sequence_count},
                                                   ${cip_header.service_code},
                                                   (${cip_header.request_or_response} == 1),
                                                   ${cip_header.status},
                                                   request_path.class_id,
                                                   request_path.instance_id,
                                                   request_path.attribute_id);
            }
            return true;
        %}

    ###############################################################################################
    ###############################  Process data for cip_io event  ###############################
    ###############################################################################################
    function process_cip_io(cip_io_item: CIP_IO): bool
        %{
            if ( ::cip_io )
            {
                zeek::BifEvent::enqueue_cip_io(connection()->zeek_analyzer(),
                                               connection()->zeek_analyzer()->Conn(),
                                               ${cip_io_item.is_originator},
                                               ${cip_io_item.sequenced_address_item.connection_identifier},
                                               ${cip_io_item.sequenced_address_item.encap_sequence_number},
                                               ${cip_io_item.connected_data_length},
                                               to_stringval(${cip_io_item.connected_data_item}));
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for cip_identity event  ############################
    ###############################################################################################
    function process_cip_identity_item(identity_item: CIP_Identity_Item): bool
        %{
            if ( ::cip_identity )
            {
                zeek::BifEvent::enqueue_cip_identity(connection()->zeek_analyzer(),
                                                     connection()->zeek_analyzer()->Conn(),
                                                     ${identity_item.encapsulation_version},
                                                     ${identity_item.socket_address.sin_addr},
                                                     ${identity_item.socket_address.sin_port},
                                                     ${identity_item.vendor_id},
                                                     ${identity_item.device_type},
                                                     ${identity_item.product_code},
                                                     ${identity_item.revision_major},
                                                     ${identity_item.revision_minor},
                                                     ${identity_item.status},
                                                     ${identity_item.serial_number},
                                                     to_stringval(${identity_item.product_name}),
                                                     ${identity_item.state});
            }
            return true;
        %}

    ###############################################################################################
    ##########################  Process data for register_session event  ##########################
    ###############################################################################################
    function process_register_session(message: Register_Session): bool
        %{
            if ( ::register_session )
            {
                zeek::BifEvent::enqueue_register_session(connection()->zeek_analyzer(),
                                                         connection()->zeek_analyzer()->Conn(),
                                                         ${message.protocol_version},
                                                         ${message.options_flags});
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for cip_security event  ############################
    ###############################################################################################
    function process_cip_security_item(security_item: CIP_Security_Item): bool
        %{
            if ( ::cip_security )
            {
                zeek::BifEvent::enqueue_cip_security(connection()->zeek_analyzer(),
                                                     connection()->zeek_analyzer()->Conn(),
                                                     ${security_item.security_profile},
                                                     ${security_item.cip_security_state},
                                                     ${security_item.enip_security_state},
                                                     ${security_item.iana_port_state});
            }
            return true;
        %}

    ###############################################################################################
    ##########################  Process data for enip_capability event  ###########################
    ###############################################################################################
    function process_enip_capability_item(enip_item: ENIP_Capability_Item): bool
        %{
            if ( ::enip_capability )
            {
                zeek::BifEvent::enqueue_enip_capability(connection()->zeek_analyzer(),
                                                        connection()->zeek_analyzer()->Conn(),
                                                        ${enip_item.enip_profile});
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for enip_service event  ############################
    ###############################################################################################
    function process_service_item(service_item: Service_Item): bool
        %{
            if ( ::enip_service )
            {
                zeek::BifEvent::enqueue_enip_service(connection()->zeek_analyzer(),
                                                     connection()->zeek_analyzer()->Conn(),
                                                     ${service_item.protocol_version},
                                                     ${service_item.capability_flags},
                                                     to_stringval(${service_item.service_name}));
            }
            return true;
        %}

    ###############################################################################################
    #########################  Process data for connected_address event  ##########################
    ###############################################################################################
    function process_connected_address_item(address_item: Connected_Address_Item): bool
        %{
            if ( ::connected_address )
            {
                zeek::BifEvent::enqueue_connected_address(connection()->zeek_analyzer(),
                                                          connection()->zeek_analyzer()->Conn(),
                                                          ${address_item.connection_identifier});
            }
            return true;
        %}

    ###############################################################################################
    #########################  Process data for sequenced_address event  ##########################
    ###############################################################################################
    function process_sequenced_address_item(address_item: Sequenced_Address_Item): bool
        %{
            if ( ::sequenced_address )
            {
                zeek::BifEvent::enqueue_sequenced_address(connection()->zeek_analyzer(),
                                                          connection()->zeek_analyzer()->Conn(),
                                                          ${address_item.connection_identifier},
                                                          ${address_item.encap_sequence_number});
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for unconnected_message_dtls event  ######################
    ###############################################################################################
    function process_unconnected_message_dtls(message: Unconnected_Message_DTLS): bool
        %{
            if ( ::unconnected_message_dtls )
            {
                zeek::BifEvent::enqueue_unconnected_message_dtls(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 ${message.unconn_message_type},
                                                                 ${message.transaction_number},
                                                                 ${message.status});
            }
            return true;
        %}

    ###############################################################################################
    ########################  Process data for socket_address_info event  #########################
    ###############################################################################################
    function process_socket_address_info(item: Socket_Address_Info_Item): bool
        %{
            if ( ::socket_address_info )
            {
                zeek::BifEvent::enqueue_socket_address_info(connection()->zeek_analyzer(),
                                                            connection()->zeek_analyzer()->Conn(),
                                                            ${item.sin_addr},
                                                            ${item.sin_port});
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for get_attribute_all_response event  #####################
    ###############################################################################################
    function process_get_attribute_all_response(data: Get_Attributes_All_Response): bool
        %{
            if ( ::get_attribute_all_response )
            {
                zeek::BifEvent::enqueue_get_attribute_all_response(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for set_attribute_all_request event  ######################
    ###############################################################################################
    function process_set_attribute_all_request(data: Set_Attributes_All_Request): bool
        %{
            if ( ::set_attribute_all_request )
            {
                zeek::BifEvent::enqueue_set_attribute_all_request(connection()->zeek_analyzer(),
                                                                  connection()->zeek_analyzer()->Conn(),
                                                                  to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for get_attribute_list_request event  #####################
    ###############################################################################################
    function process_get_attribute_list_request(data: Get_Attribute_List_Request): bool
        %{
            if ( ::get_attribute_list_request )
            {
                string attribute_ids = zeek::util::fmt("%d",${data.attribute_list[0]});

                for(uint8 i=1; i<${data.attribute_count};i++)
                    attribute_ids += zeek::util::fmt(",%d",${data.attribute_list[i]});

                zeek::BifEvent::enqueue_get_attribute_list_request(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   ${data.attribute_count},
                                                                   zeek::make_intrusive<zeek::StringVal>(attribute_ids));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for get_attribute_list_response event  #####################
    ###############################################################################################
    function process_get_attribute_list_response(data: Get_Attribute_List_Response): bool
        %{
            if ( ::get_attribute_list_response )
            {
                zeek::BifEvent::enqueue_get_attribute_list_response(connection()->zeek_analyzer(),
                                                                    connection()->zeek_analyzer()->Conn(),
                                                                    ${data.attribute_count},
                                                                    to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for set_attribute_list_request event  #####################
    ###############################################################################################
    function process_set_attribute_list_request(data: Set_Attribute_List_Request): bool
        %{
            if ( ::set_attribute_list_request )
            {
                zeek::BifEvent::enqueue_set_attribute_list_request(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   ${data.attribute_count},
                                                                   to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for set_attribute_list_response event  #####################
    ###############################################################################################
    function process_set_attribute_list_response(data: Set_Attribute_List_Response): bool
        %{
            if ( ::set_attribute_list_response )
            {
                zeek::BifEvent::enqueue_set_attribute_list_response(connection()->zeek_analyzer(),
                                                                    connection()->zeek_analyzer()->Conn(),
                                                                    ${data.attribute_count},
                                                                    to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for multiple_service_request event  ######################
    ###############################################################################################
    function process_multiple_service_request(data: Multiple_Service_Packet_Request): bool
        %{
            if ( ::cip_header )
            {
                uint16 service_packet_location;

                uint8 service_count = ${data.service_count};
                uint16 cip_sequence_count = ${data.cip_sequence_count};
                CIP_Request_Path request_path = parse_request_path(${data.request_path.request_path});

                // CIP Header event for multiple service packet
                zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                   connection()->zeek_analyzer()->Conn(),
                                                   ${data.cip_sequence_count},
                                                   MULTIPLE_SERVICE,
                                                   false,
                                                   0,
                                                   request_path.class_id,
                                                   request_path.instance_id,
                                                   request_path.attribute_id);

                // CIP Header event for each service within multiple service packet
                for(uint8 i=0; i < service_count;i++)
                {
                    service_packet_location = ${data.service_offsets[i]} - (2*service_count) - 2;
                    request_path = parse_request_multiple_service_packet(${data.services},service_packet_location+1);

                    zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                       connection()->zeek_analyzer()->Conn(),
                                                       cip_sequence_count,
                                                       ${data.services[service_packet_location]} & 0x7f,
                                                       false,
                                                       0,
                                                       request_path.class_id,
                                                       request_path.instance_id,
                                                       request_path.attribute_id);
                }
            }

            return true;
        %}

    ###############################################################################################
    #####################  Process data for multiple_service_response event  ######################
    ###############################################################################################
    function process_multiple_service_response(data: Multiple_Service_Packet_Response): bool
        %{
            if ( ::cip_header )
            {
                CIP_Request_Path request_path;
                uint16 service_packet_location;
                
                uint8 service_count = ${data.service_count};
                uint16 cip_sequence_count = ${data.cip_sequence_count};

                // CIP Header event for multiple service packet
                zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                   connection()->zeek_analyzer()->Conn(),
                                                   ${data.cip_sequence_count},
                                                   MULTIPLE_SERVICE,
                                                   true,
                                                   ${data.status},
                                                   request_path.class_id,
                                                   request_path.instance_id,
                                                   request_path.attribute_id);

                // CIP Header event for each service within multiple service packet
                for(uint8 i=0; i < service_count;i++)
                {
                    service_packet_location = ${data.service_offsets[i]} - (2*service_count) - 2;

                    zeek::BifEvent::enqueue_cip_header(connection()->zeek_analyzer(),
                                                       connection()->zeek_analyzer()->Conn(),
                                                       cip_sequence_count,
                                                       ${data.services[service_packet_location]} & 0x7f,
                                                       true,
                                                       ${data.services[service_packet_location + 2]},
                                                       request_path.class_id,
                                                       request_path.instance_id,
                                                       request_path.attribute_id);
                }
            }
            return true;
        %}

    ###############################################################################################
    ###################  Process data for get_attribute_single_response event  ####################
    ###############################################################################################
    function process_get_attribute_single_response(data: Get_Attribute_Single_Response): bool
        %{
            if ( ::get_attribute_single_response )
            {
                zeek::BifEvent::enqueue_get_attribute_single_response(connection()->zeek_analyzer(),
                                                                      connection()->zeek_analyzer()->Conn(),
                                                                      to_stringval(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for set_attribute_single_request event  ####################
    ###############################################################################################
    function process_set_attribute_single_request(data: Set_Attribute_Single_Request): bool
        %{
            if ( ::set_attribute_single_request )
            {
                zeek::BifEvent::enqueue_set_attribute_single_request(connection()->zeek_analyzer(),
                                                                     connection()->zeek_analyzer()->Conn(),
                                                                     ${data.attribute_id},
                                                                     to_stringval(${data.attribute_data}));
            }
            return true;
        %}
};
