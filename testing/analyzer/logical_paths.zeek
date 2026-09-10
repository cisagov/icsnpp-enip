# @TEST-EXEC: python3 ${TRACES}/../scripts/make-logical-paths.py paths.pcap
# @TEST-EXEC: zeek -C -r paths.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Preserve 8/16/32-bit logical IDs and distinguish nested requests.

@load icsnpp/enip

event cip_header(c: connection, is_orig: bool, packet_correlation_id: string,
                 cip_sequence_count: count, service: count, response: bool,
                 status: count, status_extended: count, class_id: count,
                 instance_id: count, attribute_id: count, occurrence_count: count)
    {
    if ( service == 0x0e )
        print fmt("%x %x %x %d", class_id, instance_id, attribute_id, occurrence_count);
    }
