# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test common, class-specific, boundary, and unknown CIP service names.

@load icsnpp/enip

event zeek_init()
    {
    print ENIP::cip_service_name(0x0e, 0xffffffff);
    print ENIP::cip_service_name(0x31, 0x01);
    print ENIP::cip_service_name(0x4c, 0x02);
    print ENIP::cip_service_name(0x4d, 0x53);
    print ENIP::cip_service_name(0x4b, 0x9999);
    }
