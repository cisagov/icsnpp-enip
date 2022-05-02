# @TEST-EXEC: zeek -C -r ${TRACES}/enip_cip_example.pcap %INPUT
# @TEST-EXEC: btest-diff cip.log
# @TEST-EXEC: btest-diff cip_identity.log
# @TEST-EXEC: btest-diff cip_io.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff enip.log
#
# @TEST-DOC: Test ENIP analyzer with small trace.

@load icsnpp/enip
