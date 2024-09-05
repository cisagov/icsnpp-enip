# @TEST-EXEC: zeek -C -r ${TRACES}/enip_cip_example.pcap %INPUT
# @TEST-EXEC: zeek-cut -n packet_correlation_id < cip.log > cip.tmp && mv cip.tmp cip.log
# @TEST-EXEC: zeek-cut -n packet_correlation_id < cip_identity.log > cip_identity.tmp && mv cip_identity.tmp cip_identity.log
# @TEST-EXEC: zeek-cut -n packet_correlation_id < cip_io.log > cip_io.tmp && mv cip_io.tmp cip_io.log
# @TEST-EXEC: zeek-cut -n packet_correlation_id < enip.log > enip.tmp && mv enip.tmp enip.log
# @TEST-EXEC: btest-diff cip.log
# @TEST-EXEC: btest-diff cip_identity.log
# @TEST-EXEC: btest-diff cip_io.log
# @TEST-EXEC: btest-diff enip.log
#
# @TEST-DOC: Test ENIP analyzer with small trace.

@load icsnpp/enip
