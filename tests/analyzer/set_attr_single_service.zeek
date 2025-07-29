# @TEST-EXEC: zeek -C -r ${TRACES}/set_attribute_single_service_cip.pcapng %INPUT
# @TEST-EXEC: zeek-cut -n packet_correlation_id < cip.log > cip.tmp && mv cip.tmp cip.log
# @TEST-EXEC: zeek-cut -n packet_correlation_id < enip.log > enip.tmp && mv enip.tmp enip.log
# @TEST-EXEC: btest-diff cip.log
# @TEST-EXEC: btest-diff enip.log
#
# @TEST-DOC: Test ENIP analyzer with set attribute single service request.

@load icsnpp/enip
