# @TEST-EXEC: zeek -C -r ${TRACES}/malformed_request_paths.pcapng %INPUT
# @TEST-EXEC: zeek-cut -n packet_correlation_id < cip.log > cip.tmp && mv cip.tmp cip.log
# @TEST-EXEC: btest-diff cip.log
#
# @TEST-DOC: Test truncated request paths, cross-service path lengths, and invalid Multiple Service offsets are handled safely.

@load icsnpp/enip
