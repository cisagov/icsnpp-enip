## enip-utilities.pac
##
## ENIP/CIP Protocol Analyzer
##
## Analyzer utilitiy functions.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.


%extern{
/*
Note: 
The binpac compiler generates one header file along with the associated source file so there
isn't a need to bring in additional headers here.  We'll just track header files in the
enip-analyzer.pac binpac file.
*/
%}

%header{
    #define ID_LEN 9
    string generateId();
%}

%code{

    //
    // Utility function used to generate unique id associated with the ENIP logs.  While
    // this id is NOT part of the ENIP/CIP documented spec, we use it to tie nested log files
    // together - e.g. any nested log files such as the status code detail log will contain
    // this id which can be used to reference back to the primary ENIP/CIP log file.
    //
    // The implemenation was taken from: https://lowrey.me/guid-generation-in-c-11/
    //
    std::string generateId() {
        std::stringstream ss;
        for (auto i = 0; i < ID_LEN; i++) {
            // Generate a random char
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            const auto rc = dis(gen);

            // Hex representaton of random char
            std::stringstream hexstream;
            hexstream << std::hex << rc;
            auto hex = hexstream.str();
            ss << (hex.length() < 2 ? '0' + hex : hex);
        }
        return ss.str();
    }
%}

refine flow ENIP_Flow += {
    function generate_packet_id(): string
    %{
        return(generateId());
    %}
}
