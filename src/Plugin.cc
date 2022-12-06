// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
#include "Plugin.h"
#include "zeek/analyzer/Component.h"

namespace plugin
{
    namespace ICSNPP_ENIP
    {
        Plugin plugin;
    }
}

using namespace plugin::ICSNPP_ENIP;

zeek::plugin::Configuration Plugin::Configure()
{
    AddComponent(new zeek::analyzer::Component("ENIP_TCP",zeek::analyzer::enip::ENIP_TCP_Analyzer::Instantiate));
    AddComponent(new zeek::analyzer::Component("ENIP_UDP",zeek::analyzer::enip::ENIP_UDP_Analyzer::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "ICSNPP::ENIP";
    config.description = "Ethernet/IP and CIP Protocol analyzer for TCP/UDP";
    config.version.major = 1;
    config.version.minor = 3;

    return config;
}
