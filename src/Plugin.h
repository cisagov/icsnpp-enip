// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.
#pragma once

#include <zeek/plugin/Plugin.h>
#include "ENIP.h"

namespace plugin
{
    namespace ICSNPP_ENIP
    {
        class Plugin : public zeek::plugin::Plugin
        {
            protected:
                virtual zeek::plugin::Configuration Configure();
        };

        extern Plugin plugin;
    }
}
