# ICSNPP-ENIP

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Ethernet/IP and CIP.

## Overview

ICSNPP-ENIP is a Zeek plugin for parsing and logging fields within the Ethernet/IP protocol.

This plugin was developed to be fully customizable, so if you would like to drill down into specific BACnet packets and log certain variables, add the logging functionality to [scripts/icsnpp/enip/main.zeek](scripts/icsnpp/enip/main.zeek). The functions within [scripts/icsnpp/enip/main.zeek](scripts/icsnpp/enip/main.zeek) and [src/events.bif](src/events.bif) should prove to be a good guide on how to add new logging functionality.

This parser produces four log files. These log files are defined in [scripts/icsnpp/enip/main.zeek](scripts/icsnpp/enip/main.zeek).
* enip.log
* cip.log
* cip_io.log
* cip_identity.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-enip
```

If this package is installed from ZKG it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly you will see `ICSNPP::ENIP`.

If you have ZKG configured to load packages (see @load packages in quickstart guide), this plugin and scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/enip` to your command to run this plugin's scripts on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-enip.git
zeek -Cr icsnpp-enip/examples/enip_cip_example.pcap icsnpp/enip
```

### Manual Install

To install this package manually, clone this repository and run the configure and make commands as shown below.

```bash
git clone https://github.com/cisagov/icsnpp-enip.git
cd icsnpp-enip/
./configure
make
```

If these commands succeed, you will end up with a newly create build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::ENIP
```

Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::ENIP
```

To run this plugin in a site deployment you will need to add the line `@load icsnpp/enip` to your `site/local.zeek` file in order to load this plugin's scripts.

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/enip` to your command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-enip/examples/enip_cip_example.pcap icsnpp/enip
```

If you want to deploy this on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the Zeek_Enip.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/Zeek_Enip.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### ENIP Header Log (enip.log)

#### Overview

This log captures Ethernet/IP header information for every Ethernet/IP packet and logs it to **enip.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| uid               | string    | Unique ID for this connection                             |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| enip_command      | string    | Ethernet/IP command                                       |
| length            | count     | Length of ENIP data following header                      |
| session_handle    | string    | Session identifier                                        |
| enip_status       | string    | Ethernet/IP status code                                   |
| sender_context    | string    | Sender context                                            |
| options           | string    | Options flags                                             |

### CIP Header Log (cip.log)

#### Overview

This log captures CIP header information for every CIP packet and logs it to **cip.log**.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| cip_sequence_count    | count     | CIP sequence number                                       |
| direction             | string    | Request or response                                       |
| cip_service           | string    | CIP service type                                          |
| cip_status            | string    | CIP status code                                           |
| class_id              | string    | CIP request path - class ID                               |
| class_name            | string    | CIP request path - class name                             |
| instance_id           | string    | CIP request path - instance ID                            |
| attribute_id          | string    | CIP request path - attribute ID                           |
| data_id               | string    | CIP request path - data ID                                |
| other_id              | string    | CIP request path - other ID                               |

### CIP I/O Log (cip_io.log)

#### Overview

This log captures CIP I/O (input-output) data for every CIP IO packet and logs it to **cip_io.log**.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this connection                             |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)        |
| connection_id         | string    | Connection identifier                                     |
| sequence_number       | count     | Sequence number within connection                         |
| data_length           | count     | Length of data in io_data field                           |
| io_data               | string    | CIP IO data                                               |

### CIP Identity Log (cip_identity.log)

#### Overview

This log captures important variables for CIP_Identity objects and logs them to **cip_identity.log**.

#### Fields Captured

| Field                 | Type      | Description                                           |
| --------------------- |-----------|-------------------------------------------------------|
| ts                    | time      | Timestamp                                             |
| uid                   | string    | Unique ID for this connection                         |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)    |
| encapsulation_version | count     | Encapsulation protocol version supported              |
| socket_address        | addr      | Socket address IP address                             |
| socket_port           | count     | Socket address port number                            |
| vendor_id             | count     | Vendor ID                                             |
| vendor_name           | string    | Name of vendor                                        |
| device_type_id        | count     | Device type ID                                        |
| device_type_name      | string    | Name of device type                                   |
| product_code          | count     | Product code assigned to device                       |
| revision              | string    | Device revision (major.minor)                         |
| device_status         | string    | Current status of device                              |
| serial_number         | string    | Serial number of device                               |
| product_name          | string    | Human readable description of device                  |
| device_state          | string    | Current state of the device                           |

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP over IP](https://github.com/cisagov/icsnpp-bsap-ip)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
* [BSAP Serial->Ethernet](https://github.com/cisagov/icsnpp-bsap-serial)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over Serial->Ethernet
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilites of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilites of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a cutting edge research facility which is a constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2020 Battelle Energy Alliance, LLC

Licensed under the 3-Part BSD (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  https://opensource.org/licenses/BSD-3-Clause

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




Licensing
-----
This software is licensed under the terms you may find in the file named "LICENSE" in this directory.