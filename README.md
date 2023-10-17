# ICSNPP-ENIP

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Ethernet/IP and CIP.

## Overview

ICSNPP-ENIP is a Zeek plugin for parsing and logging fields within the Ethernet/IP protocol.

This plugin was developed to be fully customizable. To drill down into specific ENIP/CIP packets and log certain variables, users can add the logging functionality to [scripts/icsnpp/enip/main.zeek](scripts/icsnpp/enip/main.zeek). The functions within [scripts/icsnpp/enip/main.zeek](scripts/icsnpp/enip/main.zeek) and [src/events.bif](src/events.bif) are good guides for adding new logging functionality.

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

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly, users will see `ICSNPP::ENIP`.

If ZKG is configured to load packages (see @load packages in quickstart guide), this plugin and these scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add `icsnpp/enip` to the command to run this plugin's scripts on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-enip.git
zeek -Cr icsnpp-enip/tests/traces/enip_cip_example.pcap icsnpp/enip
```

### Manual Install

To install this package manually, clone this repository and run the configure and make commands as shown below.

```bash
git clone https://github.com/cisagov/icsnpp-enip.git
cd icsnpp-enip/
./configure
make
```

If these commands succeed, users will end up with a newly created build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::ENIP
```

Once users have tested the functionality locally and it appears to have compiled correctly, they can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::ENIP
```

To run this plugin in a site deployment, users will need to add the line `@load icsnpp/enip` to the `site/local.zeek` file to load this plugin's scripts.

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add `icsnpp/enip` to the command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-enip/tests/traces/enip_cip_example.pcap icsnpp/enip
```

If users want to deploy this on an already existing Zeek implementation and don't want to build the plugin on the machine, they can extract the Zeek_Enip.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/Zeek_Enip.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

It its default configuration, this parser will only log Ethernet/IP and CIP packets on ports 2222 and 44818. This decision was made due to the false positives generated when a signature-only based detection system was used.

If users know of Ethernet/IP and CIP traffic that operate on ports other than 2222 or 44818, there are two options:
* Allow signature detection on additional, known ports only:
  * In [scripts/icsnpp/enip/dpd.sig](scripts/icsnpp/enip/dpd.sig): add the known Ethernet/IP and CIP port numbers to the lines: `dst-port == 2222, 44818`
* Allow signature detection on all ports (may produce false positive):
  * In [scripts/icsnpp/enip/dpd.sig](scripts/icsnpp/enip/dpd.sig): replace the lines: `dst-port == 2222, 44818` with `dst-port >= 1024`

### ENIP Header Log (enip.log)

#### Overview

This log captures Ethernet/IP header information for every Ethernet/IP packet and logs it to **enip.log**.

#### Fields Captured

| Field             | Type      | Description                                                   |
| ----------------- |-----------|-------------------------------------------------------------- |
| ts                | time      | Timestamp                                                     |
| uid               | string    | Unique ID for this connection                                 |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig           | bool      | True if the packet is sent from the originator                |
| source_h          | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p          | port      | Source port (see *Source and Destination Fields*)             |
| destination_h     | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p     | port      | Destination port (see *Source and Destination Fields*)        |
| enip_command_code | string    | Ethernet/IP command code                                      |
| enip_command      | string    | Ethernet/IP command name                                      |
| length            | count     | Length of ENIP data following header                          |
| session_handle    | string    | Session identifier                                            |
| enip_status       | string    | Ethernet/IP status code                                       |
| sender_context    | string    | Sender context                                                |
| options           | string    | Options flags                                                 |

### CIP Header Log (cip.log)

#### Overview

This log captures CIP header information for every CIP packet and logs it to **cip.log**.

#### Fields Captured

| Field                     | Type      | Description                                                   |
| ------------------------- |-----------|-------------------------------------------------------------- |
| ts                        | time      | Timestamp                                                     |
| uid                       | string    | Unique ID for this connection                                 |
| id                        | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig                   | bool      | True if the packet is sent from the originator                |
| source_h                  | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p                  | port      | Source port (see *Source and Destination Fields*)             |
| destination_h             | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p             | port      | Destination port (see *Source and Destination Fields*)        |
| cip_sequence_count        | count     | CIP sequence number                                           |
| direction                 | string    | Request or response                                           |
| cip_service_code          | string    | CIP service code                                              |
| cip_service               | string    | CIP service name                                              |
| cip_status_code           | string    | CIP status code                                               |
| cip_status                | string    | CIP status name                                               |
| cip_extended_status_code  | string    | CIP extended status code                                      |
| cip_extended_status       | string    | CIP extended status name                                      |
| class_id                  | string    | CIP request path - class ID                                   |
| class_name                | string    | CIP request path - class name                                 |
| instance_id               | string    | CIP request path - instance ID                                |
| attribute_id              | string    | CIP request path - attribute ID                               |

### CIP I/O Log (cip_io.log)

#### Overview

This log captures CIP I/O (input-output) data for every CIP IO packet and logs it to **cip_io.log**.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|-------------------------------------------------------------- |
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this connection                                 |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination port (see *Source and Destination Fields*)        |
| connection_id         | string    | Connection identifier                                         |
| sequence_number       | count     | Sequence number within connection                             |
| data_length           | count     | Length of data in io_data field                               |
| io_data               | string    | CIP IO data (in hex)                                          |

### CIP Identity Log (cip_identity.log)

#### Overview

This log captures important variables for CIP_Identity objects and logs them to **cip_identity.log**.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|-------------------------------------------------------------- |
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this connection                                 |
| id                    | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination Port (see *Source and Destination Fields*)        |
| encapsulation_version | count     | Encapsulation protocol version supported                      |
| socket_address        | addr      | Socket address IP address                                     |
| socket_port           | count     | Socket address port number                                    |
| vendor_id             | count     | Vendor ID                                                     |
| vendor_name           | string    | Name of vendor                                                |
| device_type_id        | count     | Device type ID                                                |
| device_type_name      | string    | Name of device type                                           |
| product_code          | count     | Product code assigned to device                               |
| revision              | string    | Device revision (major.minor)                                 |
| device_status         | string    | Current status of device                                      |
| serial_number         | string    | Serial number of device                                       |
| product_name          | string    | Human readable description of device                          |
| device_state          | string    | Current state of the device                                   |

### Source and Destination Fields

#### Overview

Zeek's typical behavior is to focus on and log packets from the originator and not log packets from the responder. However, most ICS protocols contain useful information in the responses, so the ICSNPP parsers log both originator and responses packets. Zeek's default behavior, defined in its `id` struct, is to never switch these originator/responder roles which leads to inconsistencies and inaccuracies when looking at ICS traffic that logs responses.

The default Zeek `id` struct contains the following logged fields:
* id.orig_h (Original Originator/Source Host)
* id.orig_p (Original Originator/Source Port)
* id.resp_h (Original Responder/Destination Host)
* id.resp_p (Original Responder/Destination Port)

Additionally, the `is_orig` field is a boolean field that is set to T (True) when the id_orig fields are the true originators/source and F (False) when the id_resp fields are the true originators/source.

To not break existing platforms that utilize the default `id` struct and `is_orig` field functionality, the ICSNPP team has added four new fields to each log file instead of changing Zeek's default behavior. These four new fields provide the accurate information regarding source and destination IP addresses and ports:
* source_h (True Originator/Source Host)
* source_p (True Originator/Source Port)
* destination_h (True Responder/Destination Host)
* destination_p (True Responder/Destination Port)

The pseudocode below shows the relationship between the `id` struct, `is_orig` field, and the new `source` and `destination` fields.

```
if is_orig == True
    source_h == id.orig_h
    source_p == id.orig_p
    destination_h == id.resp_h
    destination_p == id.resp_p
if is_orig == False
    source_h == id.resp_h
    source_p == id.resp_p
    destination_h == id.orig_h
    destination_p == id.orig_p
```

#### Example

The table below shows an example of these fields in the log files. The first log in the table represents a Modbus request from 192.168.1.10 -> 192.168.1.200 and the second log represents a Modbus reply from 192.168.1.200 -> 192.168.1.10. As shown in the table below, the `id` structure lists both packets as having the same originator and responder, but the `source` and `destination` fields reflect the true source and destination of these packets.

| id.orig_h    | id.orig_p | id.resp_h     | id.resp_p | is_orig | source_h      | source_p | destination_h | destination_p |
| ------------ | --------- |---------------|-----------|---------|---------------|----------|---------------|-------------- |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | T       | 192.168.1.10  | 47785    | 192.168.1.200 | 502           |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | F       | 192.168.1.200 | 502      | 192.168.1.10  | 47785         |

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/icsnpp-bsap)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### License

Copyright 2023 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE.txt`](./LICENSE.txt)).
