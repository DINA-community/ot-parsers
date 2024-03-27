# IEC 61850-8-1 GOOSE Parser

IEC 61850 GOOSE (Generic Object Oriented System Event) is a communication protocol for industrial control systems.
It is based on IEEE 802.1Q VLAN or ethernet frames.

## Overview

This IEC 61850 goose parser is a Zeek plugin (written in spicy) for parsing and logging fields used by the Goose protocol.

This parser produces a the log file `goose.log`, defined in [scripts/main.zeek](scripts/main.zeek).

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
$ cd IEC61850/GOOSE
$ cmake . && make install
$ zeek -NN | grep ANALYZER_SPICY_GOOSE
```

If this package is installed from `zkg` it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_SPICY_GOOSE` under the list of `Zeek::Spicy` analyzers.

If you have `zkg` configured to load packages (see `@load packages` in the [`zkg` Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and scripts will automatically be loaded and ready to go.

## Logging Capabilities

### Goose Log (goose.log)

This parser evaluates ethernet or VLAN frames with an ethertype of `0x88b8`.

#### Fields Captured

The following data fileds (specified in IEC 61850-8-1 Annex A.3) are written to `goose.log`.

| Field           | Type   | Description                             | Reference |
|-----------------|--------|-----------------------------------------|-----------|
| ts              | time   | Timestamp (network time)                | - |
| appid           | int    | Application ID                          | IEC 61850-8-1 Annex C.2 PDU fields |
| length          | int    | Packet length                           | IEC 61850-8-1 Annex C.2 PDU fields |
| gocbRef         | string | GOOSE Control Block Reference           | IEC 61850-7-2 Chapter 18.2.1.2 |
| timeAllowedtoLive | int  | This field represents the time allowed for the GOOSE packet to live within the network. It specifies the maximum time duration for the packet to reach its destination before it expires or gets discarded.    | IEC 61850-8-1 Chapter 18.1.2.5.1 |
| dataSet         | string | Data set transmitted within this packet  | IEC 61850-8-1 Chapter 18.1.2.1 |
| t               | time   | Timestamp of data set                   | IEC 61850-7-2 Chapter 18.2.3.1 |
| stNum           | int    | The stNum field stands for "State Number" and represents the sequence number of the GOOSE message. It is used to ensure the correct ordering of messages and to detect any missing or out-of-order packets.        | IEC 61850-7-2 Chapter 18.2.3.1  |
| sqNum           | int    | The sqNum field stands for "Sequence Number" and represents the sequence number of the sample within the GOOSE message. It is used to identify and track individual samples within a sequence of messages. | IEC 61850-7-2 Chapter 18.2.3.1  |
| simulation      | bool   | Indicates if the data from packet comes from simulation     | IEC 61850-7-2 Chapter 18.2.3.1  |
| confRev         | int    | The confRev field stands for "Configuration Revision" and represents the revision number of the configuration associated with the GOOSE packet. It is used to ensure that the recipient has the correct configuration version to interpret the data correctly.            | IEC 61850-7-2 Chapter 18.2.3.1  |
| ndsCom          | bool   | The ndsCom field stands for "Non-Destructive Sample Comparison" and is a boolean value that indicates whether the GOOSE packet contains non-destructive samples. Non-destructive samples allow the receiving device to compare the received values with the previous values without causing any changes or disruptions in the system. | IEC 61850-7-2 Chapter 18.2.3.1  |
| numDatSetEntries | int   | Number of entries in the data set        | IEC 61850-8-1 Chapter 18.1.2.5.2 |

## Others

The software was developed on behalf of the [BSI](https://www.bsi.bund.de) \(Federal Office for Information Security\) by the electrical energy systems research group at Fraunhofer [Institute Advanced Systems Technology (AST)](https://www.iosb-ast.fraunhofer.de/en.html), a branch of Fraunhofer [ISOB](https://www.iosb.fraunhofer.de/en.html).

## Licenses

Copyright (c) 2023 by DINA-Community. [See License](/LICENSE)

### Third party licenses

This projects uses code from [spicy-ldap](https://github.com/zeek/spicy-ldap/blob/main/analyzer/asn1.spicy) under the license provided in [asn1.spicy](analyzer/asn1.spicy) for all provided parsers.
