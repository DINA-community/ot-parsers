# IEC 61850-MMS parser

IEC 61850-8-1 (MMS) Parser - Communication networks and systems for power utility automation: Mappings to MMS (ISO 9506-1 and ISO 9506-2).

## Overview

IEC61850_MMS is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the IEC 61850-8-1 (MMS) protocol as presented in the standard IEC 61850-8-1 and ISO 9506-2, defining a transmission format for exchanging time-critical and non-time-critical data through local-area networks by mapping ACSI to MMS frames.

This parser produces the following log files, defined in [scripts/main.zeek](scripts/main.zeek):

* `mms.log`
* `mms_<servicename>.log`

For additional information on this log file, see the *Logging Capabilities* section below.

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
$ cd IEC61850/MMS
$ cmake . && make install
$ zeek -NN | grep ANALYZER_SPICY_IEC61850_MMS
```

If this package is installed from `zkg` it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_SPICY_IEC61850_MMS` under the list of `Zeek::Spicy` analyzers.

If you have `zkg` configured to load packages (see `@load packages` in the [`zkg` Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and scripts will automatically be loaded and ready to go.

## Protocol support and limitations

IEC61850_MMS has implemented and tested the following MMS PDU types according to the IEC 61850-8-1 / ISO 9506-2 standard (see ISO 9506-2: 7 MMS PDU):

| MMS PDU type           | Implemented    | Tested         |
| ---------------------- |----------------|----------------|
| INITIATE_REQUEST       | Yes            | Yes            |
| INITIATE_RESPONSE      | Yes            | Yes            |
| INITIATE_ERROR         | No             | No             |
| CONFIRMED_REQUEST      | Yes            | Yes            |
| CONFIRMED_RESPONSE     | Yes            | Yes            |
| CONFIRMED_ERROR        | No             | No             |
| UNCONFIRMED            | Yes            | Yes            |
| REJECT                 | No             | No             |
| CONCLUDE_REQUEST       | Yes            | Yes            |
| CONCLUDE_RESPONSE      | Yes            | Yes            |
| CONCLUDE_ERROR         | No             | No             |
| CANCEL_REQUEST         | No             | No             |
| CANCEL_RESPONSE        | No             | No             |
| CANCEL_ERROR           | No             | No             |

IEC61850_MMS has implemented and tested the following MMS request/response services according to the IEC 61850-8-1 / ISO 9506-2 standard (see IEC 61850-8-1: Table 1 - MMS objects and services in use within this SCSM):

| MMS request/response                 | Implemented    | Tested         |
| ------------------------------------ |----------------|----------------|
| STATUS                               | Yes            | Yes            |
| IDENTIFY                             | Yes            | No             |
| READ                                 | Yes            | Yes            |
| WRITE                                | Yes            | Yes            |
| DEFINE_NAMED_VARIABLE_LIST           | Yes            | No             |
| DELETE_NAMED_VARIABLE_LIST           | Yes            | Yes            |
| GET_NAME_LIST                        | Yes            | Yes            |
| GET_VARIABLE_ACCESS_ATTRIBUTE        | Yes            | Yes            |
| GET_NAMED_VARIABLE_LIST_ATTRIBUTES   | Yes (1)        | Yes            |
| GET_DOMAIN_ATTRIBUTES                | No             | No             |
| STORE_DOMAIN_CONTENTS                | No             | No             |
| READ_JOURNAL                         | No             | No             |
| INITIALIZE_JOURNAL                   | No             | No             |
| FILE_OPEN                            | Yes (1)        | Yes            |
| FILE_READ                            | Yes (1)        | Yes            |
| FILE_CLOSE                           | Yes (1)        | Yes            |
| FILE_DELETE                          | Yes            | No             |
| FILE_DIRECTORY                       | Yes            | Yes            |
| FILE_RENAME                          | Yes            | Yes            |
| OBTAIN_FILE                          | Yes            | Yes            |

*1: COTP reassembling/defragmentation not supported*

IEC61850_MMS has implemented and tested the following MMS unconfirmed services according to the IEC 61850-8-1 / ISO 9506-2 standard (see ISO 9506-2: 7.2 The Unconfirmed-PDU):

| MMS request/response   | Implemented    | Tested         |
| ---------------------- |----------------|----------------|
| INFORMATION_REPORT     | Yes            | Yes            |
| UNSOLICITED_STATUS     | No             | No             |
| EVENT_NOTIFICATION     | No             | No             |

IEC61850_MMS has implemented and tested the following MMS data object types according to the IEC 61850-8-1 / ISO 9506-2 standard (see ISO 9506-2: 14.4.2 Data & see IEC 61850-8.1: Annex F):

| MMS data object type   | Implemented    | Tested         |
| ---------------------- |----------------|----------------|
| DATA_ACCESS_ERROR      | Yes            | Yes            |
| STRUCTURE / SEQUENCE   | Yes            | Yes            |
| BOOLEAN                | Yes            | Yes            |
| BITSTRING              | Yes            | Yes            |
| SIGNED_INTEGER         | Yes            | Yes            |
| UNSIGNED_INTEGER       | Yes            | Yes            |
| FLOATING_POINT         | Yes (1)        | Yes            |
| OCTET_STRING           | Yes            | Yes            |
| VISIBLE_STRING         | Yes            | Yes            |
| GENERALIZED_TIME       | Yes            | No             |
| BINARY_TIME            | Yes (2)        | Yes            |
| BCD                    | Yes            | No             |
| OBJECT_ID              | Yes            | No             |
| MMS_STRING             | No             | No             |
| UTC_TIME               | Yes (3)        | Yes            |

*1: only supports IEEE 754 single or double precision format*

*2: implemented as relative day since January 1, 1984*

*3: implemented as the elapsed number of seconds since GMT midnight January 1, 1970*

## Logging Capabilities

### IEC 61850-8-1 (MMS) Log (MMS.log)

This log summarizes, by connection, IEC 61850-8-1 (MMS) frames transmitted over 102/tcp to `MMS.log`.

#### Fields Captured

This packages captures different characteristics from captured MMS packages. These characteristics can be used to be written into log files.
The Zeek script within this packages is an example for the logging capabilities.
The following is an example from the MMS identify service:

```
#fields	ts	uid	invokeID	vendor	modelName	revision
#types	time	string	int	string	string	string
1680702688.839633	C3eiCBGOLw3VtHfOj	1	-	-	-
1680702688.840122	C3eiCBGOLw3VtHfOj	1	ksc	Resist Server	1.5.1
```

For every mms package the following informations are written to the file mms.log.

| Field                  | Type           | Description                                          |
| ---------------------- |----------------|------------------------------------------------------| 
| ts                     | time           | Timestamp (network time)                             |
| uid                    | string         | Unique ID for this connection                        |
| mms_type               | enum           | MMS PDU type                                         |

To get an idea which fields can be wirtten to the log files have a look into the [Baseline](testing/Baseline/) folder.

#### Community ID

When used with Zeek 6.0.0 or above the communityID is also written to the conn.log

## Others

The software was developed on behalf of the [BSI](https://www.bsi.bund.de) \(Federal Office for Information Security\) by the electrical energy systems research group at Fraunhofer [Institute Advanced Systems Technology (AST)](https://www.iosb-ast.fraunhofer.de/en.html), a branch of Fraunhofer [ISOB](https://www.iosb.fraunhofer.de/en.html).

## Licenses

Copyright (c) 2023 by DINA-Community. [See License](/LICENSE)

### Third party licenses

This projects uses code from [spicy-ldap](https://github.com/zeek/spicy-ldap/blob/main/analyzer/asn1.spicy) under the license provided in [asn1.spicy](analyzer/asn1.spicy) for all provided parsers.
Additional for IEC 61850 MMS this project uses pcap files from [smartgridadsc/MMS-protocol-parser-for-Zeek-IDS](https://github.com/smartgridadsc/MMS-protocol-parser-for-Zeek-IDS).
