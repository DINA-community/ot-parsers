# IEC 61850-9-2 Sampled Values parser

IEC 61850-9-2 (SV) Parser - Communication networks and systems for process communication

## Overview

`sv.spicy` is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the IEC 61850-9-2 (SV) protocol.
This parser produces the following log files, defined in [scripts/main.zeek](analyzer/IEC61850/spicy-sv/scripts/main.zeek):

* `sv.log`

For additional information on this log file, see the *Logging Capabilities* section below.

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
$ cd IEC61850/SV
$ cmake . && make install
$ zeek -NN | grep ANALYZER_SPICY_SV
```

If this package is installed from `zkg` it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_SPICY_SV'` under the list of `Zeek::Spicy` analyzers.

If you have `zkg` configured to load packages (see `@load packages` in the [`zkg` Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and scripts will automatically be loaded and ready to go.

## Logging Capabilities

### Protocol support and limitations

This parser has implemented and tested the following svPDU objects according to the IEC 61850-9-2:

| ASDU object | Implemented | Tested | Description | Reference |
|-------------|-------------|--------|-------------|-----------|
| svID        | Yes         | Yes    | Identifier for Sampled Values. | IEC 61850-9-2 Chapter 8.5.2 |
| datset      | Yes*        | No     | Dataset transmitted within the packet. | IEC 61850-9-2 Chapter 8.5.2 |
| smpCnt      | Yes         | Yes    | Sample count, indicating the number of samples in the packet. | IEC 61850-9-2 Chapter 8.5.2 |
| confRev     | Yes         | Yes    | Configuration revision number. | IEC 61850-9-2 Chapter 8.5.2 |
| refrTm      | Yes*        | No     | Reference time for synchronization of samples. | IEC 61850-9-2 Chapter 8.5.2 |
| smpSynch    | Yes         | Yes    | Synchronization information for samples. | IEC 61850-9-2 Chapter 8.5.2 |
| smpRate     | Yes*        | No     | Sample rate, indicating the rate at which samples are taken. | IEC 61850-9-2 Chapter 8.5.2 |
| sample      | Yes*        | No     | Sample values captured within the packet. | IEC 61850-9-2 Chapter 8.5.2 |
| smpMod      | Yes*        | No     | Sample modification information. | IEC 61850-9-2 Chapter 8.5.2 |
| t           | Yes*        | No     | Timestamp of samples. | IEC 61850-9-2 Chapter 8.5.2 |

decoding as bytes implemented

### Paket Structure

IMPORTS Data FROM ISO-IEC-9506-2
```
IEC 61850-9-2 Specific Protocol ::= CHOICE {
  savPdu [APPLICATION 0] IMPLICIT SavPdu,
}
  
  
SavPdu ::= SEQUENCE {
  noASDU [0] IMPLICIT INTEGER(1..65535),
  security [1] ANY OPTIONAL, 
  asdu [2] IMPLICIT SEQUENCE OF ASDU
}

ASDU ::= SEQUENCE {
  svID [0] IMPLICIT VisibleString, 
  datset [1] IMPLICIT VisibleString OPTIONAL, 
  smpCnt [2] IMPLICIT OCTET STRING (SIZE(2)),
  confRev [3] IMPLICIT OCTET STRING (SIZE(4)),
  refrTm [4] IMPLICIT UtcTime OPTIONAL, 
  smpSynch [5] IMPLICIT OCTET STRING (SIZE(1)), 
  smpRate [6] IMPLICIT OCTET STRING (SIZE(2)) OPTIONAL,
  sample [7] IMPLICIT OCTET STRING (SIZE(n)),
  smpMod [8] IMPLICIT OCTET STRING (SIZE(2)) OPTIONAL
}
```

## Others

The software was developed on behalf of the [BSI](https://www.bsi.bund.de) \(Federal Office for Information Security\) by the electrical energy systems research group at Fraunhofer [Institute Advanced Systems Technology (AST)](https://www.iosb-ast.fraunhofer.de/en.html), a branch of Fraunhofer [ISOB](https://www.iosb.fraunhofer.de/en.html).

## Licenses

Copyright (c) 2023 by DINA-Community. [See License](/LICENSE)

### Third party licenses

This projects uses code from [spicy-ldap](https://github.com/zeek/spicy-ldap/blob/main/analyzer/asn1.spicy) under the license provided in [asn1.spicy](/asn1.spicy) for all provided parsers.
