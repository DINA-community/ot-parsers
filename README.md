## Parser for OT-protocols

The goal is to develop and share parsers for OT-protocols in Zeek.\
There are several ways to contribute:

- Report errors (and fixes if possible)
- Provide useful enhancements or new parsers

In order to test parsers a PCAP containing the corresponding protocl is required.

## Overview

Industrial Control Systems protocol parsers plugins for [Zeek](https://docs.zeek.org/en/master/index.html), the network security monitoring tool, using [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).\
The following parsers are currently provided in this repository:

- [IEC 60870-5-104](/IEC60870-5-104)
- [IEC 61850](/IEC61850)
  - [IEC 61850 MMS](/IEC61850/MMS)
  - [IEC 61850-9-2 Sampled Values](/IEC61850/SV)
  - [IEC 61850-8-1 GOOSE](/IEC61850/GOOSE)
- [HART-IP](/HART-IP)

## Getting started

Navigate to the specific protocol folder to get a README about the implemented functions, metadata and how to deploy the parser.

## Important Notes

The parsers where developed within a IT/OT-Lab environment, under usage of real, captured network traffic.
Remember that your live plant and network traffic might differ from our tested cases, due to a lack of reliant network data, which might result in unexpected behavior of the parsers. In such a case we encourage you to participate in our cause by improving the given parsers.

## License

The software was developed on behalf of the [BSI](https://www.bsi.bund.de) \(Federal Office for Information Security\)

Copyright ©  2023-2024 by DINA-Community BSD 3-Clause License. [See License](/LICENSE)
