# Spicy parser for HART-IP

HART-IP Parser - *HART Communications Protocol Specification*, HCF_SPEC-013, FCG TS20013

## Overview

This HART-IP parser is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the HART-IP protocol.

This parser produces the following log files, defined in [Scripts/main.zeek](scripts/main.zeek):

* `hartip.log`

For additional information on this log file, see the *Logging Capabilities* section below.

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
$ cd HART-IP
$ cmake . && make install
$ zeek -NN | grep ANALYZER_SPICY_HARTIP
```

If this package is installed from `zkg` it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_SPICY_HARTIP` under the list of `Zeek::Spicy` analyzers.

If you have `zkg` configured to load packages (see `@load packages` in the [`zkg` Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and scripts will automatically be loaded and ready to go.

## Logging Capabilities

### HART-IP Log (hartip.log)

This log summarizes the information on HART device, extracted through HART-IP frames transmitted over 5094/tcp. For further details on HART device identification, please refer *Command Summary Specification*, HCF_SPEC-099, FCG TS20099, Rev 10.1 [Table 15.](https://library.fieldcommgroup.org/20099/TS20099/10.1/#page=39).

#### Fields Captured

| Field         | Description                 |
|---------------|-----------------------------|
| command       | Transmitted HART-IP command |
| longTag       | Long Tag of HART device     |
| deviceID      | Device ID of HART device    |
| deviceType    | Type of HART device         |
| manufacturer  | Manufacturer of HART device |

### Others

The software was developed on behalf of the [BSI](https://www.bsi.bund.de) \(Federal Office for Information Security\) by the Industrial Cybersecurity research group at Fraunhofer [IOSB](https://www.iosb.fraunhofer.de/en.html).

## Licenses

Copyright (c) 2023 by DINA-Community. [See License](/LICENSE)

### Third party licenses

This projects uses code from [spicy-ldap](https://github.com/zeek/spicy-ldap/blob/main/analyzer/asn1.spicy) under the license provided in [asn1.spicy](/asn1.spicy) for all provided parsers.
