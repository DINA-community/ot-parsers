# Spicy parser for IEC 60870-5-104

IEC 60870-5-104 Parser - Network access for IEC 60870-5-101 using standard transport profiles.

## Overview

IEC60870_5_104 is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the IEC 60870-5-104 protocol as presented in the standard IEC 60870-5-104:2006 and IEC 60870-5-101:2003, defining a transmission format for sending and receiving SCADA data in power systems.

This parser produces the following log files, defined in [scripts/main.zeek](scripts/main.zeek):

* `104.log`

For additional information on this log file, see the *Logging Capabilities* section below.

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
cd IEC60870-5-104
cmake . && make install
zeek -NN | grep IEC60870_5_104
```

If this package is installed from `zkg` it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_SPICY_IEC608070_5_104` under the list of `Zeek::Spicy` analyzers.

If you have `zkg` configured to load packages (see `@load packages` in the [`zkg` Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and scripts will automatically be loaded and ready to go.

### Test

The script can tested immideatly with

```bash
$ zeek -r <pcapfile> iec60870_5_104.hlto ./scripts/main.zeek 
Initializing IEC 60870-5-104 analyzer
```

Now, in the folder lies an `conn.log`and the application log `iec_104.log`.

## Finalize installation

In order to including the parser into zeeks scripting land the folder has to copy into zeek. In the follwing example the installation path to zeek is`/opt/`

```bash
cd /opt/zeek/share/zeek/base/protocols
sudo mkdir iec60870-5-104/
cp <path_to_folder IEC60870-5-104>/scripts/* opt/zeek/share/zeek/base/protocols/iec60870-5-104/
cd /opt/zeek/share/zeek/base/
<texteditor> init-default.zeek
```

```bash
# <insert a command if you want here>
@load base/protocols/iec60870-5-104
```

Idealy, the line is inserted where the other base protocols are listed. An command can be included by using the # sign.

## Protocol support and limitations

This parser has implemented and tested the following message types according to the IEC 60870-5-104 standard (see IEC 60870-5-104: 6 Auswahl von ASDU aus IEC 60870-5-101 und zusätzliche ASDU):

| ASDU type (ASDU ID)    | Implemented    | Tested         |
| ---------------------- |----------------|----------------|
| M_SP_NA_1 (1)          | Fully          | Yes            |
| M_DP_NA_1 (3)          | Fully          | Yes            |
| M_ST_NA_1 (5)          | Fully          | Yes            |
| M_BO_NA_1 (7)          | Fully          | Limited        |
| M_ME_NA_1 (9)          | Fully          | Yes            |
| M_ME_NB_1 (11)         | Fully          | Yes            |
| M_ME_NC_1 (13)         | Fully          | Yes            |
| M_IT_NA_1 (15)         | Partially      | No             |
| M_PS_NA_1 (20)         | Partially      | No             |
| M_ME_ND_1 (21)         | Partially      | No             |
| M_SP_TB_1 (30)         | Fully          | Yes            |
| M_DP_TB_1 (31)         | Fully          | Yes            |
| M_ST_TB_1 (32)         | Fully          | Yes            |
| M_BO_TB_1 (33)         | Fully          | Limited        |
| M_ME_TD_1 (34)         | Fully          | Yes            |
| M_ME_TE_1 (35)         | Fully          | Yes            |
| M_ME_TF_1 (36)         | Fully          | Yes            |
| M_IT_TB_1 (37)         | Partially      | No             |
| M_EP_TD_1 (38)         | Partially      | No             |
| M_EP_TE_1 (39)         | Partially      | No             |
| M_EP_TF_1 (40)         | Partially      | No             |
| C_SC_NA_1 (45)         | Fully          | Limited        |
| C_DC_NA_1 (46)         | Fully          | Limited        |
| C_RC_NA_1 (47)         | Fully          | Limited        |
| C_SE_NA_1 (48)         | Partially      | No             |
| C_SE_NB_1 (49)         | Fully          | Limited        |
| C_SE_NC_1 (50)         | Partially      | No             |
| C_BO_NA_1 (51)         | Fully          | Limited        |
| C_SC_TA_1 (58)         | Partially      | No             |
| C_DC_TA_1 (59)         | Partially      | No             |
| C_RC_TA_1 (60)         | Partially      | No             |
| C_SE_TA_1 (61)         | Partially      | No             |
| C_SE_TB_1 (62)         | Partially      | No             |
| C_SE_TC_1 (63)         | Partially      | No             |
| C_BO_TA_1 (64)         | Fully          | Limited        |
| M_EI_NA_1 (70)         | Fully          | Yes            |
| C_IC_NA_1 (100)        | Fully          | Yes            |
| C_CI_NA_1 (101)        | Fully          | Yes            |
| C_RD_NA_1 (102)        | Fully          | Limited        |
| C_CS_NA_1 (103)        | Partially      | No             |
| C_TS_NA_1 (104)        | Partially      | No             |
| C_RP_NA_1 (105)        | Fully          | Limited*       |
| C_CD_NA_1 (106)        | Partially      | No             |
| C_TS_TA_1 (107)        | Partially      | No             |
| P_ME_NA_1 (110)        | Partially      | No             |
| P_ME_NB_1 (111)        | Partially      | No             |
| P_ME_NC_1 (112)        | Partially      | No             |
| P_AC_NA_1 (113)        | Partially      | No             |
| F_FR_NA_1 (120)        | Partially      | No             |
| F_SR_NA_1 (121)        | Partially      | No             |
| F_SC_NA_1 (122)        | Partially      | No             |
| F_LS_NA_1 (123)        | Partially      | No             |
| F_AF_NA_1 (124)        | Partially      | No             |
| F_SG_NA_1 (125)        | Partially      | No             |
| F_DR_TA_1 (126)        | Partially      | No             |

Legend for column *Implemented*:\

* Fully  &emsp; &nbsp; events are triggered
* Partially &nbsp;events not given

Legend for column *Test*:\
The parser was tested

* Limited  &nbsp;  with fabricated/edited network traffic
* Yes &emsp;&emsp; with authenticate network traffic
* No  &nbsp; &emsp;&emsp; with None (no events implemented)

## Logging Capabilities

### IEC 60870-5-104 Log (104.log)

This log summarizes, by connection, IEC 60870-5-104 frames transmitted over 2404/tcp to `104.log`.

#### Fields Captured

| Field                  | Type           | Description                                          |
| ---------------------- |----------------|------------------------------------------------------|
| ts                     | time           | Timestamp (network time)                             |
| uid                    | string         | Unique ID for this connection                        |
| asdu_length            | int            | Length of the application service data unit (ASDU)   |
| apdu_type              | string         | Type of the application protocol data unit (APDU)    |
| send_num               | int            | Sending number                                       |
| rec_num                | int            | Receiving number                                     |
| ioa_num                | int            | Number of information objects                        |
| cot                    | int            | Cause of transmission (COT)                          |
| asdu_type              | int            | Type of ASDU                                         |
| origin                 | int            | Originator address                                   |
| asdu_address           | int            | Address of the ASDU                                  |
| confirm                | bool           | Confirmation type                                    |
| bsi                    | vector\<string> | Binary state information                             |
| dco                    | vector\<string> | Double command                                       |
| shortpulse             | vector\<bool>   | Qualifier for the commands                           |
| longpulse              | vector\<bool>   | Qualifier for the commands                           |
| persistent             | vector\<bool>   | Qualifier for the commands                           |
| execute                | vector\<bool>   | Select/execute state \<0>                            |
| select                 | vector\<bool>   | Select/execute state \<1>                            |
| rco                    | vector\<string> | Regulating step command                              |
| increment              | vector\<bool>   | Status information of the step command               |
| decrement              | vector\<bool>   | Status information of the step command               |
| notallowed0            | vector\<bool>   | Status information of the step command               |
| notallowed3            | vector\<bool>   | Status information of the step command               |
| sco                    | vector\<string> | Single command                                       |
| ioa                    | vector\<int>    | Information object addresses (IOA)                   |
| state_on               | vector\<bool>   | Single or double point information: STATE_ON         |
| state_off              | vector\<bool>   | Single or double point information: STATE_OFF        |
| indeterminate0         | vector\<bool>   | Single or double point information: INDETERMINATE_0  |
| indeterminate3         | vector\<bool>   | Single or double point information: INDETERMINATE_3  |
| vti_value              | vector\<int>    | Step position information value                      |
| vti_transient          | vector\<bool>   | Step position information transient flag             |
| nva                    | vector\<int>    | Normalized value                                     |
| sva                    | vector\<int>    | Scaled value                                         |
| shortfloat             | vector\<double> | Short floating point value                           |
| blocked                | vector\<bool>   | Quality information: BLOCKED                         |
| substituted            | vector\<bool>   | Quality information: SUBSTITUTED                     |
| topical                | vector\<bool>   | Quality information: TOPICAL                         |
| valid                  | vector\<bool>   | Quality information: VALID                           |
| overflow               | vector\<bool>   | Quality information: OVERFLOW                        |
| localpoweron           | vector\<bool>   | Cause of initialization: LOCAL_POWER_ON              |
| localmanualreset       | vector\<bool>   | Cause of initialization: LOCAL_MANUAL_RESET          |
| remotereset            | vector\<bool>   | Cause of initialization: REMOTE_RESET                |
| unchangedparams        | vector\<bool>   | Cause of initialization: UNCHANGED_PARAMS            |
| stationinterrogation   | vector\<bool>   | Interrogation command: STATION_INTERROGATION         |
| qualifierinterrogation | vector\<int>    | Qualifier of interrogation command                   |
| nocounter              | vector\<bool>   | Counter of interrogation command: NO_COUNTER         |
| group1counter          | vector\<bool>   | Counter of interrogation command: GROUP1_COUNTER     |
| group2counter          | vector\<bool>   | Counter of interrogation command: GROUP2_COUNTER     |
| group3counter          | vector\<bool>   | Counter of interrogation command: GROUP3_COUNTER     |
| group4counter          | vector\<bool>   | Counter of interrogation command: GROUP4_COUNTER     |
| generalcounter         | vector\<bool>   | Counter of interrogation command: GENERAL_COUNTER    |
| readonly               | vector\<bool>   | Counter of interrogation command: READ_ONLY          |
| freeze                 | vector\<bool>   | Counter of interrogation command: FREEZE             |
| reset                  | vector\<bool>   | Counter of interrogation command: RESET              |
| freezeandreset         | vector\<bool>   | Counter of interrogation command: FREEZE_AND_RESET   |
| cp56_minutes           | vector\<int>    | CP56 time object: minutes 0-59                       |
| cp56_hours             | vector\<int>    | CP56 time object: hours 0-59                         |
| cp56_day               | vector\<int>    | CP56 time object: day 1-31                           |
| cp56_dow               | vector\<int>    | CP56 time object: day of the week 1-7                |
| cp56_month             | vector\<int>    | CP56 time object: day of the week 1-12               |
| cp56_year              | vector\<int>    | CP56 time object: year 0-9999                        |
| cp56_su                | vector\<bool>   | CP56 time object: summer time                        |
| cp56_valid             | vector\<bool>   | CP56 time object: validity                           |
| qrp                    | vector\<string> | Qualifier of reset process                           |

#### Community ID

When used with Zeek 6.0.0 or above the communityID is also written to the conn.log

## Others

The software was developed on behalf of the [BSI](https://www.bsi.bund.de) \(Federal Office for Information Security\) by the electrical energy systems research group at Fraunhofer [Institute Advanced Systems Technology (AST)](https://www.iosb-ast.fraunhofer.de/en.html), a branch of Fraunhofer [ISOB](https://www.iosb.fraunhofer.de/en.html).

## Licenses

Copyright (c) 2023 by DINA-Community. [See License](/LICENSE)

### Third party licenses

This projects uses code from [spicy-ldap](https://github.com/zeek/spicy-ldap/blob/main/analyzer/asn1.spicy) under the license provided in [asn1.spicy](/asn1.spicy) for all provided parsers.
