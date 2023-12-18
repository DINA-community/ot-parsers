spicy_add_analyzer(
    NAME MMS
    PACKAGE_NAME IEC61850_MMS
    SOURCES iec61850_mms.spicy iec61850_mms.evt zeek_mms.spicy mms_lib.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
