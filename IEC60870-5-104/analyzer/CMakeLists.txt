spicy_add_analyzer(
    NAME IEC60870_5_104
    PACKAGE_NAME "IEC 60870-5-104"
    SOURCES iec60870_5_104.spicy iec60870_5_104.evt zeek_iec60870_5_104.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
