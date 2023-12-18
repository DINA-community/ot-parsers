spicy_add_analyzer(
    NAME HARTIP
    PACKAGE_NAME spicy-hartip
    SOURCES hartip.spicy hartip.evt zeek_hartip.spicy hart_ip_enums.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
