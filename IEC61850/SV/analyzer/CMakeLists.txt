spicy_add_analyzer(
    NAME sv
    PACKAGE_NAME spicy-sv
    SOURCES sv.spicy sv.evt zeek_sv.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
