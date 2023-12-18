spicy_add_analyzer(
    NAME goose
    PACKAGE_NAME spicy-goose
    SOURCES goose.spicy goose.evt
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
