module sv;

# Define log stream
export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
	ts: time	&log;
        appid: int	&log;
        length: int	&log;
        smpCnt: int	&log;
        sv_id: string	&log;
    };
}

event sv::sv_packet(appid: int, length: int, sv_id: string, smpCnt: int) {
    # print "Detected a sampled value packet.";

    local rec: sv::Info = [$ts=network_time(), $appid=appid, $length=length, $smpCnt=smpCnt, $sv_id=sv_id];

    Log::write(sv::LOG, rec);
}

event zeek_init() &priority=5 {
        print "Initializing IEC 61850 SV analyzer";
        
        # Create the stream. This adds a default filter automatically.
        Log::create_stream(sv::LOG, [$columns=Info, $path="sv"]);
        
        if ( ! PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x88ba, PacketAnalyzer::ANALYZER_SPICY_SV)) {
            print "cannot register IEC 61850 SV analyzer for VLAN packets";
        } else {
            print "Registered IEC 61850 sv analyzer for VLAN";
        }

        if ( ! PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88ba, PacketAnalyzer::ANALYZER_SPICY_SV)) {
            print "cannot register IEC 61850 SV analyzer for Ethernet packets";
        } else {
            print "Registered IEC 61850 sv analyzer for ETHERNET";
        }
}
