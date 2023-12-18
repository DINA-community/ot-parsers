module goose;

export {
    # Create an ID for our new stream. By convention, this is called "LOG".
    redef enum Log::ID += { LOG };

    # IECGoosePdu ::= SEQUENCE {
	# 	gocbRef 			[0] IMPLICIT 	VISIBLE-STRING,
	#	timeAllowedtoLive 		[1] IMPLICIT 	INTEGER,
	#	datSet 				[2] IMPLICIT 	VISIBLE-STRING,
	#   	goID 				[3] IMPLICIT 	VISIBLE-STRING OPTIONAL,
	#	T 				[4] IMPLICIT 	UtcTime,
	#	stNum 				[5] IMPLICIT 	INTEGER,
	#	sqNum 				[6] IMPLICIT 	INTEGER,
	#	simulation 			[7] IMPLICIT 	BOOLEAN DEFAULT FALSE,
	#	confRev 			[8] IMPLICIT 	INTEGER,
	#	ndsCom 				[9] IMPLICIT 	BOOLEAN DEFAULT FALSE,
	#	numDatSetEntries 		[10] IMPLICIT 	INTEGER,
	#	allData 			[11] IMPLICIT 	SEQUENCE OF Data,
	#	}

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time                &log;
        appid: int              &log;
        length: int             &log;
        gocbRef: string         &log;
        timeAllowedtoLive: int  &log;
        dataSet: string         &log;
        t: time                 &log;
        stNum: int              &log;
        sqNum: int              &log;
        simulation: bool        &log;
        confRev: int            &log;
        ndsCom: bool            &log;
        numDatSetEntries: int   &log;
    };
}


event zeek_init() &priority=20
{
    print "Initializing IEC 61850 GOOSE analyzer";

    # Create the stream. This adds a default filter automatically.
    Log::create_stream(goose::LOG, [$columns=Info, $path="goose"]);

    if ( ! PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x88b8, PacketAnalyzer::ANALYZER_SPICY_GOOSE) ) {
        print "Cannot register GOOSE analyzer";
    } else {
        print "Registered IEC 61850 goose analyzer for VLAN";
    }

    if ( ! PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88b8, PacketAnalyzer::ANALYZER_SPICY_GOOSE) ) {
        print "Cannot register GOOSE analyzer";
    } else {
        print "Registered IEC 61850 goose analyzer for ETHERNET";
    }
}

# event defined in goose.evt.
event goose::goose_packet(appid: int, length: int, gocbRef: string, timeAllowedtoLive:int, dataSet: string, t: time, stNum: int, sqNum: int, simulation: bool, confRev: int, ndsCom: bool, numDatSetEntries: int)
{
#    print "Detected a goose packet.";

    local rec: goose::Info = [$ts=network_time(), $appid=appid, $length=length, $gocbRef=gocbRef, $timeAllowedtoLive=timeAllowedtoLive, $dataSet=dataSet, $t=t, $stNum=stNum, $sqNum=sqNum, $simulation=simulation, $confRev=confRev, $ndsCom=ndsCom, $numDatSetEntries=numDatSetEntries];

    Log::write(goose::LOG, rec);
}
