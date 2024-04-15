#module PacketAnalyzer::SPICY_104;
module iec60870_5_104;
@if ( Version::number >= 60000 )
@load policy/protocols/conn/community-id-logging
@endif

# Define log stream
export {

	# Create an ID for our new stream. By convention, this is called "LOG".
    redef enum Log::ID += { LOG };

	# Define 104 record
    type Info: record {
		ts: time &log &optional;
		uid: string &log &optional;
		asdu_length: int &log &optional;
		apdu_type: string &log &optional;
		send_num: int &log &optional;
		rec_num: int &log &optional;
		ioa_num: int &log &optional;
		cot: int &log &optional;
		asdu_type: int &log &optional;
		origin: int &log &optional;
		asdu_address: int &log &optional;
		confirm: bool &log &optional;
		ioa: vector of int &log &optional;
		state_on: vector of bool &log &optional;
		state_off: vector of bool &log &optional;
		indeterminate0: vector of bool &log &optional;
		indeterminate3: vector of bool &log &optional;
		vti_value: vector of int &log &optional;
		vti_transient: vector of bool &log &optional;

		bsi: vector of string &log &optional;

		dco: vector of string &log &optional;
		shortpulse: vector of bool &log &optional;
		longpulse: vector of bool &log &optional;
		persistent: vector of bool &log &optional;
		execute: vector of bool &log &optional;
		select: vector of bool &log &optional;

		rco: vector of string &log &optional;
		increment: vector of bool &log &optional;
		decrement: vector of bool &log &optional;
		notallowed0: vector of bool &log &optional;
		notallowed3: vector of bool &log &optional;

		sco: vector of string &log &optional;

		nva: vector of int &log &optional;
		sva: vector of int &log &optional;
		shortfloat: vector of double &log &optional;
		blocked: vector of bool &log &optional;
		substituted: vector of bool &log &optional;
		topical: vector of bool &log &optional;
		valid: vector of bool &log &optional;
		overflow: vector of bool &log &optional;
		localpoweron: vector of bool &log &optional;
		localmanualreset: vector of bool &log &optional;
		remotereset: vector of bool &log &optional;
		unchangedparams: vector of bool &log &optional;
		stationinterrogation: vector of bool &log &optional;
		qualifierinterrogation: vector of int &log &optional;
		nocounter: vector of bool &log &optional;
		group1counter: vector of bool &log &optional;
		group2counter: vector of bool &log &optional;
		group3counter: vector of bool &log &optional;
		group4counter: vector of bool &log &optional;
		generalcounter: vector of bool &log &optional;
		readonly: vector of bool &log &optional;
		freeze: vector of bool &log &optional;
		reset: vector of bool &log &optional;
		freezeandreset: vector of bool &log &optional;
		cp56_minutes: vector of int &log &optional;
		cp56_hours: vector of int &log &optional;
		cp56_day: vector of int &log &optional;
		cp56_dow: vector of int &log &optional;
		cp56_month: vector of int &log &optional;
		cp56_year: vector of int &log &optional;
		cp56_su: vector of bool &log &optional;
		cp56_valid: vector of bool &log &optional;

		read_cmd: vector of bool &log &optional;

		qrp: vector of string &log &optional;
    };

}

event zeek_init() &priority=5
    {
        print "Initializing IEC 60870-5-104 analyzer";

        # Create the stream. This adds a default filter automatically.
		Log::create_stream(iec60870_5_104::LOG, [$columns = Info, $path="iec_104"]);

	}

# Update connection object
redef record connection += {
	rec: Info &optional;
};

# Initialize record
function init_rec(c: connection) {
	local rec: Info = [];
	c$rec = rec;
}

# Write record to log stream and reinitialize
function write_rec(c: connection){
	Log::write(iec60870_5_104::LOG, c$rec);
	init_rec(c);
}

# Set cause of initialization (COI)
function set_coi(c: connection){
	c$rec$localpoweron = vector();
	c$rec$localmanualreset = vector();
	c$rec$remotereset = vector();
	c$rec$unchangedparams = vector();
}

# Set CP56 time
function set_cp56(c: connection){
	c$rec$cp56_minutes = vector();
	c$rec$cp56_hours = vector();
	c$rec$cp56_day = vector();
	c$rec$cp56_dow = vector();
	c$rec$cp56_month = vector();
	c$rec$cp56_year = vector();
	c$rec$cp56_su = vector();
	c$rec$cp56_valid = vector();
}

# Set double-point information with qualifier (DIQ)
function set_diq(c: connection){
	c$rec$state_on = vector();
	c$rec$state_off = vector();
	c$rec$indeterminate0 = vector();
	c$rec$indeterminate3 = vector();
	c$rec$blocked = vector();
	c$rec$substituted = vector();
	c$rec$topical = vector();
	c$rec$valid = vector();
}

# Set single command (SCO)
function set_sco(c: connection){
	c$rec$state_on = vector();
	c$rec$state_off = vector();
	c$rec$shortpulse = vector();
	c$rec$longpulse = vector();
	c$rec$persistent = vector();
	c$rec$execute = vector();
	c$rec$select = vector();
}

# Set double command (DCO)
function set_dco(c: connection){
	c$rec$state_on = vector();
	c$rec$state_off = vector();
	c$rec$indeterminate0 = vector();
	c$rec$indeterminate3 = vector();
	c$rec$shortpulse = vector();
	c$rec$longpulse = vector();
	c$rec$persistent = vector();
	c$rec$execute = vector();
	c$rec$select = vector();
}

# Set regulating step command (RCO)
function set_rco(c: connection){
	c$rec$increment = vector();
	c$rec$decrement = vector();
	c$rec$notallowed0 = vector();
	c$rec$notallowed3 = vector();
	c$rec$shortpulse = vector();
	c$rec$longpulse = vector();
	c$rec$persistent = vector();
	c$rec$execute = vector();
	c$rec$select = vector();
}

# Set Qualifier of set-point command (QOS)
function set_qos(c: connection){
	c$rec$execute = vector();
	c$rec$select = vector();
}

# Set Bit string of 32 bit (BSI)
function set_bsi(c: connection){
	c$rec$bsi = vector();
}

# Set normalized value (NVA)
function set_nva(c: connection){
	c$rec$nva = vector();
}

# Set qualifier of counter interrogation (QCC)
function set_qcc(c: connection){
	c$rec$nocounter = vector();
	c$rec$group1counter = vector();
	c$rec$group2counter = vector();
	c$rec$group3counter = vector();
	c$rec$group4counter = vector();
	c$rec$generalcounter = vector();
	c$rec$readonly = vector();
	c$rec$freeze = vector();
	c$rec$reset = vector();
	c$rec$freezeandreset = vector();
}

# Set quality descriptor (QDS)
function set_qds(c: connection){
	c$rec$overflow = vector();
	c$rec$blocked = vector();
	c$rec$substituted = vector();
	c$rec$topical = vector();
	c$rec$valid = vector();
}

# Seq qualifier of interrogation (QOI)
function set_qoi(c: connection){
	c$rec$stationinterrogation = vector();
	c$rec$qualifierinterrogation = vector();
}

# Set short float
function set_shortfloat(c: connection){
	c$rec$shortfloat = vector();
}

# Set single-point information with qualifier (DIQ)
function set_siq(c: connection){
	c$rec$state_on = vector();
	c$rec$state_off = vector();
	c$rec$blocked = vector();
	c$rec$substituted = vector();
	c$rec$topical = vector();
	c$rec$valid = vector();
}

# Set scaled value (SVA)
function set_sva(c: connection){
	c$rec$sva = vector();
}

# Set value with transient state indication (VTI)
function set_vit(c: connection){
	c$rec$vti_value = vector();
	c$rec$vti_transient = vector();
}

# Set value of read_cmd for C_RD_NA_1
function set_read_cmd(c: connection){
	c$rec$read_cmd = vector();
}

# Set Qualifier of reset process (QRP)
function set_qrp(c: connection){
	c$rec$qrp = vector();
}

# APDU event
event iec60870_5_104::apdu(c: connection, asdu_length: int, apdu_type: string, send_num: int, rec_num: int){
	if ( !c?$rec ){
		init_rec(c);
	}
	c$rec$ts = network_time();
	c$rec$uid = c$uid;
	c$rec$asdu_length = asdu_length;
	c$rec$apdu_type = apdu_type;
	if ( apdu_type == "I" ){
		c$rec$send_num = send_num;
		c$rec$rec_num = rec_num;
	}
	write_rec(c);
}

# ASDU event
event iec60870_5_104::asdu(c: connection, ioa_num: int, cot: int, asdu_type: int, origin: int, asdu_address: int, con: bool){
	if ( !c?$rec ){
		init_rec(c);
	}
	c$rec$ioa_num = ioa_num;
	c$rec$cot = cot;
	c$rec$asdu_type = asdu_type;
	c$rec$origin = origin;
	c$rec$asdu_address = asdu_address;
	c$rec$confirm = con;
}

# Information object event
event iec60870_5_104::io(c: connection, ioa: int){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
		}
	}
	c$rec$ioa += ioa;
}

# Single-point information without time tag event (M_SP_NA_1)
event iec60870_5_104::M_SP_NA_1(c: connection, state_on: bool, state_off: bool, blocked: bool, substituted: bool, topical: bool, valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_siq(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_siq(c);
		}
	}
	c$rec$state_on += state_on;
	c$rec$state_off += state_off;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
}

# Double-point information without time tag event (M_DP_NA_1)
event iec60870_5_104::M_DP_NA_1(c: connection, state_on: bool, state_off: bool, indeterminate0: bool, indeterminate3: bool, blocked: bool, substituted: bool, topical: bool, valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_diq(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_diq(c);
		}
	}
	c$rec$state_on += state_on;
	c$rec$state_off += state_off;
	c$rec$indeterminate0 += indeterminate0;
	c$rec$indeterminate3 += indeterminate3;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
}

# Step position information without time tag event (M_ST_NA_1)
event iec60870_5_104::M_ST_NA_1(c: connection, value: int, transient: bool, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_vit(c);
		set_qds(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_vit(c);
			set_qds(c);
		}
	}
	c$rec$vti_value += value;
	c$rec$vti_transient += transient;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
}

# Binary state information with quality descriptor (M_BO_NA_1)
event iec60870_5_104::M_BO_NA_1(c: connection, bsi: string, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_bsi(c);
		set_qds(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_bsi(c);
			set_qds(c);
		}
	}
	c$rec$bsi += bsi;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
}

# Normalized value without time tag event (M_ME_NA_1)
event iec60870_5_104::M_ME_NA_1(c: connection, nva: int, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_nva(c);
		set_qds(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_nva(c);
			set_qds(c);
		}
	}
	c$rec$nva += nva;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
}

# Scaled value without time tag event (M_ME_NB_1)
event iec60870_5_104::M_ME_NB_1(c: connection, sva: int, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_sva(c);
		set_qds(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_sva(c);
			set_qds(c);
		}
	}
	c$rec$sva += sva;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
}

# Short float value without time tag event (M_ME_NC_1)
event iec60870_5_104::M_ME_NC_1(c: connection, shortfloat: double, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_shortfloat(c);
		set_qds(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_shortfloat(c);
			set_qds(c);
		}
	}
	c$rec$shortfloat += shortfloat;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
}

# Single-point information with CP56Time2a time tag event (M_SP_TB_1)
event iec60870_5_104::M_SP_TB_1(c: connection, state_on: bool, state_off: bool, blocked: bool, substituted: bool, topical: bool, valid: bool, cp56_minutes: int, cp56_hours: int, cp56_day: int, cp56_dow: int, cp56_month: int, cp56_year: int, cp56_su: bool, cp56_valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_siq(c);
		set_cp56(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_siq(c);
			set_cp56(c);
		}
	}
	c$rec$state_on += state_on;
	c$rec$state_off += state_off;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
	c$rec$cp56_minutes += cp56_minutes;
	c$rec$cp56_hours += cp56_hours;
	c$rec$cp56_day += cp56_day;
	c$rec$cp56_dow += cp56_dow;
	c$rec$cp56_month += cp56_month;
	c$rec$cp56_year += cp56_year;
	c$rec$cp56_su += cp56_su;
	c$rec$cp56_valid += cp56_valid;
}

# Double-point information with CP56Time2a time tag event (M_DP_TB_1)
event iec60870_5_104::M_DP_TB_1(c: connection, state_on: bool, state_off: bool, indeterminate0: bool, indeterminate3: bool, blocked: bool, substituted: bool, topical: bool, valid: bool, cp56_minutes: int, cp56_hours: int, cp56_day: int, cp56_dow: int, cp56_month: int, cp56_year: int, cp56_su: bool, cp56_valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_diq(c);
		set_cp56(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_diq(c);
			set_cp56(c);
		}
	}
	c$rec$state_on += state_on;
	c$rec$state_off += state_off;
	c$rec$indeterminate0 += indeterminate0;
	c$rec$indeterminate3 += indeterminate3;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
	c$rec$cp56_minutes += cp56_minutes;
	c$rec$cp56_hours += cp56_hours;
	c$rec$cp56_day += cp56_day;
	c$rec$cp56_dow += cp56_dow;
	c$rec$cp56_month += cp56_month;
	c$rec$cp56_year += cp56_year;
	c$rec$cp56_su += cp56_su;
	c$rec$cp56_valid += cp56_valid;
}

# Step position information with CP56Time2a time tag event (M_ST_TB_1)
event iec60870_5_104::M_ST_TB_1(c: connection, value: int, transient: bool, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool, cp56_minutes: int, cp56_hours: int, cp56_day: int, cp56_dow: int, cp56_month: int, cp56_year: int, cp56_su: bool, cp56_valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_vit(c);
		set_qds(c);
		set_cp56(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_vit(c);
			set_qds(c);
			set_cp56(c);
		}
	}
	c$rec$vti_value += value;
	c$rec$vti_transient += transient;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
	c$rec$cp56_minutes += cp56_minutes;
	c$rec$cp56_hours += cp56_hours;
	c$rec$cp56_day += cp56_day;
	c$rec$cp56_dow += cp56_dow;
	c$rec$cp56_month += cp56_month;
	c$rec$cp56_year += cp56_year;
	c$rec$cp56_su += cp56_su;
	c$rec$cp56_valid += cp56_valid;
}

# Binary state information with CP56Time2a time tag event (M_BO_TB_1)
event iec60870_5_104::M_BO_TB_1(c: connection, bsi: string, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool, cp56_minutes: int, cp56_hours: int, cp56_day: int, cp56_dow: int, cp56_month: int, cp56_year: int, cp56_su: bool, cp56_valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_bsi(c);
		set_qds(c);
		set_cp56(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_bsi(c);
			set_qds(c);
			set_cp56(c);
		}
	}
	c$rec$bsi += bsi;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
	c$rec$cp56_minutes += cp56_minutes;
	c$rec$cp56_hours += cp56_hours;
	c$rec$cp56_day += cp56_day;
	c$rec$cp56_dow += cp56_dow;
	c$rec$cp56_month += cp56_month;
	c$rec$cp56_year += cp56_year;
	c$rec$cp56_su += cp56_su;
	c$rec$cp56_valid += cp56_valid;
}

# Normalized value with CP56Time2a time tag event (M_ME_TD_1)
event iec60870_5_104::M_ME_TD_1(c: connection, nva: int, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool, cp56_minutes: int, cp56_hours: int, cp56_day: int, cp56_dow: int, cp56_month: int, cp56_year: int, cp56_su: bool, cp56_valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_nva(c);
		set_qds(c);
		set_cp56(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_nva(c);
			set_qds(c);
			set_cp56(c);
		}
	}
	c$rec$nva += nva;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
	c$rec$cp56_minutes += cp56_minutes;
	c$rec$cp56_hours += cp56_hours;
	c$rec$cp56_day += cp56_day;
	c$rec$cp56_dow += cp56_dow;
	c$rec$cp56_month += cp56_month;
	c$rec$cp56_year += cp56_year;
	c$rec$cp56_su += cp56_su;
	c$rec$cp56_valid += cp56_valid;
}

# Scaled value with CP56Time2a time tag event (M_ME_TE_1)
event iec60870_5_104::M_ME_TE_1(c: connection, sva: int, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool, cp56_minutes: int, cp56_hours: int, cp56_day: int, cp56_dow: int, cp56_month: int, cp56_year: int, cp56_su: bool, cp56_valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_sva(c);
		set_qds(c);
		set_cp56(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_sva(c);
			set_qds(c);
			set_cp56(c);
		}
	}
	c$rec$sva += sva;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
	c$rec$cp56_minutes += cp56_minutes;
	c$rec$cp56_hours += cp56_hours;
	c$rec$cp56_day += cp56_day;
	c$rec$cp56_dow += cp56_dow;
	c$rec$cp56_month += cp56_month;
	c$rec$cp56_year += cp56_year;
	c$rec$cp56_su += cp56_su;
	c$rec$cp56_valid += cp56_valid;
}

# Short float value with CP56Time2a time tag event (M_ME_TF_1)
event iec60870_5_104::M_ME_TF_1(c: connection, shortfloat: double, overflow: bool, blocked: bool, substituted: bool, topical: bool, valid: bool, cp56_minutes: int, cp56_hours: int, cp56_day: int, cp56_dow: int, cp56_month: int, cp56_year: int, cp56_su: bool, cp56_valid: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_shortfloat(c);
		set_qds(c);
		set_cp56(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_shortfloat(c);
			set_qds(c);
			set_cp56(c);
		}
	}
	c$rec$shortfloat += shortfloat;
	c$rec$overflow += overflow;
	c$rec$blocked += blocked;
	c$rec$substituted += substituted;
	c$rec$topical += topical;
	c$rec$valid += valid;
	c$rec$cp56_minutes += cp56_minutes;
	c$rec$cp56_hours += cp56_hours;
	c$rec$cp56_day += cp56_day;
	c$rec$cp56_dow += cp56_dow;
	c$rec$cp56_month += cp56_month;
	c$rec$cp56_year += cp56_year;
	c$rec$cp56_su += cp56_su;
	c$rec$cp56_valid += cp56_valid;
}

# Single command
event iec60870_5_104::C_SC_NA_1(c: connection, state_on: bool, state_off: bool, shortpulse: bool, longpulse: bool, persistent: bool, execute: bool, select: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_sco(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_sco(c);
		}
	}
	c$rec$state_on += state_on;
	c$rec$state_off += state_off;
	c$rec$shortpulse += shortpulse;
	c$rec$longpulse += longpulse;
	c$rec$persistent += persistent;
	c$rec$execute += execute;
	c$rec$select += select;
}

# Double command
event iec60870_5_104::C_DC_NA_1(c: connection, state_on: bool, state_off: bool, indeterminate0: bool, indeterminate3: bool, shortpulse: bool, longpulse: bool, persistent: bool, execute: bool, select: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_dco(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_dco(c);
		}
	}
	c$rec$state_on += state_on;
	c$rec$state_off += state_off;
	c$rec$indeterminate0 += indeterminate0;
	c$rec$indeterminate3 += indeterminate3;
	c$rec$shortpulse += shortpulse;
	c$rec$longpulse += longpulse;
	c$rec$persistent += persistent;
	c$rec$execute += execute;
	c$rec$select += select;
}

# Regulating step command
event iec60870_5_104::C_RC_NA_1(c: connection, increment: bool, decrement: bool, notallowed0: bool, notallowed3: bool, shortpulse: bool, longpulse: bool, persistent: bool, execute: bool, select: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_rco(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_rco(c);
		}
	}
	c$rec$increment += increment;
	c$rec$decrement += decrement;
	c$rec$notallowed0 += notallowed0;
	c$rec$notallowed3 += notallowed3;
	c$rec$shortpulse += shortpulse;
	c$rec$longpulse += longpulse;
	c$rec$persistent += persistent;
	c$rec$execute += execute;
	c$rec$select += select;
}

# Setpoint command, scaled value
event iec60870_5_104::C_SE_NB_1(c: connection, sva: int, execute: bool, select: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_sva(c);
		set_qos(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_sva(c);
			set_qos(c);
		}
	}
	
	c$rec$sva += sva;
	c$rec$execute += execute;
	c$rec$select += select;
}

# Binary state information (C_BO_NA_1)
event iec60870_5_104::C_BO_NA_1(c: connection, bsi: string){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_bsi(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_bsi(c);
		}
	}
	c$rec$bsi += bsi;
}

# End of initialization event (M_EI_NA_1)
event iec60870_5_104::M_EI_NA_1(c: connection, localpoweron: bool, localmanualreset: bool, remotereset: bool, unchangedparams: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_coi(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_coi(c);
		}
	}
	c$rec$localpoweron += localpoweron;
	c$rec$localmanualreset += localmanualreset;
	c$rec$remotereset += remotereset;
	c$rec$unchangedparams += unchangedparams;
}

# Interrogation command event (C_IC_NA_1)
event iec60870_5_104::C_IC_NA_1(c: connection, stationinterrogation: bool, qualifierinterrogation: int){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_qoi(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_qoi(c);
		}
	}
	c$rec$stationinterrogation += stationinterrogation;
	c$rec$qualifierinterrogation += qualifierinterrogation;
}

# Counter interrogation command event (C_CI_NA_1)
event iec60870_5_104::C_CI_NA_1(c: connection, nocounter: bool, group1counter: bool, group2counter: bool, group3counter: bool, group4counter: bool, generalcounter: bool, readonly: bool, freeze: bool, reset: bool, freezeandreset: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_qcc(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_qcc(c);
		}
	}
	c$rec$nocounter += nocounter;
	c$rec$group1counter += group1counter;
	c$rec$group2counter += group2counter;
	c$rec$group4counter += group3counter;
	c$rec$group1counter += group4counter;
	c$rec$generalcounter += generalcounter;
	c$rec$readonly += readonly;
	c$rec$freeze += freeze;
	c$rec$reset += reset;
	c$rec$freezeandreset += freezeandreset;
}

# Read command
event iec60870_5_104::C_RD_NA_1(c: connection, read_cmd: bool){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_read_cmd(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_read_cmd(c);
		}
	}
	c$rec$read_cmd += read_cmd;
}

# Reset process command
event iec60870_5_104::C_RP_NA_1(c: connection, read_cmd: bool, qrp: string){
	if ( !c?$rec ){
		init_rec(c);
		c$rec$ioa = vector();
		set_qrp(c);
		set_read_cmd(c);
	} else {
		if ( !c$rec?$ioa){
			c$rec$ioa = vector();
			set_qrp(c);
			set_read_cmd(c);
		}
	}
	c$rec$qrp += qrp;
	c$rec$read_cmd += read_cmd;
}