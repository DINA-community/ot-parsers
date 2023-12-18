module MMS;
@if ( Version::number >= 60000 )
@load policy/protocols/conn/community-id-logging
@endif

# Initiate request data
type init_requ_data: record{ 
	locDetCall: int; 
	propMaxServOutCalling: int; 
	propMaxServOutCalled: int; 
	propDataStrucNestLvl: int;
};

# Initiate response data
type init_resp_data: record{ 
	locDetCalled: int; 
	negMaxServOutCalling: int; 
	negMaxServOutCalled: int; 
	negDataStrucNestLvl: int;
};

# Status response data
type status_data: record{
	logStatus: string;
	physStatus: string;
};

# Getnamelist request data
type getnamelist_requ_data: record{
	objClass: vector of record {
		basicobjClass: string;
		csobjClass: string;
	};
	objScope: vector of record {
		vmdspecific: bool;
		domainspecific: string;
		aaspecific: bool;
	};
	contAfter: string;
};

# GetNameList response data
type getnamelist_resp_data: record{
	identifier: vector of string;
	moreFollows: bool;
};

# Identify response data
type identify_resp_data: record{
	vendorName: string;
	modelName: string;
	revision: string;
};

# Read request data
type read_requ_data: record{
	specWithResult: bool;
	varSpecList: vector of vector of record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	varListName: record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
};

# Read response data
type read_resp_data: record{
	varSpecList: vector of vector of record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	varListName: record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	data: vector of vector of record {
		boolean: bool;
		integer: int;
		unsigned_integer: int;
		octetstring: string;
		visiblestring: string;
		generalizedtime: string;
	};
};

# Write request data
type write_requ_data: record{
	data: vector of vector of record {
		boolean: bool;
		integer: int;
		unsigned_integer: int;
		octetstring: string;
		visiblestring: string;
		generalizedtime: string;
	};
	varSpecList: vector of vector of record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	varListName: record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
};

# Write response data
type write_resp_data: record{
	accesserr: string;
	success: bool;
};

# GetVariableAccessAttributes request data
type getvarattr_requ_data: record{
	objName: record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	objAddr: record {
		numericAddress: int;
		symbolicAddress: string;
		unconstrainedAddress: string;
	};
};

# GetVariableAccessAttributes response data
type getvarattr_resp_data: record{
	mmsDeletable: bool;
	objAddr: record {
		numericAddress: int;
		symbolicAddress: string;
		unconstrainedAddress: string;
	};
};

# DefineNamedVariableList request data
type defvarlist_requ_data: record{
	listVars: vector of record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	varListName: record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
};

# GetNamedVarListAttr request data
type getvarlistattr_requ_data: record{
	vmdspecific: string;
	domainID: string;
	itemID: string;
	aaspecific: string;
};

# GetNamedVarListAttr response data
type getvarlistattr_resp_data: record{
	mmsDeletable: bool;
	listVars: vector of vector of record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	accCtlList: string;
};

# DeleteNamedVariableList request data
type delvarlist_requ_data: record{
	scopeOfDelete: string;
	varListName: vector of record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	domainName: string;
};

# DeleteNamedVariableList response data
type delvarlist_resp_data: record{
	numberMatched: int;
	numberDeleted: int;
};

# ObtainFile request data
type obfile_requ_data: record{
	srcFile: string;
	dstFile: string;
};

# FileOpen request data
type fileopen_requ_data: record{
	fileName: string;
    initPos: int;
};

# FileOpen response data
type fileopen_resp_data: record{
	frsmID: int;
	fileAttr: vector of record{
		sizeOfFile: int;
		lastModified: string;
	};
};

# FileRead response data
type fileread_resp_data: record{
	fileData: string;
	moreFollows: bool;
};

# FileRename request data
type filerename_requ_data: record{
	currFile: string;
	newFile: string;
};

# FileDir request data
type filedir_requ_data: record{
	fileSpec: string;
	continueAfter: string;
};

# FileDir response data
type filedir_resp_data: record{
	dirEntries: vector of record{
		fileName: string;
		sizeOfFile: int; 
		lastModified: string;
	};
    moreFollows: bool;
};

# InfoReport data
type inforep_data: record{
	varSpecList: vector of vector of record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	varListName: record {
		vmdspecific: string;
		domainID: string;
		itemID: string;
		aaspecific: string;
	};
	data: vector of vector of record {
		boolean: bool;
		integer: int;
		unsigned_integer: int;
		octetstring: string;
		visiblestring: string;
		generalizedtime: string;
	};
};

export {

	# Add log streams
	redef enum Log::ID += { 
		MMS_LOG, 
		INITIATE_LOG,
		STATUS_LOG,
		GETNAMELIST_LOG,
		IDENTIFY_LOG,
		READ_LOG,
		WRITE_LOG,
		GETVARATTR_LOG,
		DEFVARLIST_LOG,
		GETVARLISTATTR_LOG,
		DELVARLIST_LOG,
		OBFILE_LOG,
		FILEOPEN_LOG,
		FILEREAD_LOG,
		FILECLOSE_LOG,
		FILERENAME_LOG,
		FILEDEL_LOG,
		FILEDIR_LOG,
		INFOREP_LOG,
	};

	# Define MMS PDU record
	type MMS: record {
		ts: time &log &optional;
		uid: string &log &optional;
		code: string &log &optional;
		length: int &log &optional;
	};

	# Define MMS initiate PDU record
	type INITIATE: record {
		ts: time &log &optional;
		uid: string &log &optional;
	};

	# Define MMS confirmed service PDU record: status
	type STATUS: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		logicalStatus: string &log &optional;
		physicalStatus: string &log &optional;
	};

	# Define MMS confirmed service PDU record: getNameList
	type GETNAMELIST: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		basicObjClass: vector of string &log &optional;
		identifier: vector of string &log &optional;
		moreFollows: bool &log &optional;
	};

	# Define MMS confirmed service PDU record: identify
	type IDENTIFY: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		vendor: string &log &optional;
		modelName: string &log &optional;
		revision: string &log &optional;
	};

	# Define MMS confirmed service PDU record: read
	type READ: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		specList_domain_item: vector of string &log &optional;
		listName_domain_item: string &log &optional;
		number_of_reponse_data: int &log &optional;
	};

	# Define MMS confirmed service PDU record: write
	type WRITE: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		specList_domain_item: vector of string &log &optional;
		accessError: string &log &optional;
		success: bool &log &optional;
	};

	# Define MMS confirmed service PDU record: getVariableAccessAttributes
	type GETVARATTR: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		objNameDomainID: string &log &optional;
		objNameItemID: string &log &optional;
		objAddrNumericAddress: int &log &optional;
		objAddrSymbolicAddress: string &log &optional;
		objAddrUnconstrAddress: string &log &optional;
	};

	# Define MMS confirmed service PDU record: defineNamedVariableList
	type DEFVARLIST: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
	};

	# Define MMS confirmed service PDU record: getNamedVarListAttr
	type GETVARLISTATTR: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
	};

	# Define MMS confirmed service PDU record: deleteNamedVariableList
	type DELVARLIST: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		domainName: string &log &optional;
		numberListVars: int &log &optional;
		numberMatched: int &log &optional;
		numberDeleted: int &log &optional;
	};

	# Define MMS confirmed service PDU record: obtainFile
	type OBFILE: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		srcFile: string &log &optional;
		dstFile: string &log &optional;
		success: bool &log &optional;
	};

	# Define MMS confirmed service PDU record: fileOpen
	type FILEOPEN: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		filename: string &log &optional;
		frsmID: int &log &optional; # frsm file read state machine
	};

	# Define MMS confirmed service PDU record: fileRead
	type FILEREAD: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
	};

	# Define MMS confirmed service PDU record: fileClose
	type FILECLOSE: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		frsmID: int &log &optional; # frsm file read state machine
	};

	# Define MMS confirmed service PDU record: fileRename
	type FILERENAME: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		currentFile: string &log &optional;
		newFile: string &log &optional;
		success: bool &log &optional;
	};

	# Define MMS confirmed service PDU record: fileDelete
	type FILEDEL: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
	};

	# Define MMS confirmed service PDU record: fileDir
	type FILEDIR: record {
		ts: time &log &optional;
		uid: string &log &optional;
		invokeID: int &log &optional;
		messageType: string &log &optional; # request or response
		fileSpec: string &log &optional;
		dirEntries: vector of string &log &optional;
	};

	# Define MMS unconfirmed service PDU record: infoReport
	type INFOREP: record {
		ts: time &log &optional;
		uid: string &log &optional;
		vmd: string &log &optional;
		varSpecList_DomainItemID: vector of string &log &optional;
		varListNameDomainID: string &log &optional;
		varListNameItemID: string &log &optional;
	};

}

# Initialize log streams
event zeek_init() &priority=5  {
	print "Initializing IEC 61850-8-1 (MMS) analyzer";
	Log::create_stream(MMS::MMS_LOG, [$columns = MMS, $path="mms"]);
	Log::create_stream(MMS::INITIATE_LOG, [$columns = INITIATE, $path="mms_initiate"]);
	Log::create_stream(MMS::STATUS_LOG, [$columns = STATUS, $path="mms_status"]);
	Log::create_stream(MMS::GETNAMELIST_LOG, [$columns = GETNAMELIST, $path="mms_getnamelist"]);
	Log::create_stream(MMS::IDENTIFY_LOG, [$columns = IDENTIFY, $path="mms_identify"]);
	Log::create_stream(MMS::READ_LOG, [$columns = READ, $path="mms_read"]);
	Log::create_stream(MMS::WRITE_LOG, [$columns = WRITE, $path="mms_write"]);
	Log::create_stream(MMS::GETVARATTR_LOG, [$columns = GETVARATTR, $path="mms_getvarattr"]);
	Log::create_stream(MMS::DEFVARLIST_LOG, [$columns = DEFVARLIST, $path="mms_defvarlist"]);
	Log::create_stream(MMS::GETVARLISTATTR_LOG, [$columns = DEFVARLIST, $path="mms_getvarlistattr"]);
	Log::create_stream(MMS::DELVARLIST_LOG, [$columns = DELVARLIST, $path="mms_delvarlist"]);
	Log::create_stream(MMS::OBFILE_LOG, [$columns = OBFILE, $path="mms_obtainfile"]);
	Log::create_stream(MMS::FILEOPEN_LOG, [$columns = FILEOPEN, $path="mms_fileopen"]);
	Log::create_stream(MMS::FILEREAD_LOG, [$columns = FILEREAD, $path="mms_fileread"]);
	Log::create_stream(MMS::FILECLOSE_LOG, [$columns = FILECLOSE, $path="mms_fileclose"]);
	Log::create_stream(MMS::FILERENAME_LOG, [$columns = FILERENAME, $path="mms_filerename"]);
	Log::create_stream(MMS::FILEDEL_LOG, [$columns = FILEDEL, $path="mms_filedelete"]);
	Log::create_stream(MMS::FILEDIR_LOG, [$columns = FILEDIR, $path="mms_filedirectory"]);
	Log::create_stream(MMS::INFOREP_LOG, [$columns = INFOREP, $path="mms_inforeport"]);
}

# Update connection object
redef record connection += {
	mms_rec: MMS &optional;
	initiate_rec: INITIATE &optional;
	status_rec: STATUS &optional;
	getnamelist_rec: GETNAMELIST &optional;
	identify_rec: IDENTIFY &optional;
	read_rec: READ &optional;
	write_rec: WRITE &optional;
	getvarattr_rec: GETVARATTR &optional;
	defvarlist_rec: DEFVARLIST &optional;
	getvarlistattr_rec: GETVARLISTATTR &optional;
	delvarlist_rec: DELVARLIST &optional;
	obfile_rec: OBFILE &optional;
	fileopen_rec: FILEOPEN &optional;
	fileread_rec: FILEREAD &optional;
	fileclose_rec: FILECLOSE &optional;
	filerename_rec: FILERENAME &optional;
	filedel_rec: FILEDEL &optional;
	filedir_rec: FILEDIR &optional;
	inforep_rec: INFOREP &optional;
};

# Initialize records
function init_records(c: connection, r: string) {
	if ( r == "MMS" ){
		local mms_rec: MMS = [];
		c$mms_rec = mms_rec;
	}
	if ( r == "INITIATE" ){
		local initiate_rec: INITIATE = [];
		c$initiate_rec = initiate_rec;
	}
	if ( r == "STATUS" ){
		local status_rec: STATUS = [];
		c$status_rec = status_rec;
	}
	if ( r == "GETNAMELIST" ){
		local getnamelist_rec: GETNAMELIST = [];
		c$getnamelist_rec = getnamelist_rec;
	}
	if ( r == "IDENTIFY" ){
		local identify_rec: IDENTIFY = [];
		c$identify_rec = identify_rec;
	}
	if ( r == "READ" ){
		local read_rec: READ = [];
		c$read_rec = read_rec;
	}
	if ( r == "WRITE" ){
		local write_rec: WRITE = [];
		c$write_rec = write_rec;
	}
	if ( r == "GETVARATTR" ){
		local getvarattr_rec: GETVARATTR = [];
		c$getvarattr_rec = getvarattr_rec;
	}
	if ( r == "DEFVARLIST" ){
		local defvarlist_rec: DEFVARLIST = [];
		c$defvarlist_rec = defvarlist_rec;
	}
	if ( r == "GETVARLISTATTR" ){
		local getvarlistattr_rec: GETVARLISTATTR = [];
		c$getvarlistattr_rec = getvarlistattr_rec;
	}
	if ( r == "DELVARLIST" ){
		local delvarlist_rec: DELVARLIST = [];
		c$delvarlist_rec = delvarlist_rec;
	}
	if ( r == "OBFILE" ){
		local obfile_rec: OBFILE = [];
		c$obfile_rec = obfile_rec;
	}
	if ( r == "FILEOPEN" ){
		local fileopen_rec: FILEOPEN = [];
		c$fileopen_rec = fileopen_rec;
	}
	if ( r == "FILEREAD" ){
		local fileread_rec: FILEREAD = [];
		c$fileread_rec = fileread_rec;
	}
	if ( r == "FILECLOSE" ){
		local fileclose_rec: FILECLOSE = [];
		c$fileclose_rec = fileclose_rec;
	}
	if ( r == "FILERENAME" ){
		local filerename_rec: FILERENAME = [];
		c$filerename_rec = filerename_rec;
	}
	if ( r == "FILEDEL" ){
		local filedel_rec: FILEDEL = [];
		c$filedel_rec = filedel_rec;
	}
	if ( r == "FILEDIR" ){
		local filedir_rec: FILEDIR = [];
		c$filedir_rec = filedir_rec;
	}
	if ( r == "INFOREP" ){
		local inforep_rec: INFOREP = [];
		c$inforep_rec = inforep_rec;
	}
}

# Write records to log streams and reinitialize
function write_records(c: connection, r: string){
	if ( r == "MMS" ){
		Log::write(MMS::MMS_LOG, c$mms_rec);
		init_records(c, r);
	}
	if ( r == "INITIATE" ){
		Log::write(MMS::INITIATE_LOG, c$initiate_rec);
		init_records(c, r);
	}
	if ( r == "STATUS" ){
		Log::write(MMS::STATUS_LOG, c$status_rec);
		init_records(c, r);
	}
	if ( r == "GETNAMELIST" ){
		Log::write(MMS::GETNAMELIST_LOG, c$getnamelist_rec);
		init_records(c, r);
	}
	if ( r == "IDENTIFY" ){
		Log::write(MMS::IDENTIFY_LOG, c$identify_rec);
		init_records(c, r);
	}
	if ( r == "READ" ){
		Log::write(MMS::READ_LOG, c$read_rec);
		init_records(c, r);
	}
	if ( r == "WRITE" ){
		Log::write(MMS::WRITE_LOG, c$write_rec);
		init_records(c, r);
	}
	if ( r == "GETVARATTR" ){
		Log::write(MMS::GETVARATTR_LOG, c$getvarattr_rec);
		init_records(c, r);
	}
	if ( r == "DEFVARLIST" ){
		Log::write(MMS::DEFVARLIST_LOG, c$defvarlist_rec);
		init_records(c, r);
	}
	if ( r == "GETVARLISTATTR" ){
		Log::write(MMS::GETVARLISTATTR_LOG, c$getvarlistattr_rec);
		init_records(c, r);
	}
	if ( r == "DELVARLIST" ){
		Log::write(MMS::DELVARLIST_LOG, c$delvarlist_rec);
		init_records(c, r);
	}
	if ( r == "OBFILE" ){
		Log::write(MMS::OBFILE_LOG, c$obfile_rec);
		init_records(c, r);
	}
	if ( r == "FILEOPEN" ){
		Log::write(MMS::FILEOPEN_LOG, c$fileopen_rec);
		init_records(c, r);
	}
	if ( r == "FILEREAD" ){
		Log::write(MMS::FILEREAD_LOG, c$fileread_rec);
		init_records(c, r);
	}
	if ( r == "FILECLOSE" ){
		Log::write(MMS::FILECLOSE_LOG, c$fileclose_rec);
		init_records(c, r);
	}
	if ( r == "FILERENAME" ){
		Log::write(MMS::FILERENAME_LOG, c$filerename_rec);
		init_records(c, r);
	}
	if ( r == "FILEDEL" ){
		Log::write(MMS::FILEDEL_LOG, c$filedel_rec);
		init_records(c, r);
	}
	if ( r == "FILEDIR" ){
		Log::write(MMS::FILEDIR_LOG, c$filedir_rec);
		init_records(c, r);
	}
	if ( r == "INFOREP" ){
		Log::write(MMS::INFOREP_LOG, c$inforep_rec);
		init_records(c, r);
	}
}

# MMS PDU event
event iec61850mms::MMS_PDU(c: connection, code: string, length: int){
	if ( !c?$mms_rec ){
		init_records(c, "MMS");
	}
	c$mms_rec$ts = network_time();
	c$mms_rec$uid = c$uid;
	c$mms_rec$code = code;
	c$mms_rec$length = length;
	write_records(c, "MMS");
}

# MMS initiate request event
event iec61850mms::INIT_REQU(c: connection, data: init_requ_data){
	if ( !c?$initiate_rec ){
		init_records(c, "INITIATE");
	}
	c$initiate_rec$ts = network_time();
	c$initiate_rec$uid = c$uid;
	write_records(c, "INITIATE");
}

# MMS initiate response event
event iec61850mms::INIT_RESP(c: connection, data: init_resp_data){
	if ( !c?$initiate_rec ){
		init_records(c, "INITIATE");
	}
	c$initiate_rec$ts = network_time();
	c$initiate_rec$uid = c$uid;
	write_records(c, "INITIATE");
}

# MMS confirmed request event: status
event iec61850mms::STATUS_REQU(c: connection, invokeID: int, status: bool){
	if ( !c?$status_rec ){
		init_records(c, "STATUS");
	}
	c$status_rec$ts = network_time();
	c$status_rec$uid = c$uid;
	c$status_rec$invokeID = invokeID;
	write_records(c, "STATUS");
}

# MMS confirmed response event: status
event iec61850mms::STATUS_RESP(c: connection, invokeID: int, data: status_data){
	if ( !c?$status_rec ){
		init_records(c, "STATUS");
	}
	c$status_rec$ts = network_time();
	c$status_rec$uid = c$uid;
	c$status_rec$invokeID = invokeID;
	c$status_rec$logicalStatus = data$logStatus;
	c$status_rec$physicalStatus = data$physStatus;
	write_records(c, "STATUS");
}

# MMS confirmed request event: getNameList
event iec61850mms::GETNAMELIST_REQU(c: connection, invokeID: int, data: getnamelist_requ_data){
	if ( !c?$getnamelist_rec ){
		init_records(c, "GETNAMELIST");
	}
	c$getnamelist_rec$ts = network_time();
	c$getnamelist_rec$uid = c$uid;
	c$getnamelist_rec$invokeID = invokeID;
	c$getnamelist_rec$messageType = "Request";
	c$getnamelist_rec$basicObjClass = vector();

	for ( i in data$objClass ) {
		c$getnamelist_rec$basicObjClass += data$objClass[i]$basicobjClass;
	}
	write_records(c, "GETNAMELIST");
}

# MMS confirmed response event: getNameList
event iec61850mms::GETNAMELIST_RESP(c: connection, invokeID: int, data: getnamelist_resp_data){
	if ( !c?$getnamelist_rec ){
		init_records(c, "GETNAMELIST");
	}
	c$getnamelist_rec$ts = network_time();
	c$getnamelist_rec$uid = c$uid;
	c$getnamelist_rec$invokeID = invokeID;
	c$getnamelist_rec$messageType = "Response";
	c$getnamelist_rec$identifier = data$identifier;
	c$getnamelist_rec$moreFollows = data$moreFollows;
	write_records(c, "GETNAMELIST");
}

# MMS confirmed request event: identify
event iec61850mms::IDENTIFY_REQU(c: connection, invokeID: int, identify: bool){
	if ( !c?$identify_rec ){
		init_records(c, "IDENTIFY");
	}
	c$identify_rec$ts = network_time();
	c$identify_rec$uid = c$uid;
	c$identify_rec$invokeID = invokeID;
	write_records(c, "IDENTIFY");
}

# MMS confirmed response event: identify
event iec61850mms::IDENTIFY_RESP(c: connection, invokeID: int, data: identify_resp_data){
	if ( !c?$identify_rec ){
		init_records(c, "IDENTIFY");
	}
	c$identify_rec$ts = network_time();
	c$identify_rec$uid = c$uid;
	c$identify_rec$invokeID = invokeID;
	c$identify_rec$vendor = data$vendorName;
	c$identify_rec$modelName = data$modelName;
	c$identify_rec$revision = data$revision;
	write_records(c, "IDENTIFY");
}

# MMS confirmed request event: read
event iec61850mms::READ_REQU(c: connection, invokeID: int, data: read_requ_data){
	if ( !c?$read_rec ){
		init_records(c, "READ");
	}
	local separtor_seq = "_";
	c$read_rec$ts = network_time();
	c$read_rec$uid = c$uid;
	c$read_rec$invokeID = invokeID;
	c$read_rec$messageType = "Request";
	c$read_rec$specList_domain_item = vector();

	for ( i in data$varSpecList) {
		for ( n in data$varSpecList[i]) {
			c$read_rec$specList_domain_item += data$varSpecList[i][n]$domainID + separtor_seq + data$varSpecList[i][n]$itemID;
		}
	}

	c$read_rec$listName_domain_item = data$varListName$domainID + separtor_seq + data$varListName$itemID;
	write_records(c, "READ");
}

# MMS confirmed response event: read
event iec61850mms::READ_RESP(c: connection, invokeID: int, data: read_resp_data){
	if ( !c?$read_rec ){
		init_records(c, "READ");
	}
	local separtor_seq = "_";
	c$read_rec$ts = network_time();
	c$read_rec$uid = c$uid;
	c$read_rec$invokeID = invokeID;
	c$read_rec$messageType = "Response";
	c$read_rec$specList_domain_item = vector();

	for ( i in data$varSpecList) {
		for ( n in data$varSpecList[i]) {
			c$read_rec$specList_domain_item += data$varSpecList[i][n]$domainID + separtor_seq + data$varSpecList[i][n]$itemID;
		}
	}

	c$read_rec$listName_domain_item = data$varListName$domainID + separtor_seq + data$varListName$itemID;
	c$read_rec$number_of_reponse_data = |data$data|;
	write_records(c, "READ");
}

# MMS confirmed request event: write
event iec61850mms::WRITE_REQU(c: connection, invokeID: int, data: write_requ_data){
	if ( !c?$write_rec ){
		init_records(c, "WRITE");
	}
	local separtor_seq = "_";
	c$write_rec$ts = network_time();
	c$write_rec$uid = c$uid;
	c$write_rec$invokeID = invokeID;
	c$write_rec$messageType = "Request";
	c$write_rec$specList_domain_item = vector();
	for ( i in data$varSpecList ) {
		for ( n in data$varSpecList[i] ) {
			c$write_rec$specList_domain_item += data$varSpecList[i][n]$domainID + separtor_seq + data$varSpecList[i][n]$itemID;
		}
	}
	write_records(c, "WRITE");
}

# MMS confirmed response event: write
event iec61850mms::WRITE_RESP(c: connection, invokeID: int, data: write_resp_data){
	if ( !c?$write_rec ){
		init_records(c, "WRITE");
	}
	c$write_rec$ts = network_time();
	c$write_rec$uid = c$uid;
	c$write_rec$invokeID = invokeID;
	c$write_rec$messageType = "Response";
	c$write_rec$accessError = data$accesserr;
	c$write_rec$success = data$success;
	write_records(c, "WRITE");
}

# MMS confirmed request event: getVariableAccessAttributes
event iec61850mms::GETVARATTR_REQU(c: connection, invokeID: int, data: getvarattr_requ_data){
	if ( !c?$getvarattr_rec ){
		init_records(c, "GETVARATTR");
	}
	c$getvarattr_rec$ts = network_time();
	c$getvarattr_rec$uid = c$uid;
	c$getvarattr_rec$invokeID = invokeID;
	c$getvarattr_rec$messageType = "Request";
	c$getvarattr_rec$objNameDomainID = data$objName$domainID;
	c$getvarattr_rec$objNameItemID = data$objName$itemID;
	c$getvarattr_rec$objAddrNumericAddress = data$objAddr$numericAddress;
	c$getvarattr_rec$objAddrSymbolicAddress = data$objAddr$symbolicAddress;
	c$getvarattr_rec$objAddrUnconstrAddress = data$objAddr$unconstrainedAddress;
	write_records(c, "GETVARATTR");
}

# MMS confirmed response event: getVariableAccessAttributes
event iec61850mms::GETVARATTR_RESP(c: connection, invokeID: int, data: getvarattr_resp_data){
	if ( !c?$getvarattr_rec ){
		init_records(c, "GETVARATTR");
	}
	c$getvarattr_rec$ts = network_time();
	c$getvarattr_rec$uid = c$uid;
	c$getvarattr_rec$invokeID = invokeID;
	c$getvarattr_rec$messageType = "Reponse";
	c$getvarattr_rec$objAddrNumericAddress = data$objAddr$numericAddress;
	c$getvarattr_rec$objAddrSymbolicAddress = data$objAddr$symbolicAddress;
	c$getvarattr_rec$objAddrUnconstrAddress = data$objAddr$unconstrainedAddress;
	write_records(c, "GETVARATTR");
}

# MMS confirmed request event: defineNamedVariableList
event iec61850mms::DEFVARLIST_REQU(c: connection, invokeID: int, data: defvarlist_requ_data){
	if ( !c?$defvarlist_rec ){
		init_records(c, "DEFVARLIST");
	}
	c$defvarlist_rec$ts = network_time();
	c$defvarlist_rec$uid = c$uid;
	c$defvarlist_rec$invokeID = invokeID;
	write_records(c, "DEFVARLIST");
}

# MMS confirmed response event: defineNamedVariableList
event iec61850mms::DEFVARLIST_RESP(c: connection, invokeID: int, defineNamedVariableList: bool){
	if ( !c?$defvarlist_rec ){
		init_records(c, "DEFVARLIST");
	}
	c$defvarlist_rec$ts = network_time();
	c$defvarlist_rec$uid = c$uid;
	c$defvarlist_rec$invokeID = invokeID;
	write_records(c, "DEFVARLIST");
}

# MMS confirmed request event: getNamedVarListAttr
event iec61850mms::GETVARLISTATTR_REQU(c: connection, invokeID: int, data: getvarlistattr_requ_data){
	if ( !c?$getvarlistattr_rec ){
		init_records(c, "GETVARLISTATTR");
	}
	c$getvarlistattr_rec$ts = network_time();
	c$getvarlistattr_rec$uid = c$uid;
	c$getvarlistattr_rec$invokeID = invokeID;
	write_records(c, "GETVARLISTATTR");
}

# MMS confirmed response event: getNamedVarListAttr
event iec61850mms::GETVARLISTATTR_RESP(c: connection, invokeID: int, data: getvarlistattr_resp_data){
	if ( !c?$getvarlistattr_rec ){
		init_records(c, "GETVARLISTATTR");
	}
	c$getvarlistattr_rec$ts = network_time();
	c$getvarlistattr_rec$uid = c$uid;
	c$getvarlistattr_rec$invokeID = invokeID;
	write_records(c, "GETVARLISTATTR");
}

# MMS confirmed request event: deleteNamedVariableList
event iec61850mms::DELVARLIST_REQU(c: connection, invokeID: int, data: delvarlist_requ_data){
	if ( !c?$delvarlist_rec ){
		init_records(c, "DELVARLIST");
	}
	c$delvarlist_rec$ts = network_time();
	c$delvarlist_rec$uid = c$uid;
	c$delvarlist_rec$invokeID = invokeID;
	c$delvarlist_rec$messageType = "Request";
	c$delvarlist_rec$domainName = data$domainName;
	c$delvarlist_rec$numberListVars = |data$varListName|;
	write_records(c, "DELVARLIST");
}

# MMS confirmed response event: deleteNamedVariableList
event iec61850mms::DELVARLIST_RESP(c: connection, invokeID: int, data: delvarlist_resp_data){
	if ( !c?$delvarlist_rec ){
		init_records(c, "DELVARLIST");
	}
	c$delvarlist_rec$ts = network_time();
	c$delvarlist_rec$uid = c$uid;
	c$delvarlist_rec$invokeID = invokeID;
	c$delvarlist_rec$messageType = "Response";
	c$delvarlist_rec$numberMatched = data$numberMatched;
	c$delvarlist_rec$numberDeleted = data$numberDeleted;
	write_records(c, "DELVARLIST");
}

# MMS confirmed request event: obtainFile
event iec61850mms::OBFILE_REQU(c: connection, invokeID: int, data: obfile_requ_data){
	if ( !c?$obfile_rec ){
		init_records(c, "OBFILE");
	}
	c$obfile_rec$ts = network_time();
	c$obfile_rec$uid = c$uid;
	c$obfile_rec$invokeID = invokeID;
	c$obfile_rec$messageType = "Request";
	c$obfile_rec$srcFile = data$srcFile;
	c$obfile_rec$dstFile = data$dstFile;
	write_records(c, "OBFILE");
}

# MMS confirmed response event: obtainFile
event iec61850mms::OBFILE_RESP(c: connection, invokeID: int, obfile: bool){
	if ( !c?$obfile_rec ){
		init_records(c, "OBFILE");
	}
	c$obfile_rec$ts = network_time();
	c$obfile_rec$uid = c$uid;
	c$obfile_rec$invokeID = invokeID;
	c$obfile_rec$messageType = "Response";
	c$obfile_rec$success = obfile;
	write_records(c, "OBFILE");
}

# MMS confirmed request event: fileOpen
event iec61850mms::FILEOPEN_REQU(c: connection, invokeID: int, data: fileopen_requ_data){
	if ( !c?$fileopen_rec ){
		init_records(c, "FILEOPEN");
	}
	c$fileopen_rec$ts = network_time();
	c$fileopen_rec$uid = c$uid;
	c$fileopen_rec$invokeID = invokeID;
	c$fileopen_rec$messageType = "Request";
	c$fileopen_rec$filename = data$fileName;
	write_records(c, "FILEOPEN");
}

# MMS confirmed response event: fileOpen
event iec61850mms::FILEOPEN_RESP(c: connection, invokeID: int, data: fileopen_resp_data){
	if ( !c?$fileopen_rec ){
		init_records(c, "FILEOPEN");
	}
	c$fileopen_rec$ts = network_time();
	c$fileopen_rec$uid = c$uid;
	c$fileopen_rec$invokeID = invokeID;
	c$fileopen_rec$messageType = "Response";
	c$fileopen_rec$frsmID = data$frsmID;
	write_records(c, "FILEOPEN");
}

# MMS confirmed request event: fileRead
event iec61850mms::FILEREAD_REQU(c: connection, invokeID: int, fileread: int){
	if ( !c?$fileread_rec ){
		init_records(c, "FILEREAD");
	}
	c$fileread_rec$ts = network_time();
	c$fileread_rec$uid = c$uid;
	c$fileread_rec$invokeID = invokeID;
	write_records(c, "FILEREAD");
}

# MMS confirmed response event: fileRead
event iec61850mms::FILEREAD_RESP(c: connection, invokeID: int, data: fileread_resp_data){
	if ( !c?$fileread_rec ){
		init_records(c, "FILEREAD");
	}
	c$fileread_rec$ts = network_time();
	c$fileread_rec$uid = c$uid;
	c$fileread_rec$invokeID = invokeID;
	write_records(c, "FILEREAD");
}

# MMS confirmed request event: fileClose
event iec61850mms::FILECLOSE_REQU(c: connection, invokeID: int, fileclose: int){
	if ( !c?$fileclose_rec ){
		init_records(c, "FILECLOSE");
	}
	c$fileclose_rec$ts = network_time();
	c$fileclose_rec$uid = c$uid;
	c$fileclose_rec$invokeID = invokeID;
	c$fileclose_rec$messageType = "Request";
	c$fileclose_rec$frsmID = fileclose;
	write_records(c, "FILECLOSE");
}

# MMS confirmed response event: fileClose
event iec61850mms::FILECLOSE_RESP(c: connection, invokeID: int, fileclose: bool){
	if ( !c?$fileclose_rec ){
		init_records(c, "FILECLOSE");
	}
	c$fileclose_rec$ts = network_time();
	c$fileclose_rec$uid = c$uid;
	c$fileclose_rec$invokeID = invokeID;
	c$fileclose_rec$messageType = "Response";
	write_records(c, "FILECLOSE");
}

# MMS confirmed request event: fileRename
event iec61850mms::FILERENAME_REQU(c: connection, invokeID: int, data: filerename_requ_data){
	if ( !c?$filerename_rec ){
		init_records(c, "FILERENAME");
	}
	c$filerename_rec$ts = network_time();
	c$filerename_rec$uid = c$uid;
	c$filerename_rec$invokeID = invokeID;
	c$filerename_rec$messageType = "Request";
	c$filerename_rec$currentFile = data$currFile;
	c$filerename_rec$newFile = data$newFile;
	write_records(c, "FILERENAME");
}

# MMS confirmed response event: fileRename
event iec61850mms::FILERENAME_RESP(c: connection, invokeID: int, filerename: bool){
	if ( !c?$filerename_rec ){
		init_records(c, "FILERENAME");
	}
	c$filerename_rec$ts = network_time();
	c$filerename_rec$uid = c$uid;
	c$filerename_rec$invokeID = invokeID;
	c$filerename_rec$messageType = "Response";
	c$filerename_rec$success = filerename;
	write_records(c, "FILERENAME");
}

# MMS confirmed request event: fileDelete
event iec61850mms::FILEDEL_REQU(c: connection, invokeID: int, fileDelete: string){
	if ( !c?$filedel_rec ){
		init_records(c, "FILEDEL");
	}
	c$filedel_rec$ts = network_time();
	c$filedel_rec$uid = c$uid;
	c$filedel_rec$invokeID = invokeID;
	write_records(c, "FILEDEL");
}

# MMS confirmed response event: fileDelete
event iec61850mms::FILEDEL_RESP(c: connection, invokeID: int, fileDelete: bool){
	if ( !c?$filedel_rec ){
		init_records(c, "FILEDEL");
	}
	c$filedel_rec$ts = network_time();
	c$filedel_rec$uid = c$uid;
	c$filedel_rec$invokeID = invokeID;
	write_records(c, "FILEDEL");
}

# MMS confirmed request event: fileDir
event iec61850mms::FILEDIR_REQU(c: connection, invokeID: int, data: filedir_requ_data){
	if ( !c?$filedir_rec ){
		init_records(c, "FILEDIR");
	}
	c$filedir_rec$ts = network_time();
	c$filedir_rec$uid = c$uid;
	c$filedir_rec$invokeID = invokeID;
	c$filedir_rec$messageType = "Request";
	c$filedir_rec$fileSpec = data$fileSpec;
	write_records(c, "FILEDIR");
}

# MMS confirmed response event: fileDir
event iec61850mms::FILEDIR_RESP(c: connection, invokeID: int, data: filedir_resp_data){
	if ( !c?$filedir_rec ){
		init_records(c, "FILEDIR");
	}
	c$filedir_rec$ts = network_time();
	c$filedir_rec$uid = c$uid;
	c$filedir_rec$invokeID = invokeID;
	c$filedir_rec$messageType = "Response";
	c$filedir_rec$dirEntries = vector();

	for ( i in data$dirEntries ) {
		c$filedir_rec$dirEntries += data$dirEntries[i]$fileName;
	}

	write_records(c, "FILEDIR");
}

# MMS unconfirmed event: infoReport
event iec61850mms::INFOREPORT(c: connection, data: inforep_data){
	if ( !c?$inforep_rec ){
		init_records(c, "INFOREP");
	}
	local separtor_seq = "_";
	c$inforep_rec$ts = network_time();
	c$inforep_rec$uid = c$uid;
	c$inforep_rec$vmd = data$varListName$vmdspecific;
	c$inforep_rec$varListNameDomainID = data$varListName$domainID;
	c$inforep_rec$varListNameItemID = data$varListName$itemID;
	c$inforep_rec$varSpecList_DomainItemID = vector();

	for (m in data$varSpecList ) {
		for ( n in data$varSpecList[m]) {
			c$inforep_rec$varSpecList_DomainItemID += data$varSpecList[m][n]$domainID + separtor_seq + data$varSpecList[m][n]$itemID;
		}
	}
	write_records(c, "INFOREP");
}
