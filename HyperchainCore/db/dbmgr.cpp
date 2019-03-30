/*Copyright 2016-2019 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
#include "../newLog.h"
#include <random>
#include "db/dbmgr.h"
#include "headers/inter_public.h"
#include "headers/commonstruct.h"

namespace DBSQL {

	
	const std::string EVIDENCES_TBL =
		"CREATE TABLE IF NOT EXISTS evidence_tbl "
		"("
		"    [hash]                                 TEXT NOT NULL,"
		"    [blocknum]                             INTEGER DEFAULT 0,"
		"    [filename]                             TEXT NOT NULL,"
		"    [custominfo]                           TEXT DEFAULT '',"
		"    [owner]                                TEXT DEFAULT '',"
		"    [filestate]                            INTEGER DEFAULT 0,"
		"    [regtime]                              INTEGER DEFAULT 0,"
		"    [filesize]                             INTEGER DEFAULT '',"
		"    [extra]                                TEXT DEFAULT '',"
		"    PRIMARY KEY(hash, regtime)"
		");";

	const std::string HYPERBLOCK_TBL =
		"CREATE TABLE IF NOT EXISTS hyperblock ("
		"  [hash]	TEXT NOT NULL DEFAULT '',"
		"  [id]		INTEGER DEFAULT 0,"
		"  [type]	INTEGER DEFAULT 0,"
		"  [hid]		INTEGER DEFAULT 0,"
		"  [hhash]	TEXT NOT NULL DEFAULT '',"
		"  [hash_prev]	TEXT NOT NULL DEFAULT '',"
		"  [payload]	TEXT NOT NULL DEFAULT '',"
		"  [ctime]	INTEGER DEFAULT 0,"
		"  [version]	varchar(32) DEFAULT '',"
		"  [queue_id]	INTEGER DEFAULT 0,"
		"  [chain_num]	INTEGER DEFAULT 0,"
		"  [difficulty]	INTEGER DEFAULT 0,"
		"  PRIMARY KEY (hash)"
		");";

	const std::string ONCHAINED_TBL =
		"CREATE TABLE IF NOT EXISTS localblockonchained ("
		"  [requestid]	varchar(32) DEFAULT ''," 
		"  [hid]		INTEGER DEFAULT 0,"
		"  [chain_num]	INTEGER DEFAULT 0,"
		"  [id]	INTEGER DEFAULT 0,"			
		"  PRIMARY KEY (requestid)"
		");";

	const std::string UPQUEUE_TBL =
		"CREATE TABLE IF NOT EXISTS upqueue ("
		"  [id] integer PRIMARY KEY autoincrement,"
		"  [hash]	TEXT NOT NULL DEFAULT '',"
		"  [ctime]	INTEGER DEFAULT 0"
		");";

	const std::string MYSELF_TBL =
		"CREATE TABLE IF NOT EXISTS myself ("
		"  [id] char(16) PRIMARY KEY,"
		"  [regtime] INTEGER DEFAULT 0,"
		"  [accesspoint] TEXT NOT NULL DEFAULT ''"
		");";

	const std::string NEIGHBORNODE_TBL =
		"CREATE TABLE IF NOT EXISTS neighbornodes ("
		"  [id] char(16) PRIMARY KEY,"
		"  [accesspoint] TEXT NOT NULL DEFAULT ''"
		");";
}




////////////////////////////////////////////////////
static const std::string scEvidenceInsert = "INSERT OR REPLACE INTO evidence_tbl(hash,blocknum,filename,custominfo,owner,filestate,regtime,filesize,extra) "
                                         "VALUES(?,?,?,?,?,?,?,?,?);";
////////////////////////////////////////////////////
static const std::string scHyperblockInsert = "INSERT OR REPLACE INTO hyperblock(hash,id,type,hid,hhash,hash_prev,payload,ctime,queue_id,chain_num,version,difficulty)  "
"VALUES(?,?,?,?,?,?,?,?,?,?,?,?);";
////////////////////////////////////////////////////
static const std::string scUpqueueInsert = "INSERT OR REPLACE INTO upqueue(hash,ctime) "
"VALUES(?,?);";
////////////////////////////////////////////////////

static const std::string scGetNeighbors = "SELECT * FROM neighbornodes";
////////////////////////////////////////////////////
DBmgr *DBmgr::instance()
{
    static DBmgr s;
    return &s;
}

DBmgr::DBmgr(){

}

DBmgr::~DBmgr()
{
    if (_db){
        if (_db->isOpen()){
            _db->close();
        }
        delete _db;
        _db = nullptr;
    }
}

int DBmgr::open(const char *dbpath)
{
    int ecode = 0;
    try{
        if (_db){
            if (_db->isOpen()){
                _db->close();
            }
        }

        if (!_db){
            _db = new CppSQLite3DB();
        }

        _db->open(dbpath);

#ifndef _DEBUG
        //int result = sqlite3_key(_db->getDB(), "123456!@#$%^", 12);
#endif
        createTbls();

        updateDB();
    }
    catch (CppSQLite3Exception& sqliteException){
        ecode = sqliteException.errorCode();
    }
    catch (...){
        ecode = -1;
    }

    return ecode;
}

bool DBmgr::isOpen()
{
    if (_db && _db->isOpen())
    {
        return true;
    }

    return false;
}

int DBmgr::close()
{
    int ecode = 0;

    try{
        _db->close();
    }
    catch (CppSQLite3Exception& sqliteException){
        ecode = sqliteException.errorCode();
    }
    catch (...){
        ecode = -1;
    }

    return ecode;
}

bool DBmgr::ifColExist(const char *tbl, const char *col)
{
    CppSQLite3Statement stmt = _db->compileStatement("SELECT sql FROM sqlite_master WHERE type='table' AND name = ?");
    stmt.bind(1, tbl);

    std::string sql;
    CppSQLite3Query query = stmt.execQuery();
    while (!query.eof())
    {
        sql = query.getStringField(0);
        break;
    }

    return std::string::npos != sql.find(col);
}

bool DBmgr::ifTblOrIndexExist(const char *name, int type)
{
    int exist = 0;

    try{
        std::string sql;
        if (1 == type){
            sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?";
        }
        else{
            sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name = ?";
        }

        CppSQLite3Statement stmt = _db->compileStatement(sql.c_str());
        stmt.bind(1, name);

        CppSQLite3Query query = stmt.execQuery();
        if (!query.eof()){
            exist = query.getIntField(0);
        }
    }
    catch (CppSQLite3Exception& ex){
    }

    return exist == 0 ? false : true;
}

int DBmgr::insertEvidence(const TEVIDENCEINFO &evidence)
{
    try
    {
        
        CppSQLite3Statement stmt = _db->compileStatement(scEvidenceInsert.c_str());
        stmt.bind(1, evidence.cFileHash.c_str());
		stmt.bind(2, (sqlite_int64)evidence.iBlocknum);
        stmt.bind(3, evidence.cFileName.c_str());
        stmt.bind(4, evidence.cCustomInfo.c_str());
        stmt.bind(5, evidence.cRightOwner.c_str());
        stmt.bind(6, evidence.iFileState);
		stmt.bind(7, (sqlite_int64)evidence.tRegisTime);
		stmt.bind(8, (sqlite_int64)evidence.iFileSize);
        stmt.bind(9, "");

        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex)
    {
		g_daily_logger->error("DB insertEvidence; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB insertEvidence; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
        return ex.errorCode();
    }

    return 0;
}

int DBmgr::getEvidences(std::list<TEVIDENCEINFO> &evidences, int page, int size)
{
    int ret = 0;

    try
    {
        CppSQLite3Statement stmt;
        std::string sql;
        if (page == -1){
            sql = "SELECT * FROM evidence_tbl ORDER BY regtime DESC;";
        }
        else{
            sql = "SELECT * FROM evidence_tbl ORDER BY regtime DESC LIMIT ? OFFSET ?;";
        }

        stmt = _db->compileStatement(sql.c_str());

        if (page != -1){
            stmt.bind(1, size);
            stmt.bind(2, page * size);
        }

        CppSQLite3Query query = stmt.execQuery();
        while (!query.eof())
        {
            
            TEVIDENCEINFO evi;
            evi.cFileHash = query.getStringField("hash");
            evi.cFileName = query.getStringField("filename");
            evi.cCustomInfo = query.getStringField("custominfo");
            evi.cRightOwner = query.getStringField("owner");
            evi.iFileState = query.getIntField("filestate");
            evi.tRegisTime = query.getInt64Field("regtime");
            evi.iFileSize = query.getInt64Field("filesize");
			evi.iBlocknum = query.getInt64Field("blocknum"); 

            evidences.push_back(evi);

            query.nextRow();
        }
    }
    catch (CppSQLite3Exception& ex)
    {
		g_daily_logger->error("DB getEvidences; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getEvidences; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
        ret = ex.errorCode();
    }

    return ret;
}

int DBmgr::getNoConfiringList(std::list<TEVIDENCEINFO>& evidences)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql;
	
		sql = "SELECT * FROM evidence_tbl WHERE filestate!=? ORDER BY regtime DESC;";

		stmt = _db->compileStatement(sql.c_str());		
		stmt.bind(1, CONFIRMED);

	

		CppSQLite3Query query = stmt.execQuery();
		while (!query.eof())
		{
			
			TEVIDENCEINFO evi;
			evi.cFileHash = query.getStringField("hash");
			evi.cFileName = query.getStringField("filename");
			evi.cCustomInfo = query.getStringField("custominfo");
			evi.cRightOwner = query.getStringField("owner");
			evi.iFileState = query.getIntField("filestate");
			evi.tRegisTime = query.getInt64Field("regtime");
			evi.iFileSize = query.getInt64Field("filesize");
			evi.iBlocknum = query.getInt64Field("blocknum");

			evidences.push_back(evi);

			query.nextRow();
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getNoConfiringList; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getNoConfiringList; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;
}

int DBmgr::updateEvidence(const TEVIDENCEINFO &evidence, int type)
{
    try
    {
        
        std::string sql;
        if (1 == type){
            sql = "UPDATE evidence_tbl SET filestate=?"
                  "WHERE hash=?;";
        }
		else if (2 == type)
		{
			sql = "UPDATE evidence_tbl SET filestate=?"
				"WHERE hash=? And regtime=?;";
		}
		else if (3 == type)
		{
			sql = "UPDATE evidence_tbl SET filestate=?"
				"WHERE filestate=?;";
		}
		else if (4 == type)
		{
			sql = "UPDATE evidence_tbl SET filestate=?,blocknum=? "
				"WHERE hash=? And regtime=?;";
		}

        CppSQLite3Statement stmt = _db->compileStatement(sql.c_str());
        if (1 == type){
            stmt.bind(1,  evidence.iFileState);
            stmt.bind(2,  evidence.cFileHash.c_str());
        }
		else if (2 == type)
		{
			stmt.bind(1, evidence.iFileState);			
			stmt.bind(2, evidence.cFileHash.c_str());
			stmt.bind(3, (sqlite_int64)evidence.tRegisTime);
		}
		else if (3 == type)
		{
			stmt.bind(1, REJECTED);	
			stmt.bind(2, CONFIRMING);
		}
		else if (4 == type)
		{
			stmt.bind(1, evidence.iFileState);
			stmt.bind(2, (sqlite_int64)evidence.iBlocknum);
			stmt.bind(3, evidence.cFileHash.c_str());
			stmt.bind(4, (sqlite_int64)evidence.tRegisTime);
		}

        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex)
    {
		g_daily_logger->error("DB updateEvidence; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB updateEvidence; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
        return ex.errorCode();
    }

    return 0;
}

int DBmgr::delEvidence(std::string hash)
{
    try
    {
        CppSQLite3Statement stmt = _db->compileStatement("DELETE FROM evidence_tbl WHERE hash=?;");
        stmt.bind(1, hash.c_str());
        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex)
    {
		g_daily_logger->error("DB delEvidence-string; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB delEvidence-string; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
        return ex.errorCode();
    }

    return 0;
}

int DBmgr::delEvidence(const TEVIDENCEINFO &evidence)
{
	try
	{
		CppSQLite3Statement stmt = _db->compileStatement("DELETE FROM evidence_tbl WHERE hash=? And regtime=?;");
		stmt.bind(1, evidence.cFileHash.c_str());
		stmt.bind(2, (sqlite_int64)evidence.tRegisTime);
		stmt.execDML();
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB delEvidence; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB delEvidence; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		return ex.errorCode();
	}

	return 0;
}

int DBmgr::createTbls()
{
    _db->execDML(DBSQL::EVIDENCES_TBL.c_str());
	_db->execDML(DBSQL::HYPERBLOCK_TBL.c_str());
	_db->execDML(DBSQL::ONCHAINED_TBL.c_str());
	_db->execDML(DBSQL::UPQUEUE_TBL.c_str());
	_db->execDML(DBSQL::MYSELF_TBL.c_str());
	_db->execDML(DBSQL::NEIGHBORNODE_TBL.c_str());
    return 0;
}

int DBmgr::updateDB()
{
	
	if (ifTblOrIndexExist("hyperblock", 1)) {
		if (!ifColExist("hyperblock", "version")) {
			exec("alter table hyperblock ADD version varchar(32) NOT NULL default ''");
		}
		if (!ifColExist("hyperblock", "difficulty")) {
			exec("alter table hyperblock ADD difficulty integer default 0");
		}
	}
    return 0;
}


string DBmgr::hash256tostring(const unsigned char* hash)
{
	char szHash[512] = "";
	char ucBuf[10] = {0};

	unsigned int uiNum = 0;
	for(; uiNum < DEF_SHA256_LEN; uiNum ++)
	{
		memset(ucBuf, 0, 10);
		sprintf(ucBuf, "%02x", hash[uiNum]);
		strcat(szHash, ucBuf);	
	}
	string sHash = szHash;
	return sHash;

}

void DBmgr::strtohash256(unsigned char* out, const char* szHash)
{
	if (strlen(szHash) != DEF_SHA256_LEN * 2)
		return;
    int len = DEF_SHA256_LEN * 2;
    char str[DEF_SHA256_LEN * 2];
    memset(str, 0, len);
    memcpy(str, szHash, len);
    for (int i = 0; i < len; i+=2) {
        
        if(str[i] >= 'a' && str[i] <= 'f') str[i] = str[i] & ~0x20;
        if(str[i+1] >= 'a' && str[i] <= 'f') str[i+1] = str[i+1] & ~0x20;
        
        if(str[i] >= 'A' && str[i] <= 'F')
            out[i/2] = (str[i]-'A'+10)<<4;
        else
            out[i/2] = (str[i] & ~0x30)<<4;
        
        if(str[i+1] >= 'A' && str[i+1] <= 'F')
            out[i/2] |= (str[i+1]-'A'+10);
        else
            out[i/2] |= (str[i+1] & ~0x30);
    }
}

int DBmgr::insertHyperblock(const T_HYPERBLOCKDBINFO &hyperblock)
{
	try
	{
		if (existHyperblock(hyperblock)) {
			return updateHyperblock(hyperblock);
		}

		CppSQLite3Statement stmt = _db->compileStatement(scHyperblockInsert.c_str());

		stmt.bind(1, hash256tostring(hyperblock.strHashSelf).c_str());
		stmt.bind(2, (sqlite_int64)hyperblock.uiBlockId);
		stmt.bind(3, (sqlite_int64)hyperblock.ucBlockType);
		stmt.bind(4, (sqlite_int64)hyperblock.uiReferHyperBlockId);
		stmt.bind(5, hash256tostring(hyperblock.strHyperBlockHash).c_str());
		stmt.bind(6, hash256tostring(hyperblock.strPreHash).c_str());
		stmt.bind(7, hyperblock.strPayload.c_str());
		stmt.bind(8, (sqlite_int64)hyperblock.uiBlockTimeStamp);
		stmt.bind(9, (sqlite_int64)hyperblock.uiQueueID);
		stmt.bind(10, (sqlite_int64)hyperblock.uiLocalChainId);
		stmt.bind(11, hyperblock.strVersion.c_str());
		stmt.bind(12, (int)hyperblock.difficulty);

		stmt.execDML();
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB insertHyperblock; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB insertHyperblock; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		return ex.errorCode();
	}

	return 0;
}

int DBmgr::updateHyperblock(const T_HYPERBLOCKDBINFO &hyperblock)
{
	try
	{
		string sqlUpdate = "UPDATE hyperblock SET "
		"hash=?,"
		"id=?,"
		"type=?,"
		"hid=?,"
		"hhash=?,"
		"hash_prev=?,"
		"payload=?,"
		"ctime=?,"
		"version=?,"
		"queue_id=?,"
		"chain_num=?"
		" WHERE hid=? and type=? and id=?;";
		
		CppSQLite3Statement stmt = _db->compileStatement(sqlUpdate.c_str());
		stmt.bind(1, hash256tostring(hyperblock.strHashSelf).c_str());
		stmt.bind(2, (sqlite_int64)hyperblock.uiBlockId);
		stmt.bind(3, (sqlite_int64)hyperblock.ucBlockType);
		stmt.bind(4, (sqlite_int64)hyperblock.uiReferHyperBlockId);
		stmt.bind(5, hash256tostring(hyperblock.strHyperBlockHash).c_str());
		stmt.bind(6, hash256tostring(hyperblock.strPreHash).c_str());
		stmt.bind(7, hyperblock.strPayload.c_str());
		stmt.bind(8, (sqlite_int64)hyperblock.uiBlockTimeStamp);
		stmt.bind(9, hyperblock.strVersion.c_str());
		stmt.bind(10, (sqlite_int64)hyperblock.uiQueueID);
		stmt.bind(11, (sqlite_int64)hyperblock.uiLocalChainId);
		stmt.bind(12, (sqlite_int64)hyperblock.uiReferHyperBlockId);
		stmt.bind(13, (sqlite_int64)hyperblock.ucBlockType);
		stmt.bind(14, (sqlite_int64)hyperblock.uiBlockId);
		stmt.execDML();
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB updateHyperblock; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB updateHyperblock; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		return ex.errorCode();
	}

	return 0;
}

int DBmgr::existHyperblock(const T_HYPERBLOCKDBINFO &hyperblock)
{
	int ret = 0;
	try {
		CppSQLite3Statement stmt;
		std::string sql = "SELECT * FROM hyperblock where hid=? and type=? and id=? and chain_num=?;";

		stmt = _db->compileStatement(sql.c_str());
		stmt.bind(1, (sqlite_int64)hyperblock.uiReferHyperBlockId);
		stmt.bind(2, (sqlite_int64)hyperblock.ucBlockType);
		stmt.bind(3, (sqlite_int64)hyperblock.uiBlockId);
		stmt.bind(4, (sqlite_int64)hyperblock.uiLocalChainId);

		CppSQLite3Query query = stmt.execQuery();
		if (!query.eof()) {
			return 1;
		}
	}
	catch (CppSQLite3Exception& ex) {
		g_daily_logger->error("DB existHyperblock; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB existHyperblock; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}
	return ret;
}

int DBmgr::getLocalblock(T_HYPERBLOCKDBINFO &info, int hid, int id, int chain_num)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql = "SELECT * FROM hyperblock WHERE hid=? AND id=? AND chain_num=?;";

		stmt = _db->compileStatement(sql.c_str());

		stmt.bind(1, hid);
		stmt.bind(2, id);
		stmt.bind(3, chain_num);

		CppSQLite3Query query = stmt.execQuery();
		if (!query.eof())
		{
			strtohash256(info.strHashSelf, query.getStringField("hash"));

			info.uiBlockId = query.getIntField("id");
			info.ucBlockType = query.getIntField("type");
			info.uiReferHyperBlockId = query.getIntField("hid");
			strtohash256(info.strHyperBlockHash, query.getStringField("hhash"));
			strtohash256(info.strPreHash, query.getStringField("hash_prev"));
			info.strPayload = query.getStringField("payload");
			info.uiBlockTimeStamp = query.getIntField("ctime");
			info.strVersion = query.getStringField("version");
			info.uiQueueID = query.getIntField("queue_id");
			info.uiLocalChainId = query.getIntField("chain_num");
			info.difficulty = query.getIntField("difficulty");

			query.nextRow();
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getLocalblocks; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getLocalblocks; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;
}

int DBmgr::getLocalchain(int hid, int chain_num, int &blocks, int &chain_difficulty)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql = "SELECT count(*) as blocks, sum(difficulty) as chain_difficulty FROM hyperblock WHERE hid=? AND chain_num=?;";

		stmt = _db->compileStatement(sql.c_str());

		stmt.bind(1, hid);
		stmt.bind(2, chain_num);

		CppSQLite3Query query = stmt.execQuery();
		if (!query.eof())
		{
			blocks = query.getIntField("blocks");
			if (blocks == 0)
				return -1;

			chain_difficulty = query.getIntField("chain_difficulty");
		
			query.nextRow();

		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getLocalchain; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getLocalchain; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;
}

int DBmgr::getHyperblock(std::list<T_HYPERBLOCKDBINFO> &queue, int page, int size)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql;
		if (page == -1){
			sql = "SELECT * FROM hyperblock";
		}
		else{
			sql = "SELECT * FROM hyperblock LIMIT ? OFFSET ?;";
		}

		stmt = _db->compileStatement(sql.c_str());

		if (page != -1){
			stmt.bind(1, size);
			stmt.bind(2, page * size);
		}

		CppSQLite3Query query = stmt.execQuery();
		while (!query.eof())
		{
			T_HYPERBLOCKDBINFO info;
			strtohash256(info.strHashSelf, query.getStringField("hash"));
			info.uiBlockId = query.getIntField("id");
			info.ucBlockType = query.getIntField("type");
			info.uiReferHyperBlockId = query.getIntField("hid");
			strtohash256(info.strHyperBlockHash, query.getStringField("hhash"));
			strtohash256(info.strPreHash, query.getStringField("hash_prev"));
			info.strPayload = query.getStringField("payload");
			info.uiBlockTimeStamp = query.getIntField("ctime");
			info.strVersion = query.getStringField("version");
			info.uiQueueID = query.getIntField("queue_id");
			info.uiLocalChainId = query.getIntField("chain_num");

			queue.push_back(info);
			query.nextRow();
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getHyperblock; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getHyperblock; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;
}

int DBmgr::getHyperblocks(std::list<T_HYPERBLOCKDBINFO> &queue, int nStartHyperID, int nEndHyperID)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql = "SELECT * FROM hyperblock WHERE hid>=? AND hid<=? ORDER BY hid;";

		stmt = _db->compileStatement(sql.c_str());

		stmt.bind(1, nStartHyperID);
		stmt.bind(2, nEndHyperID);

		CppSQLite3Query query = stmt.execQuery();
		while (!query.eof())
		{
			T_HYPERBLOCKDBINFO info;
			strtohash256(info.strHashSelf, query.getStringField("hash"));

			info.uiBlockId = query.getIntField("id");
			info.ucBlockType = query.getIntField("type");
			info.uiReferHyperBlockId = query.getIntField("hid");
			strtohash256(info.strHyperBlockHash, query.getStringField("hhash"));
			strtohash256(info.strPreHash, query.getStringField("hash_prev"));
			info.strPayload = query.getStringField("payload");
			info.uiBlockTimeStamp = query.getIntField("ctime");			
			info.strVersion = query.getStringField("version");
			info.uiQueueID = query.getIntField("queue_id");
			info.uiLocalChainId = query.getIntField("chain_num");
			info.difficulty = query.getIntField("difficulty");
			
			queue.push_back(info);
			query.nextRow();
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getHyperblocks; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getHyperblocks; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;
}

int DBmgr::getAllHyperblockNumInfo(std::list<uint64> &queue)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql = "SELECT id FROM hyperblock WHERE type=1 ORDER BY hid;";

		stmt = _db->compileStatement(sql.c_str());

		CppSQLite3Query query = stmt.execQuery();
		while (!query.eof())
		{
			uint64 num = query.getIntField(0);
			queue.push_back(num);
			query.nextRow();
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getAllHyperblockNumInfo; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getAllHyperblockNumInfo; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;
}

int DBmgr::getHyperblockshead(T_HYPERBLOCKDBINFO &info, int nStartHyperID)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql = "SELECT * FROM hyperblock WHERE hid=? AND type=1 ORDER BY hid;";

		stmt = _db->compileStatement(sql.c_str());

		stmt.bind(1, nStartHyperID);

		CppSQLite3Query query = stmt.execQuery();
		while (!query.eof())
		{
			strtohash256(info.strHashSelf, query.getStringField("hash"));

			info.uiBlockId = query.getIntField("id");
			info.ucBlockType = query.getIntField("type");
			info.uiReferHyperBlockId = query.getIntField("hid");

			strtohash256(info.strHyperBlockHash, query.getStringField("hhash"));
			strtohash256(info.strPreHash, query.getStringField("hash_prev"));

			info.strPayload = query.getStringField("payload");
			info.uiBlockTimeStamp = query.getIntField("ctime");
			info.uiLocalChainId = query.getIntField("chain_num");
			info.strVersion = query.getStringField("version");

			query.nextRow();
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getHyperblockshead; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getHyperblockshead; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;

}

int DBmgr::getLocalblocksPayload(std::list<string> &queue, int nStartHyperID)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql = "SELECT payload FROM hyperblock WHERE hid=? AND type=2 ORDER BY hid;";

		stmt = _db->compileStatement(sql.c_str());

		stmt.bind(1, nStartHyperID);

		CppSQLite3Query query = stmt.execQuery();
		while (!query.eof())
		{
			string payload = query.getStringField(0);
			queue.push_back(payload);
			query.nextRow();			
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getLocalblocksPayload; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getLocalblocksPayload; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;

}

int DBmgr::delUpqueue(std::string hash)
{
	try
	{
		CppSQLite3Statement stmt = _db->compileStatement("DELETE FROM upqueue WHERE hash=?;");
		stmt.bind(1, hash.c_str());
		stmt.execDML();
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB delUpqueue; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB delUpqueue; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		return ex.errorCode();
	}

	return 0;
}

int DBmgr::addUpqueue(string sHash)
{

	try
	{
		uint64_t uiTime = time(NULL);
		CppSQLite3Statement stmt = _db->compileStatement(scUpqueueInsert.c_str());
		stmt.bind(1, sHash.c_str());
		stmt.bind(2, (sqlite_int64)uiTime);
		stmt.execDML();
		return sqlite3_last_insert_rowid(_db->getDB());
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB addUpqueue; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB addUpqueue; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		return ex.errorCode();
	}

	return 0;


}

int DBmgr::getUpqueue(std::list<TUPQUEUE> &queue, int page, int size)
{
	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql;
		if (page == -1){
			sql = "SELECT * FROM upqueue";
		}
		else{
			sql = "SELECT * FROM upqueue LIMIT ? OFFSET ?;";
		}

		stmt = _db->compileStatement(sql.c_str());

		if (page != -1){
			stmt.bind(1, size);
			stmt.bind(2, page * size);
		}

		CppSQLite3Query query = stmt.execQuery();
		while (!query.eof())
		{
			
			TUPQUEUE evi;
			evi.uiID = query.getIntField("id");
			evi.strHash = query.getStringField("hash");
			evi.uiTime = query.getInt64Field("ctime");

			queue.push_back(evi);

			query.nextRow();
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getUpqueue; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getUpqueue; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;
}

int DBmgr::getLatestHyperBlockNo()
{

	int ret = 0;

	try
	{
		CppSQLite3Statement stmt;
		std::string sql = "SELECT max(hid) as hid FROM hyperblock";

		stmt = _db->compileStatement(sql.c_str());

		CppSQLite3Query query = stmt.execQuery();
		if (!query.eof())
		{
			return query.getIntField("hid");
		}
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB getLatestHyperBlockNo; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB getLatestHyperBlockNo; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		ret = ex.errorCode();
	}

	return ret;

}

int DBmgr::updateOnChainState(const string &requestid, const T_LOCALBLOCKADDRESS& address)
{
	try {
		exec("insert or replace into localblockonchained(requestid,hid,chain_num,id) values(?,?,?,?)",
			requestid.c_str(),
			(sqlite_int64)address.hid,
			(sqlite_int64)address.chainnum,
			(sqlite_int64)address.id);

	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB updateOnChainState; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB updateOnChainState; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		return ex.errorCode();
	}

	return 0;
}

int DBmgr::removeOnChainState(uint64 hid)
{
	try {
		exec("delete from localblockonchained where hid = ?", (sqlite_int64)hid);
	}
	catch (CppSQLite3Exception& ex)
	{
		g_daily_logger->error("DB removeOnChainState; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		g_console_logger->error("DB removeOnChainState; error = {}, Message  = {}", ex.errorCode(), ex.errorMessage());
		return ex.errorCode();
	}

	return 0;
}


T_LOCALBLOCKADDRESS DBmgr::getOnChainStateFromRequestID(const string &requestid)
{	
	T_LOCALBLOCKADDRESS addr;
	query("SELECT hid,chain_num,id FROM localblockonchained WHERE requestid = ? ; ",
		[this, &addr](CppSQLite3Query & q) {
		addr.hid = q.getIntField("hid");
		addr.chainnum = q.getIntField("chain_num");
		addr.id = q.getIntField("id");
	}, requestid.c_str());

	return addr;
}

bool DBmgr::isBlockExisted(string &strblockhash)
{
	int num = 0;
	query("SELECT count(*) as num FROM hyperblock WHERE hash = ? ; ",
		[this, &num](CppSQLite3Query & q) {
			num = q.getIntField("num");
		}, 
		strblockhash.c_str());

	return num != 0;
}