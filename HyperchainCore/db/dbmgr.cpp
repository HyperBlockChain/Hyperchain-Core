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

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#define DBERROR(ex) dbError(__FUNCTION__, __LINE__, ex)

namespace DBSQL {

    //
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
        "  [id] INTEGER DEFAULT 0,"
        "  [hash_prev] char(64) NOT NULL DEFAULT '',"
        "  [header] blob DEFAULT '' NOT NULL,"
        "  [body] blob DEFAULT '' NOT NULL,"
        "  PRIMARY KEY (id, hash_prev)"
        ");";


    const std::string LOCALBLOCK_TBL =
        "CREATE TABLE IF NOT EXISTS localblock ("
        "  [id] INTEGER DEFAULT 0,"
        "  [hid] INTEGER DEFAULT 0,"
        "  [chain_num] INTEGER DEFAULT 0,"
        //"  [hash_prev] char(64) NOT NULL DEFAULT '',"
        //"  [hhash_prev] char(64) NOT NULL DEFAULT '',"
        "  [header] blob DEFAULT '' NOT NULL,"
        "  [body] blob DEFAULT '' NOT NULL,"
        "  [payloadMTree] blob DEFAULT '' NOT NULL,"
        "  PRIMARY KEY (hid,chain_num,id)"
        ");";

    const std::string ONCHAINED_TBL =
        "CREATE TABLE IF NOT EXISTS localblockonchained ("
        "  [requestid]	varchar(32) DEFAULT ''," //
        "  [hid]		INTEGER DEFAULT 0,"
        "  [chain_num]	INTEGER DEFAULT 0,"
        "  [id]	INTEGER DEFAULT 0,"			//
        "  PRIMARY KEY (requestid)"
        ");";

    const std::string HASHINFO_TBL =
        "CREATE TABLE IF NOT EXISTS hyperblockhashinfo ("
        "  [id]		    INTEGER DEFAULT 0,"
        "  [headerhash]	char(64) NOT NULL DEFAULT '',"
        "  [hash]	    char(64) NOT NULL DEFAULT '',"
        "  PRIMARY KEY (id)"
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
        "  [accesspoint] TEXT NOT NULL DEFAULT '',"
        "  [lasttime] INTEGER DEFAULT 0"
        ");";
}




////////////////////////////////////////////////////
static const std::string scEvidenceInsert = "INSERT OR REPLACE INTO evidence_tbl(hash,blocknum,filename,custominfo,owner,filestate,regtime,filesize,extra) "
"VALUES(?,?,?,?,?,?,?,?,?);";
////////////////////////////////////////////////////
static const std::string scUpqueueInsert = "INSERT OR REPLACE INTO upqueue(hash,ctime) "
"VALUES(?,?);";
////////////////////////////////////////////////////

static const std::string scGetNeighbors = "SELECT * FROM neighbornodes";
////////////////////////////////////////////////////

DBmgr::DBmgr() {

}

DBmgr::~DBmgr()
{
    if (_db) {
        if (_db->isOpen()) {
            _db->close();
        }
        delete _db;
        _db = nullptr;
    }
}

int DBmgr::open(const char *dbpath)
{
    int ecode = 0;
    try {
        if (_db) {
            if (_db->isOpen()) {
                _db->close();
            }
        }

        if (!_db) {
            _db = new CppSQLite3DB();
        }

        _db->open(dbpath);

#ifndef _DEBUG
        //int result = sqlite3_key(_db->getDB(), "123456!@#$%^", 12);
#endif
        createTbls();

        updateDB();
    }
    catch (CppSQLite3Exception& sqliteException) {
        return DBERROR(sqliteException);
    }
    catch (...) {
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

    try {
        _db->close();
    }
    catch (CppSQLite3Exception& sqliteException) {
        ecode = sqliteException.errorCode();
    }
    catch (...) {
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

    try {
        std::string sql;
        if (1 == type) {
            sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?";
        }
        else {
            sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name = ?";
        }

        CppSQLite3Statement stmt = _db->compileStatement(sql.c_str());
        stmt.bind(1, name);

        CppSQLite3Query query = stmt.execQuery();
        if (!query.eof()) {
            exist = query.getIntField(0);
        }
    }
    catch (...) {
        exist = 0;
    }

    return exist > 0;
}

int DBmgr::insertEvidence(const TEVIDENCEINFO &evidence)
{
    try
    {
        //
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
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
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
        if (page == -1) {
            sql = "SELECT * FROM evidence_tbl ORDER BY regtime DESC;";
        }
        else {
            sql = "SELECT * FROM evidence_tbl ORDER BY regtime DESC LIMIT ? OFFSET ?;";
        }

        stmt = _db->compileStatement(sql.c_str());

        if (page != -1) {
            stmt.bind(1, size);
            stmt.bind(2, page * size);
        }

        CppSQLite3Query query = stmt.execQuery();
        while (!query.eof())
        {
            //
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
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
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
            //
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
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::updateEvidence(const TEVIDENCEINFO &evidence, int type)
{
    try {
        //
        std::string sql;
        if (1 == type) {
            sql = "UPDATE evidence_tbl SET filestate=?"
                "WHERE hash=?;";
        }
        else if (2 == type) {
            sql = "UPDATE evidence_tbl SET filestate=?"
                "WHERE hash=? And regtime=?;";
        }
        else if (3 == type) {
            sql = "UPDATE evidence_tbl SET filestate=?"
                "WHERE filestate=?;";
        }
        else if (4 == type) {
            sql = "UPDATE evidence_tbl SET filestate=?,blocknum=? "
                "WHERE hash=? And regtime=?;";
        }

        CppSQLite3Statement stmt = _db->compileStatement(sql.c_str());
        if (1 == type) {
            stmt.bind(1, evidence.iFileState);
            stmt.bind(2, evidence.cFileHash.c_str());
        }
        else if (2 == type) {
            stmt.bind(1, evidence.iFileState);
            stmt.bind(2, evidence.cFileHash.c_str());
            stmt.bind(3, (sqlite_int64)evidence.tRegisTime);
        }
        else if (3 == type) {
            stmt.bind(1, REJECTED);
            stmt.bind(2, CONFIRMING);
        }
        else if (4 == type) {
            stmt.bind(1, evidence.iFileState);
            stmt.bind(2, (sqlite_int64)evidence.iBlocknum);
            stmt.bind(3, evidence.cFileHash.c_str());
            stmt.bind(4, (sqlite_int64)evidence.tRegisTime);
        }

        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::delEvidence(std::string hash)
{
    try {
        CppSQLite3Statement stmt = _db->compileStatement("DELETE FROM evidence_tbl WHERE hash=?;");
        stmt.bind(1, hash.c_str());
        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
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
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::createTbls()
{
    _db->execDML(DBSQL::EVIDENCES_TBL.c_str());
    _db->execDML(DBSQL::HYPERBLOCK_TBL.c_str());
    _db->execDML(DBSQL::LOCALBLOCK_TBL.c_str());
    _db->execDML(DBSQL::ONCHAINED_TBL.c_str());
    _db->execDML(DBSQL::HASHINFO_TBL.c_str());
    _db->execDML(DBSQL::UPQUEUE_TBL.c_str());
    _db->execDML(DBSQL::MYSELF_TBL.c_str());
    _db->execDML(DBSQL::NEIGHBORNODE_TBL.c_str());
    return 0;
}

int DBmgr::updateDB()
{
    //
    //TO DO in the future
    if (ifTblOrIndexExist("neighbornodes", 1)) {
        if (!ifColExist("neighbornodes", "lasttime")) {
            exec("alter table neighbornodes ADD lasttime integer default 0");
        }
    }
    return 0;
}

int DBmgr::deleteHyperblockAndLocalblock(uint64 hid)
{
    try {
        exec("DELETE FROM hyperblock WHERE id=?", static_cast<sqlite_int64>(hid));
        exec("DELETE FROM localblock WHERE hid=?", static_cast<sqlite_int64>(hid));
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::insertHyperblock(const T_HYPERBLOCK& hyperblock)
{
    try {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << hyperblock.header;
        string header = ssBuf.str();

        ssBuf.str("");
        oa << hyperblock.body;
        string body = ssBuf.str();

        exec("insert or replace into hyperblock(id,hash_prev,header,body) values(?,?,?,?)",
            hyperblock.GetID(),
            hyperblock.GetPreHash().toHexString(),
            header, body);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::updateHyperblock(const T_HYPERBLOCK& hyperblock)
{
    return insertHyperblock(hyperblock);
}

int DBmgr::insertLocalblock(const T_LOCALBLOCK& localblock, uint64 hid, uint16 chainnum)
{
    try {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << localblock.header;
        string header = ssBuf.str();

        ssBuf.str("");
        oa << localblock.body;
        string body = ssBuf.str();

        ssBuf.str("");
		uint32 payloadnum = static_cast<uint32>(localblock.payloadMTree.size());
		oa << payloadnum;
		oa << boost::serialization::make_array(localblock.payloadMTree.data(), payloadnum);
        string mt = ssBuf.str();
        exec("insert or replace into localblock(id,hid,chain_num,header,body,payloadMTree) values(?,?,?,?,?,?)",
            localblock.GetID(), hid, chainnum,
            header, body, mt);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}


int DBmgr::getLocalblock(T_LOCALBLOCK& localblock, uint64 hid, uint16 id, uint16 chain_num)
{
    int ret = -1;
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM localblock WHERE hid=? AND id=? AND chain_num=?;", [&localblock, &ret, hid](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            localblock.SetChainNum(q.getIntField("chain_num"));
            localblock.SetPreHID(hid - 1);
            try {
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> localblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> localblock.body;
                ret = 0;
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
            }
        }, hid, id, chain_num);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::getLocalchain(uint64 hid, int chain_num, int &blocks, int &chain_difficulty)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT count(*) as blocks FROM localblock WHERE hid=? AND chain_num=?;",
            [&blocks](CppSQLite3Query & q) {
                blocks = q.getIntField("blocks");
            }, hid, chain_num);
        //TO DO: how to compute chain_difficulty?
        chain_difficulty = blocks;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getLocalBlocks(std::list<T_LOCALBLOCK> &queue, uint64 nHyperID)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM localblock WHERE hid=? order by chain_num;", [&queue, nHyperID](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                T_LOCALBLOCK localblock;
                localblock.SetChainNum(q.getIntField("chain_num"));
                localblock.SetPreHID(nHyperID - 1);
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> localblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> localblock.body;
                queue.emplace_back(localblock);
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
            }
            catch (std::exception& e) {
                g_consensus_console_logger->error("{}", e.what());
            }
            catch (...) {
                g_consensus_console_logger->error("unknown exception occurs");
            }
        }, nHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getHyperBlock(T_HYPERBLOCK &h, const T_SHA256 &hhash)
{

    try {
        CppSQLite3Statement stmt;
        query("select * from hyperblock where id = (SELECT id FROM hyperblock WHERE hash_prev=?);", [&h](CppSQLite3Query & q) {
            stringstream ssBuf;
            int len = 0;
            try {
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
                ia >> h.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> h.body;
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
            }
        }, hhash.toHexString());
        return 0;
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return -1;
}

int DBmgr::getHyperBlocks(std::list<T_HYPERBLOCK> &queue, uint64 nStartHyperID, uint64 nEndHyperID)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM hyperblock WHERE id>=? AND id<=? order by id;", [&queue](CppSQLite3Query & q) {
            stringstream ssBuf;
            int len = 0;
            try {
                T_HYPERBLOCK hyperblock;
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
                ia >> hyperblock.header;

                len = 0;
                p = q.getBlobField("body", len);
                ssBuf.clear();
                ssBuf.str(string((char*)p, len));
                ia >> hyperblock.body;

                queue.emplace_back(hyperblock);
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
            }
        }, nStartHyperID, nEndHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getAllHyperblockNumInfo(std::set<uint64> &queue)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT id FROM hyperblock ORDER BY id;",
            [&queue](CppSQLite3Query & q) {
            queue.insert(q.getInt64Field("id"));
        });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getHyperblockshead(T_HYPERBLOCKHEADER& header, uint64 nStartHyperID)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM hyperblock WHERE id=?;",
            [&header](CppSQLite3Query & q) {
            stringstream ssBuf;
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            int len = 0;
            try {
                T_HYPERBLOCK hyperblock;
                const unsigned char * p = q.getBlobField("header", len);
                ssBuf.str(string((char*)p, len));
                ia >> header;
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
            }
        }, nStartHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::getLocalblocksPayloadTotalSize(uint64 nStartHyperID, size_t& size)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT sum(length(hex(body))) as s FROM localblock WHERE hid=?;",
            [&size](CppSQLite3Query & q) {
            size = static_cast<size_t>(q.getInt64Field("s"));
        },nStartHyperID);
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::delUpqueue(std::string hash)
{
    try {
        CppSQLite3Statement stmt = _db->compileStatement("DELETE FROM upqueue WHERE hash=?;");
        stmt.bind(1, hash.c_str());
        stmt.execDML();
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int64 DBmgr::addUpqueue(string sHash)
{
    try {
        uint64_t uiTime = time(NULL);
        CppSQLite3Statement stmt = _db->compileStatement(scUpqueueInsert.c_str());
        stmt.bind(1, sHash.c_str());
        stmt.bind(2, (sqlite_int64)uiTime);
        stmt.execDML();
        return sqlite3_last_insert_rowid(_db->getDB());
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::getUpqueue(std::list<TUPQUEUE> &queue, int page, int size)
{
    int ret = 0;

    try {
        CppSQLite3Statement stmt;
        std::string sql;
        if (page == -1) {
            sql = "SELECT * FROM upqueue";
        }
        else {
            sql = "SELECT * FROM upqueue LIMIT ? OFFSET ?;";
        }

        stmt = _db->compileStatement(sql.c_str());

        if (page != -1) {
            stmt.bind(1, size);
            stmt.bind(2, page * size);
        }

        CppSQLite3Query query = stmt.execQuery();
        while (!query.eof()) {
            //
            TUPQUEUE evi;
            evi.uiID = query.getIntField("id");
            evi.strHash = query.getStringField("hash");
            evi.uiTime = query.getInt64Field("ctime");

            queue.push_back(evi);

            query.nextRow();
        }
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::getLatestHyperBlockNo()
{
    int ret = 0;
    try {
        CppSQLite3Statement stmt;
        std::string sql = "SELECT max(id) as hid FROM hyperblock";

        stmt = _db->compileStatement(sql.c_str());

        CppSQLite3Query query = stmt.execQuery();
        if (!query.eof()) {
            return query.getIntField("hid");
        }
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return ret;
}

int DBmgr::getAllHashInfo(std::map<uint64, T_SHA256> &hashmap, std::map<uint64, T_SHA256> &headerhashmap)
{
    try {
        CppSQLite3Statement stmt;
        query("SELECT * FROM hyperblockhashinfo ORDER BY id;",
            [&hashmap, &headerhashmap](CppSQLite3Query & q) {
            headerhashmap[q.getInt64Field("id")] = CCommonStruct::StrToHash256(string(q.getStringField("headerhash")));
            hashmap[q.getInt64Field("id")] = CCommonStruct::StrToHash256(string(q.getStringField("hash")));
        });
    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }
    return 0;
}

int DBmgr::updateHashInfo(const uint64 hid, const T_SHA256 headerhash, const T_SHA256 hash)
{
    try {
        exec("insert or replace into hyperblockhashinfo(id,headerhash,hash) values(?,?,?)",
            hid,
            headerhash.toHexString().c_str(),
            hash.toHexString().c_str());

    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

int DBmgr::updateOnChainState(const string &requestid, const T_LOCALBLOCKADDRESS& address)
{
    try {
        exec("insert or replace into localblockonchained(requestid,hid,chain_num,id) values(?,?,?,?)",
            requestid.c_str(),
            address.hid,
            address.chainnum,
            address.id);

    }
    catch (CppSQLite3Exception& ex) {
        return DBERROR(ex);
    }

    return 0;
}

void DBmgr::initOnChainState(uint64 hid)
{
    try {
        exec("update localblockonchained set hid=-1,chain_num=-1,id=-1 where hid=?", hid);
    }
    catch (CppSQLite3Exception& ex) {
        DBERROR(ex);
    }
}

bool DBmgr::getOnChainStateFromRequestID(const string &requestid, T_LOCALBLOCKADDRESS &addr)
{
    bool isfound = false;
    addr.hid = -1;
    query("SELECT hid,chain_num,id FROM localblockonchained WHERE requestid = ? ; ",
        [this, &addr, &isfound](CppSQLite3Query & q) {
        addr.hid = q.getIntField("hid");
        addr.chainnum = q.getIntField("chain_num");
        addr.id = q.getIntField("id");
        isfound = true;
    }, requestid.c_str());

    return isfound;
}

bool DBmgr::isBlockExisted(uint64 hid)
{
    int num = 0;
    query("SELECT count(*) as num FROM hyperblock WHERE id = ? ; ",
        [this, &num](CppSQLite3Query & q) {
        num = q.getIntField("num");
    },
        hid);

    return num != 0;
}

int DBmgr::dbError(const char * funcname, int line, CppSQLite3Exception& ex)
{
    char errbuf[64] = { 0 };
    std::snprintf(errbuf, 64, "Exception in %s(%d): (%d)%s", funcname,
                    line,
                    ex.errorCode(),
                    ex.errorMessage());
    g_daily_logger->error(errbuf);
    g_console_logger->error(errbuf);

    return ex.errorCode();
}