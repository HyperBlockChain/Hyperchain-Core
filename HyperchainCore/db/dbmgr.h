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
#pragma once

#include "headers/inter_public.h"

#include <thread>
#include <mutex>


#include <map>
#include <functional>

#include "util/cppsqlite3.h"


class CppSQLite3DB;

class DBmgr
{
public:
    static DBmgr* instance();

    virtual ~DBmgr();

    int open(const char * dbpath);
    bool isOpen();
    int close();

public:
    int insertEvidence(const TEVIDENCEINFO& evidence);
    int getEvidences(std::list<TEVIDENCEINFO>& evidences, int page, int size = 20);
    int updateEvidence(const TEVIDENCEINFO& evidence, int type = 1);
	int getNoConfiringList(std::list<TEVIDENCEINFO>& evidences);
    int delEvidence(std::string hash);
	int delEvidence(const TEVIDENCEINFO &evidence);
	int insertHyperblock(const T_HYPERBLOCKDBINFO &hyperblock);
	int updateHyperblock(const T_HYPERBLOCKDBINFO &hyperblock);
	int existHyperblock(const T_HYPERBLOCKDBINFO &hyperblock);
	int getHyperblock(std::list<T_HYPERBLOCKDBINFO> &list, int page, int size);
	int getHyperblockshead(std::list<T_HYPERBLOCKDBINFO> &queue, int nStartHyperID);
	int getAllHyperblockNumInfo(std::list<uint64> &queue);
	int getHyperblocks(std::list<T_HYPERBLOCKDBINFO> &queue, int nStartHyperID, int nEndHyperID);
    int getUpqueue(std::list<TUPQUEUE> &queue, int page, int size);
	int delUpqueue(std::string hash);
	int addUpqueue(string sHash);

	int findverinhyperblock();
	int updatahyperblockaddver();

	int getLatestHyperBlockNo();
	int getLatestHyperBlock(T_HYPERBLOCKDBINFO &hyperblock);
	int getOnChainStateFromHashTime(string strlocalhash, uint64 time);
	bool isBlockExisted(string &strblockhash);
	string hash256tostring(const unsigned char* hash);
	void strtohash256(unsigned char* hash, const char* szHash);


	void bindParam(CppSQLite3Statement &stmt, int i)
	{}

	template<typename T, typename... Args>
	void bindParam(CppSQLite3Statement &stmt, int i, T && first, Args&&... args)
	{
		stmt.bind(i, first);
		bindParam(stmt, ++i, std::forward<Args>(args)...);
	}

	template<typename... Args>
	void query(const string & sql,std::function<void(CppSQLite3Query&)> f,  Args... args)
	{
		try {
			CppSQLite3Statement stmt;
			stmt = _db->compileStatement(sql.c_str());
			bindParam(stmt,1,args...);

			CppSQLite3Query query = stmt.execQuery();
			while (!query.eof()) {
				f(query);
				query.nextRow();
			}
		}
		catch (CppSQLite3Exception& ex) {
			throw std::runtime_error(ex.errorMessage());
		}
	}

	template<typename... Args>
	void exec(const string & sql, Args... args)
	{
		try {
			CppSQLite3Statement stmt;
			stmt = _db->compileStatement(sql.c_str());
			bindParam(stmt, 1, args...);
			stmt.execDML();
		}
		catch (CppSQLite3Exception& ex) {
			throw std::runtime_error(ex.errorMessage());
		}
	}

private:
    DBmgr();

private:
    int createTbls();

private:
    int updateDB();

private:
    bool ifColExist(const char* tbl, const char* col);
    //type 1:tbl 2:index
    bool ifTblOrIndexExist(const char* name, int type = 1);

private:
    CppSQLite3DB *_db;
    std::mutex _mutex;
};
