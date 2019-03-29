/*Copyright 2016-2019 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this?
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,?
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <list>
#include <map>
#include <set>
#include <thread>
#ifdef WIN32
#include <windows.h> 
#endif // WIN32
#include <mutex>
#include "../Types.h"
using namespace std;
using std::chrono::system_clock;

typedef map<string, system_clock::time_point> MAP_NODE;
typedef map<uint64, MAP_NODE> MULTI_MAP_HPSPACEDATA;

class CHyperChainSpace
{
public:	
	CHyperChainSpace(string nodeid);
	~CHyperChainSpace();

	void start();
	void stop() {
		m_bpull = false;
		if (m_threadpull->joinable())
			m_threadpull->join();
	}
	void GetHyperChainData(MULTI_MAP_HPSPACEDATA & out_HyperChainData);
	void GetHyperChainShow(map<string, string>& out_HyperChainShow);
	void GetLocalChainShow(vector<string> & out_LocalChainShow);
	int GetLocalChainIDList(list<uint64> & out_LocalIDList);
	size_t GetLocalChainIDSize() { return m_localhpidlist.size(); }
	uint64 GetGlobalLatestHyperBlockNo();
	int GetRemoteHyperBlockByID(uint64 globalHID);
	void UpdataChainIDList();


	uint64 PullDataFromChainSpace();

	bool PullChainSpaceRspTaskEXC(string & mes);
	void PullChainSpaceRspTaskRSP(string  mes, string nodeid);
		
private:
	void PullDataThread();
	int GetChainIDListFormLocal();
	bool FindIDExistInChainIDList(uint64 id);
	
	void AnalyticalChainData(string strbuf, string nodeid);
	void SplitString(const string& s, vector<std::string>& v, const std::string& c);

private:

	string m_mynodeid;							
	list<uint64> m_localhpidlist;			
	vector <string> m_hyperidlistcompressed;
	MULTI_MAP_HPSPACEDATA m_hpspacedata;	
	map<string, string> m_hpspaceshow;		
	mutex m_datalock;
	mutex m_showlock;
	mutex m_listlock;

	unique_ptr<thread> m_threadpull;
	bool m_bpull;
};