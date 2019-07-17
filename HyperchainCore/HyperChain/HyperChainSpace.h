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
	void GetHyperChainData(map<uint64, set<string>>& out_HyperChainData);
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

	string m_mynodeid;						//HC: 本节点kadid	
	list<uint64> m_localhpidlist;			//HC: 本地超块ID
	vector <string> m_hyperidlistcompressed;//HC: 本地超块ID 网络发送文本格式 "ID-ID"
	map<uint64, set<string>> m_hpspacedata;	//HC: 链空间 <HyperID, <nodeID>>
	map<string, string> m_hpspaceshow;		//HC: <nodeID, HyperID Section(0;6667-6677;6679-6690;)>
	mutex m_datalock;
	mutex m_showlock;
	mutex m_listlock;

	unique_ptr<thread> m_threadpull;
	bool m_bpull;
};