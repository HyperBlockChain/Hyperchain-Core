/*Copyright 2016-2018 hyperchain.net (Hyperchain)

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
#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <thread>
#ifdef WIN32
#include <windows.h> 
#endif 
#include <mutex>
#include "../Types.h"
using namespace std;

#define PULLTIMER (3*60*1000)


class CHyperChainSpace
{
public:	
	CHyperChainSpace(string nodeid);
	~CHyperChainSpace();
	void GetHyperChainData(map<uint64, set<string>>& out_HyperChainData);
	int GetLocalChainIDList(list<uint64> & out_LocalIDList);
	void UpdataChainIDList();


	uint64 PullDataFromChainSpace();

	bool PullChainSpaceRspTaskEXC(string & mes);
	void PullChainSpaceRspTaskRSP(string  mes, string nodeid);
		
private:
	void Init();
	void PullDataThread();
	int GetChainIDListFormLocal();
	bool FindIDExistInChainIDList(uint64 id);
	
	void AnalyticalChainData(string strbuf, string nodeid);
	void SplitString(const string& s, vector<std::string>& v, const std::string& c);


private:

	string m_mynodeid;
	list<uint64> m_localhpidlist;
	vector <string> m_hyperidlistcompressed; 
	map<uint64, set<string>> m_hpspacedata;
	mutex m_lock;

	thread m_threadpull;
	bool m_bpull;
};