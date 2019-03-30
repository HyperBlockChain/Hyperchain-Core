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
#include "HyperData.h"
#include "HyperChainSpace.h"
#include "node/TaskThreadPool.h"
#include "node/Singleton.h"
#include "HyperChain/PullChainSpaceTask.hpp"
#include "db/dbmgr.h"
#include <algorithm>
#include <thread>


CHyperChainSpace::CHyperChainSpace(string nodeid)
{
	m_mynodeid = nodeid;
}

CHyperChainSpace::~CHyperChainSpace()
{
	m_bpull = false;
	if (m_threadpull->joinable())
	{
		m_threadpull->join();
	}
}
void CHyperChainSpace::GetHyperChainData(MULTI_MAP_HPSPACEDATA & out_HyperChainData)
{
	lock_guard<mutex> locker(m_datalock);
	out_HyperChainData.clear();
	out_HyperChainData = m_hpspacedata;
}

void CHyperChainSpace::GetHyperChainShow(map<string, string>& out_HyperChainShow)
{
	lock_guard<mutex> locker(m_showlock);
	out_HyperChainShow.clear();
	out_HyperChainShow = m_hpspaceshow;
}

void CHyperChainSpace::GetLocalChainShow(vector<string> & out_LocalChainShow)
{
	lock_guard<mutex> locker(m_listlock);
	out_LocalChainShow.clear();
	out_LocalChainShow = m_hyperidlistcompressed;
}

int CHyperChainSpace::GetLocalChainIDList(list<uint64> & out_LocalIDList)
{
	return DBmgr::instance()->getAllHyperblockNumInfo(out_LocalIDList);
}

uint64 CHyperChainSpace::GetGlobalLatestHyperBlockNo()
{
	lock_guard<mutex> locker(m_datalock);
	if (m_hpspacedata.size() == 0)
		return 0;

	MULTI_MAP_HPSPACEDATA::reverse_iterator it = m_hpspacedata.rbegin();
	if (it == m_hpspacedata.rend())
		return 0;

	return it->first;
}

int CHyperChainSpace::GetRemoteHyperBlockByID(uint64 globalHID)
{
	lock_guard<mutex> locker(m_datalock);
	if (m_hpspacedata.size() == 0)
		return -1;

	MULTI_MAP_HPSPACEDATA::iterator it = m_hpspacedata.find(globalHID);
	if (it == m_hpspacedata.end())
		return -1;

	MAP_NODE nodemap = it->second;
	CHyperData * hd = Singleton<CHyperData>::instance();


	MAP_NODE::iterator iter = nodemap.begin();
	for (int i = 0; (i < 3) && (iter != nodemap.end()); iter++, i++) {

		hd->PullHyperDataByHID(globalHID, iter->first);
		return 0;

	}
	return 0;
}

int CHyperChainSpace::GetChainIDListFormLocal()
{
	lock_guard<mutex> lk(m_listlock);
	int ret = 0;

	m_hyperidlistcompressed.clear();
	m_localhpidlist.clear();

	if (GetLocalChainIDList(m_localhpidlist) != 0)
		return ret;

	if (m_localhpidlist.size() == 0)
		return ret;

	list<uint64>::iterator it = m_localhpidlist.begin();
	uint64 nstart = m_localhpidlist.front();
	uint64 nend = nstart;
	string data;

	for (auto li : m_localhpidlist)
	{
		if (li == nend || li - nend == 1)
			nend = li;
		else
		{
			
			if (nstart == nend)
				data = to_string(nstart);
			else
				data = to_string(nstart) + "-" + to_string(nend);

			m_hyperidlistcompressed.push_back(data);

			nstart = li;
			nend = nstart;
		}
		ret++;
	}

	if (nstart == nend)
	{
		data = to_string(nstart);
	}
	else
	{
		data = to_string(nstart) + "-" + to_string(nend);
	}
	ret++;
	m_hyperidlistcompressed.push_back(data);

	return ret;
}

void CHyperChainSpace::AnalyticalChainData(string strbuf, string nodeid)
{
	
	string::size_type np = strbuf.find("HyperID=");
	if (np != string::npos)
	{
		strbuf = strbuf.substr(np + 8);
	}

	{
		lock_guard<mutex> locker(m_showlock);
		m_hpspaceshow[nodeid] = strbuf;
	}

	vector<string> vecHID;
	SplitString(strbuf, vecHID, ";");

	vector<string>::iterator vit;
	string::size_type ns = 0;

	lock_guard<mutex> lk(m_datalock);
	for (auto sid : vecHID)
	{
		string strIDtoID = sid;
		ns = strIDtoID.find("-");


		if ((ns != string::npos) && (ns > 0))
		{
			uint64 IDS = stoull(strIDtoID.substr(0, ns));
			uint64 IDE = stoull(strIDtoID.substr(ns + 1, strIDtoID.length() - 1));

			for (uint64 ID = IDS; ID < IDE + 1; ID++)
			{
				m_hpspacedata[ID].insert(make_pair(nodeid, system_clock::now()));

			}

		}
		else
		{
			uint64 ID = stoull(strIDtoID);

			m_hpspacedata[ID].insert(make_pair(nodeid, system_clock::now()));

		}
	}
}


void CHyperChainSpace::SplitString(const string& s, vector<std::string>& v, const std::string& c)
{
	string::size_type pos1, pos2;
	pos2 = s.find(c);
	pos1 = 0;
	while (std::string::npos != pos2)
	{
		v.push_back(s.substr(pos1, pos2 - pos1));

		pos1 = pos2 + c.size();
		pos2 = s.find(c, pos1);
	}

}

bool CHyperChainSpace::PullChainSpaceRspTaskEXC(string & mes)
{
	lock_guard<mutex> lk(m_listlock);
	if (m_hyperidlistcompressed.size() <= 0)
		return false;

	mes += "HyperID=";
	for (auto li : m_hyperidlistcompressed)
	{
		mes += li;
		mes += ";";
	}

	return true;
}

void CHyperChainSpace::PullChainSpaceRspTaskRSP(string  mes, string nodeid)
{
	string buf = mes;
	if (buf.length() <= 0)
		return;

	AnalyticalChainData(buf, nodeid);
}

bool CHyperChainSpace::FindIDExistInChainIDList(uint64 id)
{
	auto iter = find(m_localhpidlist.begin(), m_localhpidlist.end(), id);
	if (iter != m_localhpidlist.end())
	{
		return true;
	}
	else
	{
		return false;
	}

	return false;
}

void CHyperChainSpace::UpdataChainIDList()
{
	lock_guard<mutex> lk(m_listlock);
	m_localhpidlist.clear();
	GetLocalChainIDList(m_localhpidlist);
}

void CHyperChainSpace::start()
{

	GetChainIDListFormLocal();
	m_bpull = true;

	m_threadpull.reset(new std::thread(&CHyperChainSpace::PullDataThread, this));
}

uint64 CHyperChainSpace::PullDataFromChainSpace()
{
	uint64 nret = 0;
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	if (!taskpool)
		return 0;


	nret = GetChainIDListFormLocal();

	taskpool->put(make_shared<PullChainSpaceTask>());

	return nret;

}

void CHyperChainSpace::PullDataThread()
{
	int num = 0;
	while (m_bpull)
	{
		PullDataFromChainSpace();
		num = 0;
		while (m_bpull && num < 100) {
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
			++num;
		}
	}
}
