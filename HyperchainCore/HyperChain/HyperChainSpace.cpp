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
	Init();
}

CHyperChainSpace::~CHyperChainSpace()
{
	m_bpull = false;
	if(m_threadpull.joinable())
	{
		m_threadpull.join();
	}
}
void CHyperChainSpace::GetHyperChainData(map<uint64, set<string>>& out_HyperChainData)
{
	lock_guard<mutex> locker(m_lock);
	out_HyperChainData.clear();
	out_HyperChainData = m_hpspacedata;
}

int CHyperChainSpace::GetLocalChainIDList(list<uint64> & out_LocalIDList)
{
	return DBmgr::instance()->getAllHyperblockNumInfo(out_LocalIDList);
}

int CHyperChainSpace::GetChainIDListFormLocal()
{	
	lock_guard<mutex> lk(m_lock);
	uint64 ret = 0;
	m_localhpidlist.clear();
	if (GetLocalChainIDList(m_localhpidlist) == 0)
	{
		if (m_localhpidlist.size() == 0)
			return ret;

		list<uint64>::iterator it = m_localhpidlist.begin();
		uint64 nstart = m_localhpidlist.front();
		uint64 nend = nstart;
		string data;
		m_hyperidlistcompressed.clear();

		for (auto li : m_localhpidlist)
		{

			if (li == nend || li - nend == 1)
			{
				nend = li;
			}
			else
			{
				
				if (nstart == nend)
				{
					data = to_string(nstart);
				}
				else
				{
					data = to_string(nstart) + "-" + to_string(nend);
				}

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
	}

	return ret;
}

void CHyperChainSpace::AnalyticalChainData(string strbuf, string nodeid)
{
	
	string::size_type np = strbuf.find("HyperID=");
	if (np != string::npos)
	{
		strbuf = strbuf.substr(np + 8);
	}

	vector<string> vecHID;
	SplitString(strbuf, vecHID, ";");

	vector<string>::iterator vit;
	string::size_type ns = 0;

	for (auto sid : vecHID)
	{
		string strIDtoID = sid;

		if ((ns = strIDtoID.find("-")) > 0)
		{
			uint64 IDS = stoi(strIDtoID.substr(0, ns));
			uint64 IDE = stoi(strIDtoID.substr(ns + 1, strIDtoID.length() - 1));

			for (uint64 ID = IDS; ID < IDE + 1; ID++)
			{
				if (!FindIDExistInChainIDList(ID))
				{
					m_hpspacedata[ID].insert(nodeid);
				}

			}

		}
		else
		{
			uint64 ID = stoi(strIDtoID);
			if (!FindIDExistInChainIDList(ID))
			{
				m_hpspacedata[ID].insert(nodeid);
			}

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
	bool bret = false;

	if (m_hyperidlistcompressed.size() <= 0)
		return bret;
	else
		bret = true;

	mes += "HyperID=";
	for (auto li: m_hyperidlistcompressed)
	{
		mes += li;
		mes += ";";
	}

	return bret;

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
	m_localhpidlist.clear();
	GetLocalChainIDList(m_localhpidlist);
}


void CHyperChainSpace::Init()
{
	m_hpspacedata.clear();
	GetChainIDListFormLocal();
	m_bpull = true;
	
	m_threadpull = thread(&CHyperChainSpace::PullDataThread, this);
}



uint64 CHyperChainSpace::PullDataFromChainSpace()
{
	uint64 nret = 0;
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	if (!taskpool)
		return 0;

	m_hpspacedata.clear();
	nret = GetChainIDListFormLocal();

	taskpool->put(make_shared<PullChainSpaceTask>());

	return nret;

}

void CHyperChainSpace::PullDataThread()
{
	while (m_bpull)
	{
		PullDataFromChainSpace();
		
		uint64 ntimer = 500;
		while (m_bpull && ntimer <= PULLTIMER )
		{
			SLEEP(ntimer);
			ntimer += ntimer;			
		}
	}
}
