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
#include "HyperData.h"
#include "db/HyperchainDB.h"
#include "node/TaskThreadPool.h"
#include "node/Singleton.h"
#include "HyperChain/PullHyperDataTask.hpp"


CHyperData::CHyperData()
{
}


CHyperData::~CHyperData()
{
}


void CHyperData::PullHyperDataByHID(uint64 hyid, string nodeid)
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	if (!taskpool)
		return;

	string msg = "hyperid=";
	msg += to_string(hyid);

	taskpool->put(make_shared<PullHyperDataTask>(msg, nodeid));
}

void CHyperData::PullHyperDataRspexec(string buf, vector<string> & outmsg)
{
	string hyperdata = buf;
	string::size_type np = hyperdata.find("hyperid=");
	if (np != string::npos)
	{
		string strhyid(hyperdata.begin() + 8, hyperdata.end());
		uint64 hyperid = stoi(strhyid);
		GetBlockFromID(hyperid, outmsg);
	}
}

int CHyperData::PullHyperDataRspexecRespond(string buf)
{
	if (buf.size() == 0)
		return -1;

	T_HYPERBLOCKDBINFO hblockinfo(buf);
	return DBmgr::instance()->insertHyperblock(hblockinfo);
}



void CHyperData::GetBlockFromID(uint64 BlockNum, vector<string>& hyperdata)
{
	QList<T_HYPERBLOCKDBINFO> queue;
	int nRet = DBmgr::instance()->getHyperblocks(queue, BlockNum, BlockNum);
	if (queue.size() == 0)
		return;

	for (auto qu : queue)
	{
		T_HYPERBLOCKDBINFO info = qu;
		hyperdata.push_back(info.serialize());
	}
}


