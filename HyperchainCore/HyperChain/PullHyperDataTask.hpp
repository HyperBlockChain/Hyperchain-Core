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
using namespace std;

#include "node/ITask.hpp"
#include "HyperChain/HyperData.h"
#include "HyperChain/HyperChainSpace.h"
#include "node/NodeManager.h"

class PullHyperDataRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::HYPER_CHAIN_HYPERDATA_PULL_RSP> {
public:
	using ITask::ITask;
	PullHyperDataRspTask() {};
	PullHyperDataRspTask(CUInt128 nodeid, string buf, size_t len) : ITask()
	{
		_sentnodeid = nodeid;
		strpayload = buf;
		_payloadlen = len;
	}

	~PullHyperDataRspTask() {};
	void exec() override
	{
		CHyperData * hd = Singleton<CHyperData>::getInstance();
		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		string msgbuf;

		hd->PullHyperDataRspexec(strpayload, msgbuf);
		
		DataBuffer<PullHyperDataRspTask> datamsgbuf(std::move(msgbuf));
		nodemgr->sendTo(_sentnodeid, datamsgbuf);
		
	}

	void execRespond() override
	{
		CHyperData * hd = Singleton<CHyperData>::getInstance();
		string msgbuf = _payload;
		if (hd->PullHyperDataRspexecRespond(msgbuf) == 0)
		{
			CHyperChainSpace * hspc = Singleton<CHyperChainSpace, string>::getInstance();
			hspc->UpdataChainIDList();
		}
		
	}

private:
	string strpayload;
};

class PullHyperDataTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::HYPER_CHAIN_HYPERDATA_PULL> {
public:
	using ITask::ITask;
	PullHyperDataTask() {};
	PullHyperDataTask(string msg, string ndid) 
	{
		m_msg = msg;
		nodeid = ndid;
	}

	~PullHyperDataTask() {};
	void exec() override
	{		
		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		string msgbuf = m_msg;		

		DataBuffer<PullHyperDataTask> datamsgbuf(std::move(msgbuf));
		nodemgr->sendTo(CUInt128(nodeid), datamsgbuf);
	
	}

	void execRespond() override
	{
		TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();		
		taskpool->put(make_shared<PullHyperDataRspTask>(_sentnodeid, _payload, _payloadlen));
	}

private:
	string nodeid;
	string m_msg;
};




