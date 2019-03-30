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

#include "newLog.h"
#include "UInt128.h"
#include "ObjectFactory.hpp"

#include "Singleton.h"
#include "TaskThreadPool.h"
#include "../consensus/onchaintask.hpp"
#include "../consensus/onchainconfirmtask.hpp"
#include "../consensus/globalbuddytask.h"
#include "../consensus/hyperblockTask.hpp"
#include "SearchTask.hpp"
#include "SearchNeighbourTask.h"
#include "NodeManager.h"
#include "HyperChain/PullChainSpaceTask.hpp"
#include "HyperChain/PullHyperDataTask.hpp"
#include "UdpAccessPoint.hpp"

class UdpRecvDataHandler
{
public:
	UdpRecvDataHandler()
	{
		registerType();
	}
	UdpRecvDataHandler(const UdpRecvDataHandler &) = delete;
	UdpRecvDataHandler & operator=(const UdpRecvDataHandler &) = delete;

	bool put(const char* ip, uint32_t port, const char *buf, size_t len)
	{
		if (len < ProtocolHeaderLen) {
			char logmsg[128] = { 0 };
			snprintf(logmsg, 128, "Received invalid data from: %s:%d\n", ip, port);
			cout << logmsg;
			return true;
		}

		auto taskbuf = make_shared<string>(buf,len);
		return put(ip, port, taskbuf);
	}

	bool put(const char* ip, uint32_t port, TASKBUF taskbuf)
	{
		size_t len = taskbuf->size();
		if (len < ProtocolHeaderLen) {
			char logmsg[128] = { 0 };
			snprintf(logmsg, 128, "Received invalid data from: %s:%d\n", ip, port);
			cout << logmsg;
			return true;
		}

		
		uint8_t nodeid[CUInt128::value];
		memcpy(nodeid,taskbuf->c_str(),CUInt128::value);
		HCNodeSH neighbourNode = make_shared<HCNode>(std::move(CUInt128(nodeid)));
		neighbourNode->addAP(make_shared<UdpAccessPoint>(ip,port));

		NodeManager *nodemanager = Singleton<NodeManager>::getInstance();
		nodemanager->updateNode(neighbourNode);

		
		TASKTYPE tt = *(TASKTYPE*)(taskbuf->c_str() + CUInt128::value + sizeof(ProtocolVer));

		shared_ptr<ITask> task = _taskTypeFactory.CreateShared<ITask>(static_cast<uint32_t>(tt), std::move(taskbuf));
		if (!task) {
			
			char logmsg[128] = { 0 };
			snprintf(logmsg, 128, "Received unregistered task data from %s:%d which cannot be handled, abandoned them.\n",ip,port);
			cout << logmsg;
			return true;
		}

		TaskThreadPool *pTaskThreadPool = Singleton<TaskThreadPool>::getInstance();
		return pTaskThreadPool->put(std::move(task));
	}

private:
	
	void registerType()
	{
		_taskTypeFactory.RegisterType<ITask,SearchTask,TASKBUF&&>(static_cast<uint32_t>(TASKTYPE::HYPER_CHAIN_SEARCH));
		_taskTypeFactory.RegisterType<ITask,SearchRspTask,TASKBUF&&>(static_cast<uint32_t>(TASKTYPE::HYPER_CHAIN_SEARCH_RSP));

		_taskTypeFactory.RegisterType<ITask,OnChainTask,TASKBUF>(static_cast<uint32_t>(TASKTYPE::ON_CHAIN));
		_taskTypeFactory.RegisterType<ITask,OnChainRspTask,TASKBUF>(static_cast<uint32_t>(TASKTYPE::ON_CHAIN_RSP));

		_taskTypeFactory.RegisterType<ITask, OnChainConfirmTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::ON_CHAIN_CONFIRM));
		_taskTypeFactory.RegisterType<ITask, OnChainConfirmRspTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::ON_CHAIN_CONFIRM_RSP));
		_taskTypeFactory.RegisterType<ITask, OnChainWaitTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::ON_CHAIN_WAIT));

		_taskTypeFactory.RegisterType<ITask, CopyBlockTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::COPY_BLOCK));

		_taskTypeFactory.RegisterType<ITask, OnChainRefuseTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::ON_CHAIN_REFUSE));

		_taskTypeFactory.RegisterType<ITask,SearchNeighbourTask,TASKBUF>(static_cast<uint32_t>(TASKTYPE::SEARCH_NEIGHBOUR));
		_taskTypeFactory.RegisterType<ITask,SearchNeighbourRspTask,TASKBUF>(static_cast<uint32_t>(TASKTYPE::SEARCH_NEIGHBOUR_RSP));


		_taskTypeFactory.RegisterType<ITask, PullChainSpaceTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::HYPER_CHAIN_SPACE_PULL));
		_taskTypeFactory.RegisterType<ITask, PullChainSpaceRspTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::HYPER_CHAIN_SPACE_PULL_RSP));

		_taskTypeFactory.RegisterType<ITask, PullHyperDataTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::HYPER_CHAIN_HYPERDATA_PULL));
		_taskTypeFactory.RegisterType<ITask, PullHyperDataRspTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::HYPER_CHAIN_HYPERDATA_PULL_RSP));

		_taskTypeFactory.RegisterType<ITask, GlobalBuddyStartTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::GLOBAL_BUDDY_START_REQ));
		_taskTypeFactory.RegisterType<ITask, GlobalBuddySendTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::GLOBAL_BUDDY_SEND_REQ));
		_taskTypeFactory.RegisterType<ITask, GlobalBuddyRspTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::GLOBAL_BUDDY_RSP));

		_taskTypeFactory.RegisterType<ITask, BoardcastHyperBlockTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::BOARDCAST_HYPER_BLOCK));
		_taskTypeFactory.RegisterType<ITask, GetHyperBlockByNoReqTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::GET_HYPERBLOCK_BY_NO_REQ));
	}
private:

	objectFactory _taskTypeFactory;
};
