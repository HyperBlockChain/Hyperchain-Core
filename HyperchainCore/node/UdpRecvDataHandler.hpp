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


#include "UInt128.h"
#include "ObjectFactory.hpp"

#include "Singleton.h"
#include "TaskThreadPool.h"
#include "UpChainTask.hpp"
#include "SearchTask.hpp"
#include "SearchNeighbourTask.hpp"
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
		size_t prefixlen = CUInt128::value + sizeof(TASKTYPE);
		assert(len >= prefixlen);

		TaskThreadPool *pTaskThreadPool = Singleton<TaskThreadPool>::getInstance();

		auto taskbuf = make_shared<string>(buf,len);
		return put(ip, port, taskbuf);
	}

	bool put(const char* ip, uint32_t port, TASKBUF taskbuf)
	{
		size_t prefixlen = CUInt128::value + sizeof(TASKTYPE);
		int len = taskbuf->size();
		assert(len >= prefixlen);

		
		string nodeid(taskbuf->c_str(), CUInt128::value);
		CNode neighbourNode(std::move(CUInt128(nodeid)));
		neighbourNode.addAP(make_shared<UdpAccessPoint>(ip,port));

		NodeManager *nodemanager = Singleton<NodeManager>::getInstance();
		nodemanager->updateNode(std::move(neighbourNode));

		
		const char * buf = taskbuf->c_str();
		TaskThreadPool *pTaskThreadPool = Singleton<TaskThreadPool>::getInstance();
		TASKTYPE tt = *(TASKTYPE*)(buf + CUInt128::value);

		shared_ptr<ITask> task = _taskTypeFactory.CreateShared<ITask>(tt, std::move(taskbuf));
		if (!task) {
			cout << "Received unregistered task data which cannot be handled, abandoned them.";
			
			return true;
		}

		return pTaskThreadPool->put(std::move(task));
	}

private:
	
	void registerType()
	{
		_taskTypeFactory.RegisterType<ITask,SearchTask,TASKBUF&&>(HYPER_CHAIN_SEARCH);
		_taskTypeFactory.RegisterType<ITask,SearchRspTask,TASKBUF&&>(HYPER_CHAIN_SEARCH_RSP);

		_taskTypeFactory.RegisterType<ITask,UpChainTask,TASKBUF>(HYPER_CHAIN_UP);
		_taskTypeFactory.RegisterType<ITask,UpChainRspTask,TASKBUF>(HYPER_CHAIN_UP_RSP);

		_taskTypeFactory.RegisterType<ITask,SearchNeighbourTask,TASKBUF>(SEARCH_NEIGHBOUR);
		_taskTypeFactory.RegisterType<ITask,SearchNeighbourRspTask,TASKBUF>(SEARCH_NEIGHBOUR_RSP);


		_taskTypeFactory.RegisterType<ITask, PullChainSpaceTask, TASKBUF>(HYPER_CHAIN_SPACE_PULL);
		_taskTypeFactory.RegisterType<ITask, PullChainSpaceRspTask, TASKBUF>(HYPER_CHAIN_SPACE_PULL_RSP);

		_taskTypeFactory.RegisterType<ITask, PullHyperDataTask, TASKBUF>(HYPER_CHAIN_HYPERDATA_PULL);
		_taskTypeFactory.RegisterType<ITask, PullHyperDataRspTask, TASKBUF>(HYPER_CHAIN_HYPERDATA_PULL_RSP);
	}
private:

	objectFactory _taskTypeFactory;
};
