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

#include "ITask.hpp"

class SearchRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::HYPER_CHAIN_SEARCH_RSP> {
public:
	using ITask::ITask;

	SearchRspTask(CUInt128 nodeid) {};
	~SearchRspTask() {};
	void exec() override
	{
		cout << "SearchRspTask respond.";
	}
	void execRespond() override
	{

	}
};

class SearchTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::HYPER_CHAIN_SEARCH> {
public:
	using ITask::ITask;
	~SearchTask() {}
	void exec() override
	{
		cout << "SearchTask request.";
	}
	void execRespond() override
	{
		TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
		taskpool->put(std::make_shared<SearchRspTask>(_sentnodeid));
	}
};


