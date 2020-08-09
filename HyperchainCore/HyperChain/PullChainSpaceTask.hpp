/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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
#include "HyperChainSpace.h"
#include "node/NodeManager.h"

class PullChainSpaceRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::HYPER_CHAIN_SPACE_PULL_RSP> {
public:
    using ITask::ITask;
    PullChainSpaceRspTask() {};
    PullChainSpaceRspTask(CUInt128 nodeid) : ITask() { _sentnodeid = nodeid; }
    ~PullChainSpaceRspTask() {};

    void exec() override
    {
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        vector<string> localHIDsection;
        sp->GetLocalHIDsection(localHIDsection);
        if (localHIDsection.empty())
            return;

        string msgbuf = "BlockID=";
        for (auto &li : localHIDsection) {
            msgbuf += li;
            msgbuf += ";";
        }

        uint64 headerID = sp->GetHeaderHashCacheLatestHID();

        msgbuf += "HeaderID=";
        msgbuf += to_string(headerID);

        DataBuffer<PullChainSpaceRspTask> datamsg(std::move(msgbuf));
        nodemgr->sendTo(_sentnodeid, datamsg);
    }

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->AnalyzeChainSpaceData(msgbuf, _sentnodeid.ToHexString());
        //sp->SyncLatestHyperBlock();
    }
};

class PullChainSpaceTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::HYPER_CHAIN_SPACE_PULL> {
public:
    using ITask::ITask;
    PullChainSpaceTask() {};
    ~PullChainSpaceTask() {};
    void exec() override
    {
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        DataBuffer<PullChainSpaceTask> msgbuf(0);

        nodemgr->sendToAllNodes(msgbuf);
    }

    void execRespond() override
    {
        PullChainSpaceRspTask task(_sentnodeid);
        task.exec();
    }

};



