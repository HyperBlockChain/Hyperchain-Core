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
#include "node/Singleton.h"
#include "HyperChainSpace.h"
#include "node/NodeManager.h"
#include "node/TaskThreadPool.h"
//#include "consensus/buddyinfo.h"
//#include "headers/inter_public.h"
//#include "consensus/p2pprotocol.h"
//#include "headers/lambda.h"
//#include "../crypto/sha2.h"

//#include <iostream>
//using namespace std;


class GetHeaderHashByNoRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HEADERHASH_BY_NO_RSP> {
public:
    using ITask::ITask;
    GetHeaderHashByNoRspTask() {};
    GetHeaderHashByNoRspTask(CUInt128 nodeid, uint64_t hid) : m_blockNum(hid), ITask() { _sentnodeid = nodeid; }
    ~GetHeaderHashByNoRspTask() {};

    void exec() override
    {
        T_HYPERBLOCK hyperBlock;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        if (!sp->getHyperBlock(m_blockNum, hyperBlock)) {
            //
            return;
        }

        T_SHA256 headerHash = hyperBlock.calculateHeaderHashSelf();

        string msgbuf = to_string(m_blockNum) + ":" + headerHash.tostring();
        DataBuffer<GetHeaderHashByNoRspTask> datamsg(std::move(msgbuf));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_sentnodeid, datamsg);
    }

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        string::size_type ns = msgbuf.find(":");
        if ((ns == string::npos) || (ns == 0)) {
            //
            return;
        }
        
        uint64_t hid = stoull(msgbuf.substr(0, ns));
        T_SHA256 headerHash = T_SHA256(msgbuf.substr(ns + 1, msgbuf.length() - 1));

        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->PutHyperBlockHeaderHash(hid, headerHash, _sentnodeid.ToHexString());
    }

    uint64_t m_blockNum;
};

class GetHeaderHashByNoReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HEADERHASH_BY_NO_REQ> {
public:
    using ITask::ITask;
    GetHeaderHashByNoReqTask(uint64 blockNum, string nodeid) : m_blockNum(blockNum), m_nodeid(nodeid) {};
    ~GetHeaderHashByNoReqTask() {};

    void exec() override
    {
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        DataBuffer<GetHeaderHashByNoReqTask> msgbuf(std::move(to_string(m_blockNum)));
        nodemgr->sendTo(CUInt128(m_nodeid), msgbuf);
    }

    void execRespond() override
    {
        string blockid(_payload, _payloadlen);
        uint64_t hid = stoull(blockid);
        TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
        taskpool->put(std::make_shared<GetHeaderHashByNoRspTask>(_sentnodeid, hid));
    }

    uint64_t m_blockNum;
    string m_nodeid;
};
