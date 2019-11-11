/*Copyright 2016-2019 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#pragma once

#include <iostream>
using namespace std;

#include "node/ITask.hpp"
#include "node/NodeManager.h"
#include "node/Singleton.h"


#include "bignum.h"
#include "protocol.h"
#include "net.h"

void pingNode(const CAddress &addrConnect);
void sendToNode(CNode* pnode);
const CUInt128 * FindNodeId(const CAddress &addrConnect);


using OPAPP = std::tuple <std::string, std::map<string, string >> ;

int OperatorApplication(std::shared_ptr<OPAPP> parg);

class LedgeRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::PARACOIN_RSP> {
public:
    using ITask::ITask;

    LedgeRspTask(CUInt128 &&fromNodeId, const char *requestNode) : ITask(), _nodemgr(Singleton<NodeManager>::getInstance()),
        _fromNodeId(std::move(fromNodeId)), _msg(requestNode) {}
    ~LedgeRspTask() {}

    void exec() override;
    void execRespond() override;

private:
    NodeManager *_nodemgr;
    CUInt128 _fromNodeId;
    string _msg;
};

class LedgeTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::PARACOIN> {
public:
    using ITask::ITask;

    explicit LedgeTask(const string &nodeid, const char *databuf, size_t len) :ITask(), _nodeid(nodeid), _msg(databuf, len),
        _nodemgr(Singleton<NodeManager>::getInstance()) {}
    void exec() override;
    void execRespond() override;

private:
    string _nodeid;
    string _msg;
    NodeManager *_nodemgr;
};

class PingRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::PARA_PING_NODE_RSP> {
public:
    PingRspTask(TASKBUF && recvbuf) : ITask(std::forward<TASKBUF>(recvbuf)), _nodemgr(Singleton<NodeManager>::getInstance()) {}

    PingRspTask(CUInt128 &&toNodeId, const char *requestNode) : _nodemgr(Singleton<NodeManager>::getInstance()), _msg(requestNode) {
        _sentnodeid = toNodeId;
    }

    ~PingRspTask() {}

    void exec() override;
    void execRespond() override;

private:
    NodeManager *_nodemgr;
    string _msg;
};

class PingTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::PARA_PING_NODE> {
public:
    using ITask::ITask;

    explicit PingTask() : _nodemgr(Singleton<NodeManager>::getInstance()) {}
    void exec() override;
    void execRespond() override;

private:
    NodeManager *_nodemgr;
};






