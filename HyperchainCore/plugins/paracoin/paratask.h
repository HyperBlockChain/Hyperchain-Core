/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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

#define PARACOIN_T_SERVICE "paracoin_task"




enum class PARA_TASKTYPE : unsigned char
{
    BASETYPE = 0,

    PARACOIN,
    PARA_PING_NODE,
    PARA_PING_NODE_RSP,
};

void pingNode(const CAddress &addrConnect);
void sendToNode(CNode* pnode);
const CUInt128 * FindNodeId(const CAddress &addrConnect);

void StartMQHandler();
void StopMQHandler();

using OPAPP = std::tuple <std::string, std::map<string, string >> ;

int OperatorApplication(std::shared_ptr<OPAPP> parg);

class IParaTask : public ITask
{
public:
    using ITask::ITask;
    IParaTask() {}
    IParaTask(TASKBUF && recvbuf) : ITask(std::forward<TASKBUF>(recvbuf))
    {
        

        _payload++;
        _payloadlen--;
    }
};

class ParaTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::PARACOIN> {
public:
    using ITask::ITask;

    explicit ParaTask(const string &nodeid, const char *databuf, size_t len) :ITask(), _nodeid(nodeid), _msg(databuf, len),
        _nodemgr(Singleton<NodeManager>::getInstance()) {}
    void exec() override;
    void execRespond() override;

    template< class InputIt >
    void append(InputIt first, InputIt last)
    {
        _msg.append(first,last);
    }


private:
    string _nodeid;
    string _msg;
    NodeManager *_nodemgr;
};

class ParaPingRspTask : public IParaTask, public std::integral_constant<TASKTYPE, TASKTYPE::PARACOIN> {
public:
    ParaPingRspTask(TASKBUF && recvbuf) : IParaTask(std::forward<TASKBUF>(recvbuf)), _nodemgr(Singleton<NodeManager>::getInstance()) {}

    ParaPingRspTask(CUInt128 &&toNodeId, const char *requestNode) : _nodemgr(Singleton<NodeManager>::getInstance()), _msg(requestNode) {
        _sentnodeid = toNodeId;
    }

    ~ParaPingRspTask() {}

    void exec() override;
    void execRespond() override;

private:
    NodeManager *_nodemgr;
    string _msg;
};

class ParaPingTask : public IParaTask, public std::integral_constant<TASKTYPE, TASKTYPE::PARACOIN> {
public:
    using IParaTask::IParaTask;

    explicit ParaPingTask() : _nodemgr(Singleton<NodeManager>::getInstance()) {}
    void exec() override;
    void execRespond() override;

private:
    NodeManager *_nodemgr;
};






