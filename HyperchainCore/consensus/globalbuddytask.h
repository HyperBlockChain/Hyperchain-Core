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

#include <iostream>
using namespace std;

#ifdef _WIN32
#include <WinSock2.h>
#endif

#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "buddyinfo.h"
#include "../node/TaskThreadPool.h"
#include "headers/lambda.h"


class GlobalBuddyStartTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_START_REQ> {
public:
    using ITask::ITask;

    ~GlobalBuddyStartTask() {};

    void exec() override;
    void execRespond() override;
};


class GlobalBuddySendTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_SEND_REQ> {
public:
    using ITask::ITask;

    ~GlobalBuddySendTask() {};

    void exec() override;
    void execRespond() override;
};


class GlobalBuddyRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GLOBAL_BUDDY_RSP> {
public:
    using ITask::ITask;
    GlobalBuddyRspTask() {};
    GlobalBuddyRspTask(const char* buf, size_t len) : ITask(), _buf(buf, len) {};
    ~GlobalBuddyRspTask() {};

    void exec() override;


    void execRespond() override;

private:
    void replyChildChains(T_P2PPROTOCOLGLOBALBUDDYHEADER& globalBuddyReqRecv);

private:
    string _buf;

};
