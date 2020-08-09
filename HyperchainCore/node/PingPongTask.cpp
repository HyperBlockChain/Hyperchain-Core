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

#include "../newLog.h"
#include "Singleton.h"
#include "NodeManager.h"
#include "PingPongTask.h"
#include "../wnd/common.h"

void PingPongTask::exec()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    string msgbuf = nodemgr->myself()->serialize();
    DataBuffer<PingPongTask> datamsgbuf(std::move(msgbuf));

    HCNodeSH toServer;
    for (auto& nodeID : _vNodes)
    {
        toServer = nodemgr->getNode(nodeID);
        if (toServer) {
            nodemgr->sendTo(toServer, datamsgbuf);
            g_console_logger->debug("PingPongTask::exec(),targetID = {}", nodeID.ToHexString());
        }
   }
}

void PingPongTask::execRespond()
{
    PingPongRspTask tsk(std::move(_sentnodeid), _payload);
    tsk.exec();
}



void PingPongRspTask::exec()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    //NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();

    HCNodeSH toClient = nodemgr->getNode(_fromNodeId);
    string msgbuf = nodemgr->myself()->serialize();
    DataBuffer<PingPongRspTask> datamsgbuf(std::move(msgbuf));
    nodemgr->sendTo(toClient, datamsgbuf);

    g_console_logger->debug("PingPongRspTask::exec(),targetID = {}", _fromNodeId.ToHexString());
}

void PingPongRspTask::execRespond()
{
    //NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();
    //g_console_logger->debug("PingPongRspTask::execRespond(),targetID = {}", _sentnodeid.ToHexString());
}
