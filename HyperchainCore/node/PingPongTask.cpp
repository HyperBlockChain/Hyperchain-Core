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

#include "../newLog.h"
#include "Singleton.h"
#include "NodeManager.h"
#include "TaskThreadPool.h"
#include "PingPongTask.h"
#include "../wnd/common.h"

extern void AddIDToMsgBuf(int& nID, string& msgBuff);
extern void ParseIDMsgBuf(string input, int& nID, string& msgBuf);
extern int g_nTaskID;

void PingPongTask::exec()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH toServer = nodemgr->getNode(_toNodeId);
    string msgbuf = nodemgr->myself()->serialize();

    //
    AddIDToMsgBuf(g_nTaskID, msgbuf);
    //
    DataBuffer<PingPongTask> datamsgbuf(std::move(msgbuf));

    nodemgr->sendTo(toServer, datamsgbuf);
    g_console_logger->debug("PingPongTask::exec(), taskID ={} ,targetID = {}", g_nTaskID - 1, _toNodeId.ToHexString());
}

void PingPongTask::execRespond()
{
    TaskThreadPool* taskpool = Singleton<TaskThreadPool>::instance();
    taskpool->put(make_shared<PingPongRspTask>(std::move(_sentnodeid), _payload));
}

//
void PingPongRspTask::exec()
{
    //
    //----------------------
    //
    int nTaskID;
    ParseIDMsgBuf(_msg, nTaskID, _msg);
    //

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();

    HCNodeSH toClient = nodemgr->getNode(_fromNodeId);
    string msgbuf = nodemgr->myself()->serialize();
    //
    AddIDToMsgBuf(nTaskID, msgbuf);
    //
    DataBuffer<PingPongRspTask> datamsgbuf(std::move(msgbuf));
    nodemgr->sendTo(toClient, datamsgbuf);

    g_console_logger->debug("PingPongRspTask::exec(), taskID ={} ,targetID = {}", nTaskID, _fromNodeId.ToHexString());

}

void PingPongRspTask::execRespond()
{
    NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();

    string msg = _payload;
    //
    int nTaskID;
    ParseIDMsgBuf(_payload, nTaskID, msg);
    //

    g_console_logger->debug("PingPongRspTask::execRespond(), taskID ={} ,targetID = {}", nTaskID, _sentnodeid.ToHexString());

}
