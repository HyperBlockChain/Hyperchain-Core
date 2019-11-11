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
#include "headers.h"

#include "node/ITask.hpp"
#include "node/Singleton.h"
#include "node/NodeManager.h"
#include "node/TaskThreadPool.h"
#include "node/SearchNeighbourTask.h"
#include "node/UdpAccessPoint.hpp"

//#include "wnd/common.h"
#include "ledgertask.h"
#include "protocol.h"

#include <iostream>
#include <map>
using namespace std;

extern bool AppInit2(int argc, char* argv[]);
extern void ShutdownExcludeRPCServer();
void ReInitSystemRunningEnv();

static bool isControlingApp = false;
int OperatorApplication(std::shared_ptr<OPAPP> parg)
{
    if (isControlingApp) {
        return -1;
    }
    auto t = parg.get();

    auto& apphash = std::get<0>(*t);
    auto& mapParas = std::get<1>(*t);
    
    mapParas["-tokenhash"] = apphash;

    ShutdownExcludeRPCServer();

    //
    std:;deque<string> appli;

    appli.push_front("hc");

    int app_argc = mapParas.size() + 1;
    std::shared_ptr<char*> app_argv(new char* [app_argc]);

    for (auto& elm : mapParas) {
        
        string stroption = elm.first;
        if (!elm.second.empty()) {
            stroption += "=";
            stroption += elm.second;
        }
        appli.push_back(stroption);
    }


    int i = 0;
    char** p = app_argv.get();
    for (auto& elm : appli) {
        p[i++] = &elm[0];
    }

    ReInitSystemRunningEnv();
    AppInit2(app_argc, app_argv.get());

    isControlingApp = false;
    return 0;
}

void pingNode(const CAddress &addrConnect)
{
	//The peer nodeid maybe be unknown.
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::instance();
	taskpool->put(make_shared<PingTask>(addrConnect));
}

void sendToNode(CNode* pnode)
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    TRY_CRITICAL_BLOCK(pnode->cs_vSend)
    {
        CDataStream& vSend = pnode->vSend;
        if (!vSend.empty())
        {
            int nBytes = vSend.size();
            if (nBytes > 0)
            {
                taskpool->put(make_shared<LedgeTask>(pnode->nodeid, &vSend[0], nBytes));
                vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                pnode->nLastSend = GetTime();
            }
            if (vSend.size() > SendBufferSize()) {
                if (!pnode->fDisconnect)
                    printf("socket send flood control disconnect (%d bytes)\n", vSend.size());
                pnode->CloseSocketDisconnect();
            }
        }
    }
}

void recvFromNode(CNode* pnode, const char *pchBuf, size_t nBytes)
{
    TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
    {
        CDataStream& vRecv = pnode->vRecv;
        unsigned int nPos = vRecv.size();

        if (nPos > ReceiveBufferSize()) {
            if (!pnode->fDisconnect)
                printf("socket recv flood control disconnect (%d bytes)\n", vRecv.size());
            pnode->CloseSocketDisconnect();
        }
        else {
            // typical socket buffer is 8K-64K
            if (nBytes > 0)
            {
                vRecv.resize(nPos + nBytes);
                memcpy(&vRecv[nPos], pchBuf, nBytes);
                pnode->nLastRecv = GetTime();
            }
            else if (nBytes == 0)
            {
                // socket closed gracefully
                if (!pnode->fDisconnect)
                    printf("socket closed\n");
                pnode->CloseSocketDisconnect();
            }
            else if (nBytes < 0)
            {
                // error
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                {
                    if (!pnode->fDisconnect)
                        printf("socket recv error %d\n", nErr);
                    pnode->CloseSocketDisconnect();
                }
            }
        }
    }
}

const CUInt128 * FindNodeId(const CAddress &addrConnect)
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    UdpAccessPoint ap(addrConnect.ToStringIP(), std::atoi(addrConnect.ToStringPort().c_str()));

    return nodemgr->FindNodeId(&ap);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
void LedgeRspTask::exec()
{
}

void LedgeRspTask::execRespond()
{

}

void LedgeTask::exec()
{
    DataBuffer<LedgeTask> msgbuf(std::move(_msg));
    _nodemgr->sendTo(CUInt128(_nodeid), msgbuf);
}

void LedgeTask::execRespond()
{
    //Received ledger message from other node.
    //push message into node buffer.
    string sentnodeid = _sentnodeid.ToHexString();
    CRITICAL_BLOCK(cs_vNodes)
        BOOST_FOREACH(CNode* pnode, vNodes)
        if (pnode->nodeid == sentnodeid) {
            recvFromNode(pnode, _payload, _payloadlen);
            break;
        }
}


///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////

void PingRspTask::exec()
{
    DataBuffer<PingRspTask> databuf(_nodemgr->myself()->serialize());
    _nodemgr->sendTo(_sentnodeid, databuf);
}

void PingRspTask::execRespond()
{
    //save node
    HCNodeSH  node = _nodemgr->getNode(_sentnodeid);
    if (!node) {
        node = _nodemgr->parseNode(_msg);
        printf("%s: added a new Ledge node.\n", __FUNCTION__);
    }

    HCNode::APList &aplist = node->getAPList();
    UdpAccessPoint udppoint("127.0.0.1", 0);
    auto ret = std::find_if(aplist.begin(), aplist.end(), [&](const HCNode::APList::reference apCurr) {
        if (apCurr->id() == udppoint.id()) {
            return true;
        }
        return false;
    });

    if (ret == std::end(aplist)) {
        printf("%s: cannot find udp access point\n", __FUNCTION__);
        return;
    }
    UdpAccessPoint *ap = dynamic_cast<UdpAccessPoint*>(ret->get());
    CAddress addrConnect(ap->ip(), (int)ap->port());

    CRITICAL_BLOCK(cs_vNodes)
    {
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (pnode->nodeid == _sentnodeid.ToHexString()) {
                if (pnode->addr != addrConnect) {
                    pnode->addr = addrConnect;
                }
                pnode->AddRef();
                return;
            }

        //no found
        printf("Create a new outbound node and insert into Ledge nodes.\n");
        CNode* pNode = new CNode(-1, addrConnect, false);
        pNode->nodeid = _sentnodeid.ToHexString();
        pNode->nTimeConnected = GetTime();
        pNode->AddRef();
        vNodes.push_back(pNode);
    }
    printf("%s: reachable node %s\n", __FUNCTION__, addrConnect.ToString().c_str());
}


void PingTask::exec()
{
	UdpAccessPoint ap(_addrConnect.ToStringIP(),std::atoi(_addrConnect.ToStringPort().c_str()));

	//HCNodeSH & me = _nodemgr->myself();
	//msgbuf.insert(0, me->getNodeId<string>());

	DataBuffer<PingTask> databuf(0);

	string data = databuf.tostring();
	ap.write(data.c_str(), data.size());
}

void PingTask::execRespond()
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<PingRspTask>(std::move(_sentnodeid), _payload));
}


extern "C" BOOST_SYMBOL_EXPORT
bool RegisterTask(void* objFac)
{
    objectFactory* objFactory = reinterpret_cast<objectFactory*>(objFac);
    if (!objFactory) {
        return false;
    }

    objFactory->RegisterType<ITask, PingTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::LEDGE_PING_NODE));
    objFactory->RegisterType<ITask, PingRspTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::LEDGE_PING_NODE_RSP));
    objFactory->RegisterType<ITask, LedgeTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::LEDGE));
    objFactory->RegisterType<ITask, LedgeRspTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::LEDGE_RSP));
    return true;
}

extern "C" BOOST_SYMBOL_EXPORT
void UnregisterTask(void* objFac)
{
    objectFactory* objFactory = reinterpret_cast<objectFactory*>(objFac);
    if (!objFactory) {
        return;
    }

    objFactory->UnregisterType<ITask, PingTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::LEDGE_PING_NODE));
    objFactory->UnregisterType<ITask, PingRspTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::LEDGE_PING_NODE_RSP));
    objFactory->UnregisterType<ITask, LedgeTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::LEDGE));
    objFactory->UnregisterType<ITask, LedgeRspTask, TASKBUF>(static_cast<uint32_t>(TASKTYPE::LEDGE_RSP));
}

