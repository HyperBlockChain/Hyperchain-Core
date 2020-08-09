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

#include "headers.h"

#include "node/ITask.hpp"
#include "node/Singleton.h"
#include "node/NodeManager.h"
#include "node/SearchNeighbourTask.h"
#include "node/UdpAccessPoint.hpp"
#include "node/UdpRecvDataHandler.hpp"

#include "cryptotoken.h"
#include "ledgertask.h"
#include "protocol.h"

#include <iostream>
#include <map>
using namespace std;

extern CryptoToken g_cryptoToken;

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

    

    std::deque<string> appli;

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


void sendToNode(CNode* pnode)
{
    TRY_CRITICAL_BLOCK(pnode->cs_vSend)
    {
        CDataStream& vSend = pnode->vSend;
        if (!vSend.empty())
        {
            int nBytes = vSend.size();
            if (nBytes > 0)
            {
                LedgerTask tsk(pnode->nodeid, &vSend[0], nBytes);
                tsk.exec();
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

///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
void LedgerTask::exec()
{
    DataBuffer<LedgerTask> msgbuf(std::move(_msg));
    _nodemgr->sendTo(CUInt128(_nodeid), msgbuf);
}

void LedgerTask::execRespond()
{
    //Received ledger message from other node.
    //push message into node buffer.
    LEDGER_TASKTYPE tt = (LEDGER_TASKTYPE)*_payload;
    switch (tt) {
    case LEDGER_TASKTYPE::LEDGER: {
        string sentnodeid = _sentnodeid.ToHexString();
        //CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_vNodes)
            BOOST_FOREACH(CNode* pnode, vNodes)
            if (pnode->nodeid == sentnodeid) {
                recvFromNode(pnode, _payload + sizeof(LEDGER_TASKTYPE), _payloadlen - sizeof(LEDGER_TASKTYPE));
            }
        break;
    }
    case LEDGER_TASKTYPE::LEDGER_PING_NODE: {
        PingTask task(getRecvBuf());
        task.execRespond();
        break;
    }
    case LEDGER_TASKTYPE::LEDGER_PING_NODE_RSP: {
        PingRspTask task(getRecvBuf());
        task.execRespond();
        break;
    }
    default:
        return;
    }

}


///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////

void PingRspTask::exec()
{
    char prefix = (char)LEDGER_TASKTYPE::LEDGER_PING_NODE_RSP;
    string self(prefix, 1);
    self += _nodemgr->myself()->serialize();

    DataBuffer<PingRspTask> databuf(std::move(self));
    _nodemgr->sendTo(_sentnodeid, databuf);
}

void PingRspTask::execRespond()
{
    //save node
    string payload(_payload, _payloadlen);
    T_APPTYPE apptype;
    size_t offset = apptype.unserialize(payload) + 1;

    uint32 hid;
    uint16 chainnum;
    uint16 localid;
    apptype.get(hid, chainnum, localid);
    if (!g_cryptoToken.IsTokenSame(hid, chainnum, localid)) {
        printf("%s: application type is different.\n", __FUNCTION__);
        return;
    }

    UdpAccessPoint udppoint("", 0);
    if (!_nodemgr->getNodeAP(_sentnodeid, &udppoint)) {
        if (!_nodemgr->parseNode(payload.substr(offset), &udppoint)) {
            printf("%s: cannot find udp access point\n", __FUNCTION__);
            return;
        }
        printf("%s: added a new Ledger node.\n", __FUNCTION__);
    }

    CAddress addrConnect(udppoint.ip(), (int)udppoint.port());

    CRITICAL_BLOCK(cs_main)
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
        printf("Create a new outbound node and insert into Ledger nodes.\n");
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
    DataBuffer<PingTask> databuf(1);
    char *p = databuf.payload();
    *p = (char)LEDGER_TASKTYPE::LEDGER_PING_NODE;

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    nodemgr->sendToAllNodes(databuf);
}

void PingTask::execRespond()
{
    PingRspTask tsk(std::move(_sentnodeid), _payload);
    tsk.exec();
}

static bool isRegistered = false;

extern "C" BOOST_SYMBOL_EXPORT
bool RegisterTask(void* objFac)
{
    UdpRecvDataHandler* datahandler = reinterpret_cast<UdpRecvDataHandler*>(objFac);
    if (!datahandler) {
        return false;
    }

    datahandler->registerAppTask(TASKTYPE::LEDGER, LEDGER_T_SERVICE);
    isRegistered = true;
    return true;
}

extern "C" BOOST_SYMBOL_EXPORT
void UnregisterTask(void* objFac)
{
    if (!isRegistered) {
        return;
    }

    UdpRecvDataHandler* datahandler = reinterpret_cast<UdpRecvDataHandler*>(objFac);
    if (!datahandler) {
        return;
    }

    datahandler->unregisterAppTask(TASKTYPE::LEDGER);
}

static MsgHandler ledgermsghandler;

static void handleLedgerTask(void *wrk, zmsg *msg)
{
    msg->unwrap();
    string buf = msg->pop_front();
    auto taskbuf = std::make_shared<string>(std::move(buf));

    HCMQWrk *realwrk = reinterpret_cast<HCMQWrk*>(wrk);

    TASKTYPE tt = *(TASKTYPE*)(taskbuf->c_str() + CUInt128::value + sizeof(ProtocolVer));
    if (tt != TASKTYPE::PARACOIN) {
        return;
    }

    LedgerTask task(std::move(taskbuf));
    task.execRespond();
}

void StartMQHandler()
{
    std::function<void(void*, zmsg*)> fwrk =
        std::bind(&handleLedgerTask, std::placeholders::_1, std::placeholders::_2);

    ledgermsghandler.registerTaskWorker(LEDGER_T_SERVICE, fwrk);
    ledgermsghandler.start();
    cout << "Ledger MQID:   " << ledgermsghandler.getID() << endl;

}

void StopMQHandler()
{
    ledgermsghandler.stop();
}

