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
#include "newLog.h"
#include "HyperData.h"
#include "db/HyperchainDB.h"
#include "node/Singleton.h"
#include "node/TaskThreadPool.h"
#include "consensus/hyperblockTask.hpp"
#include "../wnd/common.h"

#include <iostream>

#include <cpprest/json.h>
using namespace web;


CHyperData::CHyperData()
{
}


CHyperData::~CHyperData()
{
}

void CHyperData::PullHyperDataByHID(uint64 hid, string nodeid)
{
    struct timeval timePtr;
    CCommonStruct::gettimeofday_update(&timePtr);

    DataBuffer<GetHyperBlockByNoReqTask> msgbuf(sizeof(T_P2PPROTOCOLGETHYPERBLOCKBYNOREQ));
    T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ tGetHyperBlockByNoReq = reinterpret_cast<T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ>(msgbuf.payload());
    tGetHyperBlockByNoReq->SetP2pprotocolgethyperblockbynoreq(
        T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GET_HYPERBLOCK_BY_NO_REQ, timePtr.tv_sec), hid);

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->sendTo(CUInt128(nodeid), msgbuf);
}
