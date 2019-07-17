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

#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "buddyinfo.h"
#include "headers/lambda.h"
#include "../crypto/sha2.h"
#include "../db/HyperchainDB.h"
#include <openssl/evp.h>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>


#include <iostream>
using namespace std;

extern void ReOnChainFun();
extern void GetOnChainInfo();
extern bool isEndNode();
extern void putStream(boost::archive::binary_oarchive &oa, T_HYPERBLOCK &hyperblock);


class BoardcastHyperBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::BOARDCAST_HYPER_BLOCK> {
public:
    using ITask::ITask;
    BoardcastHyperBlockTask() {};
    ~BoardcastHyperBlockTask() {};

    void exec() override
    {
        if (!isEndNode()) {
            return;
        }

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        {
            CAutoMutexLock muxAuto(g_tP2pManagerStatus.m_MuxHchainBlockList);
            T_HYPERBLOCK &hyperblock = g_tP2pManagerStatus.GetPreHyperBlock();
            putStream(oa, hyperblock);
        }
        DataBuffer<BoardcastHyperBlockTask> msgbuf(move(ssBuf.str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendToAllNodes(msgbuf);
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

        T_SHA256 hash;
        T_HYPERBLOCK hyperblock;
        try {
            ia >> hash;
            ia >> hyperblock;
            uint32 count = hyperblock.GetChildChainsCount();
            for (uint32 i=0; i < count; i++) {
                LIST_T_LOCALBLOCK childchain;
				uint32 blocknum;
				ia >> blocknum;
				for (uint32 j = 0; j < blocknum; j++) {
					T_LOCALBLOCK block;
					ia >> block;
					childchain.push_back(std::move(block));
				}
                hyperblock.AddChildChain(std::move(childchain));
            }
            ostringstream oss;
            hyperblock.calculateHashSelf();
            if(hash != hyperblock.GetHashSelf()) {
                oss << "Received invalid hyper block: " << hyperblock.GetID() << " for hash error";
                throw std::runtime_error(oss.str());
            }
            if (!hyperblock.verify()) {
                oss << "Received invalid hyper block: " << hyperblock.GetID() << " for verification failed";
                throw std::runtime_error(oss.str());
            }
        }
        catch (runtime_error& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        //HC: put hyper block into hyper block cache
        g_tP2pManagerStatus.updateHyperBlockCache(hyperblock);
    }
};

class GetHyperBlockByNoReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HYPERBLOCK_BY_NO_REQ> {
public:
    using ITask::ITask;
    GetHyperBlockByNoReqTask(uint64 blockNum)
    {
        m_blockNum = blockNum;
    }

    ~GetHyperBlockByNoReqTask() {};

    void exec() override
    {
        struct timeval timePtr;
        CCommonStruct::gettimeofday_update(&timePtr);

        DataBuffer<GetHyperBlockByNoReqTask> msgbuf(sizeof(T_P2PPROTOCOLGETHYPERBLOCKBYNOREQ));
        T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ tGetHyperBlockByNoReq = reinterpret_cast<T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ>(msgbuf.payload());
        tGetHyperBlockByNoReq->SetP2pprotocolgethyperblockbynoreq(
            T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GET_HYPERBLOCK_BY_NO_REQ, timePtr.tv_sec), m_blockNum);

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendToAllNodes(msgbuf);
    }

    void execRespond() override
    {
        T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ pP2pProtocolGetHyperBlockByNoReq = (T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ)(_payload);
        uint64 reqblockNum = pP2pProtocolGetHyperBlockByNoReq->GetBlockNum();

        T_HYPERBLOCK hyperBlock;
        if (!g_tP2pManagerStatus.getHyperBlock(reqblockNum, hyperBlock)) {
            //HC: I haven't the hyper block.
            return;
        }

        //HC: prepare to send the hyper block to the request node
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        putStream(oa, hyperBlock);
        DataBuffer<BoardcastHyperBlockTask> msgbuf(move(ssBuf.str()));

        //HC: send to the request node
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_sentnodeid, msgbuf);
    }

    uint64_t m_blockNum;
};




