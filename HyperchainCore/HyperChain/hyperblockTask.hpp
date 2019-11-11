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
#include "node/ITask.hpp"
//#include "node/Singleton.h"
#include "HyperChainSpace.h"
#include "node/NodeManager.h"
#include "consensus/buddyinfo.h"
#include "headers/inter_public.h"
//#include "headers/commonstruct.h"
#include "consensus/p2pprotocol.h"
#include "headers/lambda.h"
#include "../crypto/sha2.h"

#include <openssl/evp.h>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>


#include <iostream>
using namespace std;


extern void putStream(boost::archive::binary_oarchive& oa, const T_HYPERBLOCK& hyperblock);

class BoardcastHyperBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::BOARDCAST_HYPER_BLOCK> {
public:
    using ITask::ITask;
    BoardcastHyperBlockTask() {};
    ~BoardcastHyperBlockTask() {};

    void exec() override
    {
        vector<CUInt128> sendNodes = g_tP2pManagerStatus->GetMulticastNodes();
        if (sendNodes.empty())
            return;

        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        stringstream ssBuf;
        T_HYPERBLOCK hyperblock;

        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        {
            hyperblock = sp->GetLatestHyperBlock();
            putStream(oa, hyperblock);
        }
        DataBuffer<BoardcastHyperBlockTask> msgbuf(std::move(ssBuf.str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        vector<CUInt128>::iterator iter = sendNodes.begin();
        for (; iter != sendNodes.end(); iter++) {
            g_consensus_console_logger->info("Broadcast Latest HyperBlock [{}] to neighbors [{}]", hyperblock.GetID(), (*iter).ToHexString());
            nodemgr->sendTo(*iter, msgbuf);
        }

        g_tP2pManagerStatus->ClearMulticastNodes();
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);

        T_SHA256 hash;
        T_HYPERBLOCK hyperblock;
        try {
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            ia >> hash;
            ia >> hyperblock;
            uint32 count = hyperblock.GetChildChainsCount();
            for (uint32 i = 0; i < count; i++) {
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
            if (hash != hyperblock.GetHashSelf()) {
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
        catch (std::exception& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }
        catch (...) {
            g_consensus_console_logger->error("unknown exception occurs");
        }

        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        CHECK_RESULT ret = sp->CheckDependency(hyperblock);
        if (CHECK_RESULT::VALID_DATA != ret) {

            if (CHECK_RESULT::INVALID_DATA == ret) {
                g_consensus_console_logger->warn("Received invalid hyper block: {} for dependency check failed", hyperblock.GetID());
            }

            if (CHECK_RESULT::INCOMPATIBLE_DATA == ret) {
                //
                uint64 maxblockid = sp->GetMaxBlockID();
                uint64 hyperblockid = hyperblock.GetID() - 1;
                if ((maxblockid > MATURITY_SIZE) && (hyperblockid <= maxblockid - MATURITY_SIZE)) {
                    sp->PullHyperDataByHID(hyperblockid, _sentnodeid.ToHexString());
                    g_consensus_console_logger->warn("pull hyper block:[{}] from:[{}] for dependency check", hyperblockid, _sentnodeid.ToHexString());
                }
            }
            
            return;
        }

        //
        sp->updateHyperBlockCache(hyperblock);

        CAutoMutexLock muxTask(g_tP2pManagerStatus->MuxCycleQueueTask);
        g_tP2pManagerStatus->CycleQueueTask.push(TASKTYPE::BOARDCAST_HYPER_BLOCK);
    }
};

class GetHyperBlockByNoReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HYPERBLOCK_BY_NO_REQ> {
public:
    using ITask::ITask;
    GetHyperBlockByNoReqTask(uint64 blockNum, string nodeid)
    {
        m_blockNum = blockNum;
        m_nodeid = nodeid;
    }

    ~GetHyperBlockByNoReqTask() {};

    void exec() override
    {
        DataBuffer<GetHyperBlockByNoReqTask> msgbuf(sizeof(T_P2PPROTOCOLGETHYPERBLOCKBYNOREQ));
        T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ tGetHyperBlockByNoReq = reinterpret_cast<T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ>(msgbuf.payload());
        tGetHyperBlockByNoReq->SetP2pprotocolgethyperblockbynoreq(
            T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GET_HYPERBLOCK_BY_NO_REQ, CCommonStruct::gettimeofday_update()), m_blockNum);

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(CUInt128(m_nodeid), msgbuf);
    }

    void execRespond() override
    {
        T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ pP2pProtocolGetHyperBlockByNoReq = (T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ)(_payload);
        uint64 reqblockNum = pP2pProtocolGetHyperBlockByNoReq->GetBlockNum();

        T_HYPERBLOCK hyperBlock;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        if (!sp->getHyperBlock(reqblockNum, hyperBlock)) {
            //
            return;
        }

        //
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        putStream(oa, hyperBlock);
        DataBuffer<BoardcastHyperBlockTask> msgbuf(std::move(ssBuf.str()));

        //
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_sentnodeid, msgbuf);
    }

    uint64_t m_blockNum;
    string m_nodeid;
};




