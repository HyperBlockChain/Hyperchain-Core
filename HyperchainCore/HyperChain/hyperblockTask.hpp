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
#pragma once
#include "node/ITask.hpp"
#include "node/Singleton.h"
#include "HyperChainSpace.h"
#include "node/NodeManager.h"
#include "consensus/buddyinfo.h"
#include "headers/inter_public.h"
#include "headers/lambda.h"
#include "consensus/consensus_engine.h"
#include "../crypto/sha2.h"

#include <openssl/evp.h>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>


#include <iostream>
using namespace std;

extern void putStream(boost::archive::binary_oarchive& oa, const T_HYPERBLOCK& hyperblock);
extern void getFromStream(boost::archive::binary_iarchive &ia, T_HYPERBLOCK& hyperblock, T_SHA256& hash);

class NoHyperBlockRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::NO_HYPERBLOCK_RSP> {
public:
    using ITask::ITask;
    NoHyperBlockRspTask() {};
    ~NoHyperBlockRspTask() {};

    void exec() override {};

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        uint64_t hid = stoull(msgbuf);
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->NoHyperBlock(hid, _sentnodeid.ToHexString());
    }
};

class BoardcastHyperBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::BOARDCAST_HYPER_BLOCK> {
public:
    using ITask::ITask;
    BoardcastHyperBlockTask() {};
    ~BoardcastHyperBlockTask() {};

    void exec() override
    {
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        vector<CUInt128> sendNodes;
        sp->GetMulticastNodes(sendNodes);
        if (sendNodes.empty())
            return;

        stringstream ssBuf;
        T_HYPERBLOCK hyperblock;

        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        {
            sp->GetLatestHyperBlock(hyperblock);
            putStream(oa, hyperblock);
        }
        DataBuffer<BoardcastHyperBlockTask> msgbuf(std::move(ssBuf.str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        vector<CUInt128>::iterator iter = sendNodes.begin();
        for (; iter != sendNodes.end(); iter++) {
            g_consensus_console_logger->info("Broadcast Latest HyperBlock [{}] to neighbors [{}]", hyperblock.GetID(), (*iter).ToHexString());
            nodemgr->sendTo(*iter, msgbuf);
        }
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);

        T_SHA256 hash;
        T_HYPERBLOCK hyperblock;
        try {
            boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
            getFromStream(ia, hyperblock, hash);

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
            return;
        }

        string nodeid = _sentnodeid.ToHexString();
        vector<CUInt128> multicastnodes;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->PutHyperBlock(hyperblock, nodeid, multicastnodes);
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
        if (m_blockNum == -1)
            return;

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

        if (reqblockNum == -1) {
            g_daily_logger->info("GetHyperBlockByNoReqTask, ignore invalid hyperblock id: [-1]");
            return;
        }

        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        T_HYPERBLOCK hyperBlock;
        if (!sp->getHyperBlock(reqblockNum, hyperBlock)) {
            

            DataBuffer<NoHyperBlockRspTask> msgbuf(std::move(to_string(reqblockNum)));
            nodemgr->sendTo(_sentnodeid, msgbuf);
            g_daily_logger->info("GetHyperBlockByNoReqTask, I haven't hyperblock: [{}], sentnodeid: [{}]", reqblockNum, _sentnodeid.ToHexString());
            return;
        }

        

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        putStream(oa, hyperBlock);
        DataBuffer<BoardcastHyperBlockTask> msgbuf(std::move(ssBuf.str()));

        

        nodemgr->sendTo(_sentnodeid, msgbuf);
    }

private:
    uint64_t m_blockNum;
    string m_nodeid;
};

class GetHyperBlockByPreHashReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HYPERBLOCK_BY_PREHASH_REQ> {
public:
    using ITask::ITask;
    GetHyperBlockByPreHashReqTask(uint64 blockNum, T_SHA256 prehash, string nodeid)
    {
        m_blockNum = blockNum;
        m_prehash = prehash;
        m_nodeid = nodeid;
    }

    ~GetHyperBlockByPreHashReqTask() {};

    void exec() override
    {
        string datamsg = m_prehash.toHexString();
        DataBuffer<GetHyperBlockByPreHashReqTask> msgbuf(std::move(datamsg));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(CUInt128(m_nodeid), msgbuf);
    }

    void execRespond() override
    {
        string msg(_payload, _payloadlen);
        T_SHA256 PreHash = CCommonStruct::StrToHash256(msg);
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        T_HYPERBLOCK hyperBlock;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        if (!sp->getHyperBlockByPreHash(PreHash, hyperBlock)) {
            

            DataBuffer<NoHyperBlockRspTask> msgbuf(std::move(to_string(m_blockNum)));
            nodemgr->sendTo(_sentnodeid, msgbuf);
            g_daily_logger->info("GetHyperBlockByPreHashReqTask, I haven't hyper block: [{}], sentnodeid: [{}]", m_blockNum, _sentnodeid.ToHexString());
            return;
        }

        

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        putStream(oa, hyperBlock);
        DataBuffer<BoardcastHyperBlockTask> msgbuf(std::move(ssBuf.str()));

        

        nodemgr->sendTo(_sentnodeid, msgbuf);
    }

private:
    uint64_t m_blockNum;
    T_SHA256 m_prehash;
    string m_nodeid;
};



