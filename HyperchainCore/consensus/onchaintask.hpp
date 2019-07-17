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

#include <iostream>
using namespace std;

#include "headers/lambda.h"
#include "../crypto/sha2.h"
#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "buddyinfo.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

extern bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);
extern void copyLocalBuddyList(LIST_T_LOCALCONSENSUS &endList, LIST_T_LOCALCONSENSUS fromList);
extern void SendConfirmReq(const CUInt128 &peerid, uint64 hyperblocknum, const string &hash, uint8 type);
extern bool isHyperBlockMatched(uint64 hyperblockid, const T_SHA256 &hash, const CUInt128 &peerid);

class OnChainRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_RSP> {
public:
    using ITask::ITask;
    OnChainRspTask(const CUInt128 &peerid, string && pBuf, unsigned int uiBufLen) :
        _peerid(peerid), _pBuf(std::forward<string>(pBuf)), _uiBufLen(uiBufLen) {}
    ~OnChainRspTask() {};
    void exec() override
    {
        g_consensus_console_logger->trace("enter OnChainRspTask: {}", _peerid.ToHexString());
        //HC: Have I child blocks to consensus?
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
        size_t nodeSize = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
        if (nodeSize == 0) {
            g_consensus_console_logger->trace("OnChainRspTask: my consensus block size is 0 ");
            return;
        }

        stringstream ssBufIn(_pBuf);
        boost::archive::binary_iarchive ia(ssBufIn, boost::archive::archive_flags::no_header);

        T_P2PPROTOCOLONCHAINREQ P2pProtocolOnChainReqRecv;
        try {
            ia >> P2pProtocolOnChainReqRecv;
        }
        catch (runtime_error& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        if (!isHyperBlockMatched(P2pProtocolOnChainReqRecv.GetHyperBlockID(), P2pProtocolOnChainReqRecv.tHyperBlockHash, _peerid)) {
            g_consensus_console_logger->warn("OnChainRspTask: PreHyperBlock isn't matched. recv:{} local:{} from: {}",
                P2pProtocolOnChainReqRecv.GetHyperBlockID(),
                g_tP2pManagerStatus.GetMaxBlockID(), _peerid.ToHexString());
            return;
        }

		//HC: Set buddy block hyper block information to latest.
		g_tP2pManagerStatus.updateLocalBuddyBlockToLatest();
		nodeSize = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
        if (nodeSize != ONE_LOCAL_BLOCK && P2pProtocolOnChainReqRecv.GetBlockCount() != ONE_LOCAL_BLOCK) {
            g_consensus_console_logger->trace("OnChainRspTask: cannot make buddy, my consensus block size:{}, recv block: {}",
                nodeSize, P2pProtocolOnChainReqRecv.GetBlockCount());
            return;
        }

        T_BUDDYINFOSTATE buddyInfo;
        copyLocalBuddyList(buddyInfo.localList, g_tP2pManagerStatus.listLocalBuddyChainInfo);

        //HC: 组合形成备选链
        for (uint64 i = 0; i < P2pProtocolOnChainReqRecv.GetBlockCount(); i++) {
            T_LOCALCONSENSUS  LocalBlockInfo;
            try {
                ia >> LocalBlockInfo;
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
                return;
            }

            bool index = JudgExistAtLocalBuddy(buddyInfo.localList, LocalBlockInfo);

            if (index)
                continue;
            //HC: 加入本地待上链数据块，形成备选链
            buddyInfo.localList.push_back(LocalBlockInfo);
            //HC: 排序组合成链
            buddyInfo.localList.sort(CmpareOnChain());
        }

        stringstream ssList;
        boost::archive::binary_oarchive oaList(ssList, boost::archive::archive_flags::no_header);

        ITR_LIST_T_LOCALCONSENSUS itrTemp = buddyInfo.localList.begin();
        for (; itrTemp != buddyInfo.localList.end(); itrTemp++) {
            oaList << (*itrTemp);
        }
        buddyInfo.SetPeerAddrOut(T_PEERADDRESS(_peerid));
        //HC: 设置备选链状态
        buddyInfo.SetBuddyState(SEND_ON_CHAIN_RSP);


        T_SHA256 tempHash(0);
        GetSHA256(tempHash.data(), ssList.str().data(), ssList.str().size());

        char strLocalHashTemp[FILESIZES] = { 0 };
        CCommonStruct::Hash256ToStr(strLocalHashTemp, tempHash);

        buddyInfo.SetBuddyHashInit(0);
        buddyInfo.SetBuddyHash(strLocalHashTemp);

        CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyReq);
        ITR_LIST_T_BUDDYINFOSTATE itrReq = g_tP2pManagerStatus.listCurBuddyReq.begin();
        for (; itrReq != g_tP2pManagerStatus.listCurBuddyReq.end(); itrReq++) {
            if (0 == memcmp((*itrReq).GetBuddyHash(), buddyInfo.GetBuddyHash(), DEF_STR_HASH256_LEN)) {
                return;
            }
        }
        //HC: 将备选链放入备选链集合中
        g_tP2pManagerStatus.listCurBuddyReq.push_back(buddyInfo);

        size_t blockNum = buddyInfo.localList.size();

        T_SHA256 tPreHyperBlockHash;
        uint64 hyperblockid = 0;
        g_tP2pManagerStatus.GetPreHyperBlockIDAndHash(hyperblockid, tPreHyperBlockHash);

        struct timeval timeTemp;
        CCommonStruct::gettimeofday_update(&timeTemp);

        T_P2PPROTOCOLONCHAINRSP P2pProtocolOnChainRsp;
        P2pProtocolOnChainRsp.SetP2pprotocolonchainrsp(T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_RSP, timeTemp.tv_sec), P2P_PROTOCOL_SUCCESS),
            hyperblockid, blockNum, strLocalHashTemp);
        P2pProtocolOnChainRsp.tHyperBlockHash = tPreHyperBlockHash;

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << P2pProtocolOnChainRsp;

        ITR_LIST_T_LOCALCONSENSUS itr = buddyInfo.localList.begin();
        for (; itr != buddyInfo.localList.end(); itr++) {
            oa << (*itr);
        }

        DataBuffer<OnChainRspTask> msgbuf(move(ssBuf.str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        g_consensus_console_logger->info("Send out OnChainRspTask");
        nodemgr->sendTo(_peerid, msgbuf);
    }

    void execRespond() override
    {
        g_consensus_console_logger->info("Received OnChainRspTask");
        T_BUDDYINFO localBuddyInfo;

        T_PEERADDRESS peerAddrOut(_sentnodeid);
        localBuddyInfo.Set(RECV_RSP, _payloadlen, _payload, peerAddrOut);

        bool index = false;
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
        LIST_T_BUDDYINFO::iterator itr = g_tP2pManagerStatus.listRecvLocalBuddyRsp.begin();
        for (; itr != g_tP2pManagerStatus.listRecvLocalBuddyRsp.end(); itr++) {
            if ((*itr).GetRequestAddress() == localBuddyInfo.GetRequestAddress()) {
                index = true;
                break;
            }
        }
        if (!index) {
            g_tP2pManagerStatus.listRecvLocalBuddyRsp.push_back(localBuddyInfo);
        }
    }

private:
    CUInt128 _peerid;
    string _pBuf;
    unsigned int _uiBufLen;
};

class OnChainTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN> {
public:
    using ITask::ITask;

    ~OnChainTask() {};
    void exec() override
    {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		//HC: update local block's hyper block information
		g_tP2pManagerStatus.updateLocalBuddyBlockToLatest();
        size_t blockNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();

        T_SHA256 tPreHyperBlockHash;
        uint64 hyperblockid = 0;
        g_tP2pManagerStatus.GetPreHyperBlockIDAndHash(hyperblockid, tPreHyperBlockHash);

        struct timeval timeTemp;
        CCommonStruct::gettimeofday_update(&timeTemp);

        //HC: put previous hyper block hash and id into protocol head
        T_P2PPROTOCOLONCHAINREQ P2pProtocolOnChainReq;
        P2pProtocolOnChainReq.SetP2pprotocolonchainreq(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_REQ, timeTemp.tv_sec),
            hyperblockid, tPreHyperBlockHash, blockNum);

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        oa << P2pProtocolOnChainReq;

        uint32_t i = 0;
        ITR_LIST_T_LOCALCONSENSUS itr = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
        for (; itr != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itr++) {
            T_LOCALCONSENSUS PeerInfos;
            PeerInfos.SetLoaclConsensus((*itr).GetPeer(), (*itr).GetLocalBlock());
            oa << PeerInfos;
            i++;
        }
        DataBuffer<OnChainTask> msgbuf(move(ssBuf.str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        g_consensus_console_logger->info("Broadcast OnChainTask...block number:{} prehyperblockid:{}", i,
            P2pProtocolOnChainReq.GetHyperBlockID());
        nodemgr->sendToAllNodes(msgbuf);
    }

    void execRespond() override
    {
        T_BUDDYINFO localBuddyInfo;

        T_PEERADDRESS peerAddrOut(_sentnodeid);
        localBuddyInfo.Set(RECV_REQ, _payloadlen, _payload, peerAddrOut);

        char logmsg[128] = { 0 };
        snprintf(logmsg, 128, "OnChain request from peer:%s reached\n", _sentnodeid.ToHexString().c_str());
        g_consensus_console_logger->info(logmsg);

        stringstream ssBuf(localBuddyInfo.GetBuffer());
        //HC: sizeof(long) =4 on Windows but =8 on Linux, so suppress header check by using archive flags.
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
        T_P2PPROTOCOLONCHAINREQ P2pProtocolOnChainReq;
        try {
            ia >> P2pProtocolOnChainReq;
        }
        catch (runtime_error& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        bool index = false;
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);

        LIST_T_BUDDYINFO::iterator itr = g_tP2pManagerStatus.listRecvLocalBuddyReq.begin();
        for (; itr != g_tP2pManagerStatus.listRecvLocalBuddyReq.end(); itr++) {
            stringstream ssTemp(itr->GetBuffer());
            boost::archive::binary_iarchive iaTemp(ssTemp, boost::archive::archive_flags::no_header);
            T_P2PPROTOCOLONCHAINREQ currReq;
            try {
                iaTemp >> currReq;
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
                return;
            }
            if ((*itr).GetRequestAddress() == localBuddyInfo.GetRequestAddress()) {
                if (P2pProtocolOnChainReq.tType.GetTimeStamp() <= currReq.tType.GetTimeStamp()) {
                    index = true;
                }
                else {
                    g_tP2pManagerStatus.listRecvLocalBuddyReq.erase(itr);
                }
                break;
            }
        }

        if (!index) {
            //HC: 保存收到的每个节点的buddy数据
            g_tP2pManagerStatus.listRecvLocalBuddyReq.push_back(localBuddyInfo);
            g_tP2pManagerStatus.SetRecvRegisReqNum(g_tP2pManagerStatus.GetRecvRegisReqNum() + 1);
            g_tP2pManagerStatus.SetRecvConfirmingRegisReqNum(g_tP2pManagerStatus.GetRecvConfirmingRegisReqNum() + 1);
        }
    }
};

class OnChainRefuseTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_REFUSE> {
public:
    using ITask::ITask;

    OnChainRefuseTask(const CUInt128 &peerid, const string & hash, uint8 type) : _peerid(peerid), _hash(hash), _type(type) {}

    ~OnChainRefuseTask() {};

    void exec() override
    {
        char logmsg[128] = { 0 };

        snprintf(logmsg, 128, "Refuse peer:%s chain respond\n", _peerid.ToHexString().c_str());
        g_consensus_console_logger->info(logmsg);

        T_PP2PPROTOCOLREFUSEREQ pP2pProtocolRefuseReq = nullptr;
        int ipP2pProtocolRefuseReqLen = sizeof(T_P2PPROTOCOLREFUSEREQ);

        DataBuffer<OnChainRefuseTask> msgbuf(ipP2pProtocolRefuseReqLen);
        pP2pProtocolRefuseReq = reinterpret_cast<T_PP2PPROTOCOLREFUSEREQ>(msgbuf.payload());

        struct timeval timeTemp;
        CCommonStruct::gettimeofday_update(&timeTemp);
        pP2pProtocolRefuseReq->SetP2pprotocolrefusereq(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_REFUSE_REQ, timeTemp.tv_sec), (char*)_hash.c_str(), _type);

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        nodemgr->sendTo(_peerid, msgbuf);
    }

    void execRespond() override
    {
        T_PP2PPROTOCOLREFUSEREQ pP2pProtocolRefuseReq = (T_PP2PPROTOCOLREFUSEREQ)(_payload);

        if (pP2pProtocolRefuseReq->GetSubType() == RECV_RSP) {
            bool isfound = false;
            CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
            auto itr = g_tP2pManagerStatus.listCurBuddyRsp.begin();
            for (; itr != g_tP2pManagerStatus.listCurBuddyRsp.end();) {
                if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolRefuseReq->GetHash(), DEF_STR_HASH256_LEN)) {
                    itr = g_tP2pManagerStatus.listCurBuddyRsp.erase(itr);
                    isfound = true;
                }
                else {
                    itr++;
                }
            }

            if (!isfound) {
                return;
            }
            g_consensus_console_logger->info("Confirm refused from: {}: select another buddy to confirm: listCurBuddyRsp size:{}",
                _sentnodeid.ToHexString(), g_tP2pManagerStatus.listCurBuddyRsp.size());

            if (g_tP2pManagerStatus.listCurBuddyRsp.size() > 0) {
                auto itr = g_tP2pManagerStatus.listCurBuddyRsp.begin();
                for (auto &b : itr->GetList()) {
                    g_consensus_console_logger->info("Confirm selected: {}", b.GetLocalBlock().GetPayLoadPreview());
                }

                LIST_T_LOCALCONSENSUS& c = itr->GetLocalConsensus();
                T_LOCALBLOCK &tLocalBlock = c.begin()->GetLocalBlock();

                SendConfirmReq(itr->GetPeerAddrOut()._nodeid, tLocalBlock.GetID(),
                    itr->GetBuddyHash(), P2P_PROTOCOL_SUCCESS);
            }
        }
        else if (pP2pProtocolRefuseReq->GetSubType() == RECV_REQ)
        {
            CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyReq);
            auto itr = g_tP2pManagerStatus.listCurBuddyReq.begin();
            for (; itr != g_tP2pManagerStatus.listCurBuddyReq.end();) {
                if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolRefuseReq->GetHash(), DEF_STR_HASH256_LEN)) {
                    itr = g_tP2pManagerStatus.listCurBuddyReq.erase(itr);
                }
                else {
                    itr++;
                }
            }
        }
    }

private:
    CUInt128 _peerid;
    string _hash;
    int _type;
};

class OnChainWaitTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_WAIT> {
public:
    using ITask::ITask;

    OnChainWaitTask(const CUInt128 &peerid, const string &hash) : _peerid(peerid), _hash(hash) {}

    ~OnChainWaitTask() {};

    void exec() override
    {
        char logmsg[128] = { 0 };

        snprintf(logmsg, 128, "I am waiting for confirm respond,inform peer to wait: %s \n", _peerid.ToHexString().c_str());
        g_consensus_console_logger->info(logmsg);

        DataBuffer<OnChainWaitTask> msgbuf(DEF_STR_HASH256_LEN);
        memcpy(msgbuf.payload(), _hash.c_str(), DEF_STR_HASH256_LEN);

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_peerid, msgbuf);
    }

    void execRespond() override
    {
        const char *pHash = _payload;

        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
        for (auto &buddy : g_tP2pManagerStatus.listCurBuddyRsp) {
            if (0 == strncmp(buddy.strBuddyHash, pHash, DEF_STR_HASH256_LEN) && buddy.GetBuddyState() == SEND_CONFIRM) {

                g_consensus_console_logger->info("Confirm wait from {}: select another buddy to confirm : listCurBuddyRsp size:{}",
                    _sentnodeid.ToHexString(), g_tP2pManagerStatus.listCurBuddyRsp.size());

                buddy.SetBuddyState(RECV_ON_CHAIN_RSP);
                for (auto &buddyCon : g_tP2pManagerStatus.listCurBuddyRsp) {
                    if (&buddyCon != &buddy) {
                        LIST_T_LOCALCONSENSUS& c = buddyCon.GetLocalConsensus();
                        T_LOCALBLOCK &tLocalBlock = c.begin()->GetLocalBlock();
                        SendConfirmReq(buddyCon.GetPeerAddrOut()._nodeid, tLocalBlock.GetID(),
                            buddyCon.GetBuddyHash(), P2P_PROTOCOL_SUCCESS);
                        break;
                    }
                }

                //Todo:
                //if listCurBuddyRsp.size()==1, how to do?
                break;
            }
        }
    }

private:
    CUInt128 _peerid;
    string _hash;
};
