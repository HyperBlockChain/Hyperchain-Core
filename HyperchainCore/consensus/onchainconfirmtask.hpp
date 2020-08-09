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


#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "../consensus/consensus_engine.h"
#include "buddyinfo.h"
#include "headers/lambda.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#include <iostream>
using namespace std;

extern void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type);
extern bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);

extern void SendCopyLocalBlock(T_LOCALCONSENSUS &localBlock);


class OnChainConfirmRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_CONFIRM_RSP> {
public:
    using ITask::ITask;

    OnChainConfirmRspTask(const CUInt128 &peerid, uint64 uiHyperBlockNum, const string & hash) :
        _peerid(peerid), _uiHyperBlockNum(uiHyperBlockNum), _hash(hash) {}

    ~OnChainConfirmRspTask() {};

    void exec() override
    {
        g_consensus_console_logger->info("Send OnChainConfirmRspTask to {}\n", _peerid.ToHexString().c_str());

        

        T_PP2PPROTOCOLONCHAINCONFIRMRSP pP2pProtocolOnChainConfirmRsp = nullptr;

        int ipP2pProtocolOnChainConfirmRspLen = sizeof(T_P2PPROTOCOLONCHAINCONFIRMRSP);

        DataBuffer<OnChainConfirmRspTask> msgbuf(ipP2pProtocolOnChainConfirmRspLen);
        pP2pProtocolOnChainConfirmRsp = reinterpret_cast<T_PP2PPROTOCOLONCHAINCONFIRMRSP>(msgbuf.payload());
        pP2pProtocolOnChainConfirmRsp->uiHyperBlockNum = _uiHyperBlockNum;
        pP2pProtocolOnChainConfirmRsp->SetInitHash(0);
        pP2pProtocolOnChainConfirmRsp->SetP2pprotocolonchainconfirmrsp(
            T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_CONFIRM_RSP, CCommonStruct::gettimeofday_update()), P2P_PROTOCOL_SUCCESS),
            const_cast<char*>(_hash.c_str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        nodemgr->sendTo(_peerid, msgbuf);

    }

    void execRespond() override
    {
        g_consensus_console_logger->info("Received OnChainConfirmRspTask from {}", _sentnodeid.ToHexString());
        T_PP2PPROTOCOLONCHAINCONFIRMRSP pP2pProtocolOnChainConfirmRspRecv = (T_PP2PPROTOCOLONCHAINCONFIRMRSP)(_payload);

        ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

        auto itr = pConsensusStatus->listCurBuddyRsp.begin();
        for (; itr != pConsensusStatus->listCurBuddyRsp.end();) {
            if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolOnChainConfirmRspRecv->GetHash(), DEF_STR_HASH256_LEN) &&
                (*itr).GetBuddyState() == SEND_CONFIRM) {
                pEng->PutIntoConsensusList(*itr);
                int i = 0;
                for (auto &b : pConsensusStatus->listLocalBuddyChainInfo) {
                    g_consensus_console_logger->info("OnChainConfirmRspTask: listLocalBuddyChainInfo: {} {}", ++i, b.GetLocalBlock().GetPayLoadPreview());
                }
            }
            else if ((*itr).GetBuddyState() != CONSENSUS_CONFIRMED) {
                SendRefuseReq((*itr).GetPeerAddrOut()._nodeid,
                    string((*itr).strBuddyHash, DEF_STR_HASH256_LEN), RECV_REQ);
                itr = pConsensusStatus->listCurBuddyRsp.erase(itr);
                continue;
            }
            ++itr;
        }

        auto itrReq = pConsensusStatus->listCurBuddyReq.begin();
        for (; itrReq != pConsensusStatus->listCurBuddyReq.end();) {
            if (0 == strncmp((*itrReq).strBuddyHash, pP2pProtocolOnChainConfirmRspRecv->strHash, DEF_STR_HASH256_LEN)) {
                itrReq->uibuddyState = CONSENSUS_CONFIRMED;
            }
            else {
                SendRefuseReq((*itrReq).GetPeerAddrOut()._nodeid,
                    string((*itrReq).strBuddyHash, DEF_STR_HASH256_LEN), RECV_RSP);
                itrReq = pConsensusStatus->listCurBuddyReq.erase(itrReq);
                continue;
            }
            ++itrReq;
        }

        g_consensus_console_logger->info("OnChainConfirmRspTask: listCurBuddyReq size: {} listCurBuddyRsp size: {}",
            pConsensusStatus->listCurBuddyReq.size(),
            pConsensusStatus->listCurBuddyRsp.size());

        pConsensusStatus->listRecvLocalBuddyRsp.clear();

        pConsensusStatus->listRecvLocalBuddyReq.clear();
    }

private:
    CUInt128 _peerid;
    uint64_t _uiHyperBlockNum;
    string _hash;
};

class OnChainConfirmTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_CONFIRM> {
public:
    using ITask::ITask;

    OnChainConfirmTask(const CUInt128 &peerid, uint64 uiHyperBlockNum, string hash, uint8 state) :
        _peerid(peerid), _uiHyperBlockNum(uiHyperBlockNum), _hash(hash), _state(state) {}

    ~OnChainConfirmTask() {};
    void exec() override
    {
        ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

        for (auto &buddy : pConsensusStatus->listCurBuddyRsp) {
            if (buddy.GetBuddyState() == SEND_CONFIRM) {
                g_consensus_console_logger->info("OnChainConfirmTask: already sent out Confirm");
                return;
            }
        }

        bool isFind = false;
        for (auto &chain : pConsensusStatus->listCurBuddyRsp) {
            if (0 == strncmp(chain.GetBuddyHash(), _hash.c_str(), DEF_STR_HASH256_LEN)) {
                chain.SetBuddyState(SEND_CONFIRM);
                g_consensus_console_logger->info("OnChainConfirmTask: set buddy state SEND_CONFIRM");
                isFind = true;
                break;
            }
        }
        if (!isFind) {
            return;
        }

        char logmsg[128] = { 0 };
        snprintf(logmsg, 128, "Send OnChainConfirmTask to peer:%s\n", _peerid.ToHexString().c_str());
        g_consensus_console_logger->info(logmsg);

        T_PP2PPROTOCOLONCHAINCONFIRM pP2pProtocolOnChainConfirm = nullptr;

        int ipP2pProtocolOnChainConfirmLen = sizeof(T_P2PPROTOCOLONCHAINCONFIRM);

        DataBuffer<OnChainConfirmTask> msgbuf(ipP2pProtocolOnChainConfirmLen);
        pP2pProtocolOnChainConfirm = reinterpret_cast<T_PP2PPROTOCOLONCHAINCONFIRM>(msgbuf.payload());
        pP2pProtocolOnChainConfirm->SetInitHash(0);
        pP2pProtocolOnChainConfirm->uiHyperBlockNum = _uiHyperBlockNum;
        pP2pProtocolOnChainConfirm->SetP2pprotocolonchainconfirm(
            T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_CONFIRM, CCommonStruct::gettimeofday_update()), _state),
            const_cast<char*> (_hash.c_str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(_peerid, msgbuf);

    }

    void execRespond() override
    {
        T_PP2PPROTOCOLONCHAINCONFIRM pP2pProtocolOnChainConfirmRecv = (T_PP2PPROTOCOLONCHAINCONFIRM)(_payload);

        bool isFind = false;

        auto f = [&](T_BUDDYINFOSTATE &buddyinfostate) {
            if (0 == strncmp(buddyinfostate.strBuddyHash,
                pP2pProtocolOnChainConfirmRecv->GetHash(), DEF_STR_HASH256_LEN)) {
                isFind = true;
                return true;
            }
            return false;
        };

        g_consensus_console_logger->info("Received confirm from {}", _sentnodeid.ToHexString());
        string confirmbuddyhash = string(pP2pProtocolOnChainConfirmRecv->GetHash(), DEF_STR_HASH256_LEN);

        string currBuddyHash;
        ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
        bool isconfirming = pEng->IsConfirming(currBuddyHash);

        T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

        std::find_if(pConsensusStatus->listCurBuddyReq.begin(), pConsensusStatus->listCurBuddyReq.end(), f);
        if (isFind) {
            if (!isconfirming || currBuddyHash == confirmbuddyhash) {
                

                

                g_consensus_console_logger->info("confirm from {}: will makebuddy, isconfirming:{}", _sentnodeid.ToHexString(), isconfirming);

                if (pEng->MakeBuddy(confirmbuddyhash)) {
                    SendConfirmRsp(confirmbuddyhash, pP2pProtocolOnChainConfirmRecv->uiHyperBlockNum);
                }
            }
        }
        else {
            

            SendWaitRsp(confirmbuddyhash);
        }

        if (!isFind) {
            g_consensus_console_logger->info("Confirm refused: cannot find the buddy hash from {} ",
                _sentnodeid.ToHexString().c_str());
            SendRefuseReq(_sentnodeid, confirmbuddyhash, RECV_RSP);
        }
    }

    void SendConfirmRsp(string hash, uint64_t uiHyperBlockNum)
    {
        OnChainConfirmRspTask tsk(_sentnodeid, uiHyperBlockNum, hash);
        tsk.exec();

    }
    void SendWaitRsp(string hash)
    {
        OnChainWaitTask tsk(_sentnodeid, hash);
        tsk.exec();
    }

private:
    CUInt128 _peerid;
    uint64_t _uiHyperBlockNum;
    string _hash;
    int _state;
};



class CopyBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::COPY_BLOCK> {
public:
    using ITask::ITask;

    CopyBlockTask(const T_LOCALCONSENSUS &localBlock) : _localBlock(localBlock) {}

    ~CopyBlockTask() {};

    void exec() override
    {
        g_consensus_console_logger->info("Send CopyBlockLocalTask: {}",
            _localBlock.GetLocalBlock().GetPayLoadPreview());

        ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

        size_t nodeSize = pConsensusStatus->listLocalBuddyChainInfo.size();
        if (nodeSize > NOT_START_BUDDY_NUM) {
            uint16 num = 0;
            for (auto &b : pConsensusStatus->listLocalBuddyChainInfo) {
                if ((b.GetLocalBlock().GetUUID() == _localBlock.GetLocalBlock().GetUUID())) {
                    continue;
                }
                num++;
                if (num >= nodeSize) {
                    break;
                }
            }

            stringstream ssBuf;
            boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

            T_P2PPROTOCOLCOPYBLOCKREQ P2pProtocolCopyBlockReq;
            P2pProtocolCopyBlockReq.SetType(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_COPY_BLOCK_REQ, CCommonStruct::gettimeofday_update()));
            P2pProtocolCopyBlockReq.uiBuddyNum = num;
            oa << P2pProtocolCopyBlockReq;

            T_LOCALCONSENSUS LocalBlockInfo;
            LocalBlockInfo.SetLocalBlock(_localBlock.GetLocalBlock());
            LocalBlockInfo.SetPeer(_localBlock.GetPeer());
            oa << LocalBlockInfo;

            


            uint16 i = 0;
            for (auto &b : pConsensusStatus->listLocalBuddyChainInfo) {
                if ((b.GetLocalBlock().GetUUID() == _localBlock.GetLocalBlock().GetUUID())) {
                    continue;
                }
                string uuid = b.GetLocalBlock().GetUUID();
                uint32 uuidSize = static_cast<uint32>(uuid.size());
                oa << uuidSize;
                oa << boost::serialization::make_binary_object(uuid.data(), uuidSize);
                i++;
                if (i >= nodeSize) {
                    break;
                }
            }

            DataBuffer<CopyBlockTask> msgbuf(std::move(ssBuf.str()));

            NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
            HCNodeSH me = nodemgr->myself();

            ITR_LIST_T_LOCALCONSENSUS itr = pConsensusStatus->listLocalBuddyChainInfo.begin();
            for (; itr != pConsensusStatus->listLocalBuddyChainInfo.end(); itr++) {
                if ((*itr).tLocalBlock.GetUUID() == _localBlock.GetLocalBlock().GetUUID()) {
                    continue;
                }
                if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
                    continue;
                }
                g_consensus_console_logger->info("Send {} blocks hash and CopyBlockLocalTask to {}",
                    P2pProtocolCopyBlockReq.uiBuddyNum,
                    (*itr).GetPeer().GetPeerAddr()._nodeid.ToHexString());
                nodemgr->sendTo((*itr).GetPeer().GetPeerAddr()._nodeid, msgbuf);
            }
        }
    }

    void execRespond() override
    {
        g_consensus_console_logger->trace("Received CopyBlockTask");

        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

        T_P2PPROTOCOLCOPYBLOCKREQ P2pProtocolCopyBlockReqRecv;
        T_LOCALCONSENSUS  LocalBlockTemp;
        try {
            ia >> P2pProtocolCopyBlockReqRecv;
            ia >> LocalBlockTemp;
        }
        catch (runtime_error& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
        T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

        ITR_LIST_T_LOCALCONSENSUS itrList = pConsensusStatus->listLocalBuddyChainInfo.begin();
        for (; itrList != pConsensusStatus->listLocalBuddyChainInfo.end(); itrList++) {
            if (((*itrList).GetLocalBlock().GetUUID() == LocalBlockTemp.GetLocalBlock().GetUUID())) {
                return;
            }
        }

        uint16 num = 0;
        string uuidRecv;
        for (uint16 i = 0; i < P2pProtocolCopyBlockReqRecv.uiBuddyNum; i++) {
            try {
                uint32 uuidSize = 0;
                ia >> uuidSize;
                uuidRecv.resize(uuidSize);
                ia >> boost::serialization::make_binary_object(const_cast<char*>(uuidRecv.data()), uuidSize);
            }
            catch (runtime_error& e) {
                g_consensus_console_logger->warn("{}", e.what());
                return;
            }

            for (auto &b : pConsensusStatus->listLocalBuddyChainInfo) {
                if (uuidRecv == b.GetLocalBlock().GetUUID()) {
                    num++;
                    break;
                }
            }
        }
        g_consensus_console_logger->info("CopyBlockTask: recv {} copy block data,{} block is same.",
            P2pProtocolCopyBlockReqRecv.uiBuddyNum, num);
        

        if (num < 2) {
            g_consensus_console_logger->warn("CopyBlockTask: cannot accept the copy data,maybe I have entered next phase.");
            return;
        }
        g_consensus_console_logger->trace("CopyBlockTask: push block into listLocalBuddyChainInfo,payload:{}",
            LocalBlockTemp.GetLocalBlock().GetPayLoadPreview());
        pConsensusStatus->listLocalBuddyChainInfo.push_back(LocalBlockTemp);
        pConsensusStatus->listLocalBuddyChainInfo.sort(CmpareOnChain());
        pConsensusStatus->tBuddyInfo.usBlockNum = static_cast<uint16>(pConsensusStatus->listLocalBuddyChainInfo.size());
    }

private:
    T_LOCALCONSENSUS _localBlock;
};
