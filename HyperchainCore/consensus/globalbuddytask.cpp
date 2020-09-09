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
#include "globalbuddytask.h"
#include "consensus_engine.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>


void MergeChainsWithMine(T_P2PPROTOCOLGLOBALBUDDYHEADER &globalBuddyHeader, boost::archive::binary_iarchive &ia)
{
    LIST_T_LOCALCONSENSUS listLocalConsensusInfo;
    uint64 uiChainCountNum = 0;

    ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();

    for (uint64 i = 0; i < globalBuddyHeader.GetBlockCount(); i++) {
        T_GLOBALCONSENSUS  localBlockInfo;
        try {
            ia >> localBlockInfo;
        }
        catch (runtime_error& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        T_LOCALCONSENSUS localInfo;
        localInfo.tLocalBlock = localBlockInfo.GetLocalBlock();
        localInfo.tPeer = localBlockInfo.GetPeer();

        if (uiChainCountNum != localBlockInfo.GetChainNo()) {
            uiChainCountNum = localBlockInfo.GetChainNo();
            if (listLocalConsensusInfo.size() != 0) {
                pEng->MergeToGlobalBuddyChains(listLocalConsensusInfo);
                listLocalConsensusInfo.clear();
            }
        }

        listLocalConsensusInfo.emplace_back(localInfo);

        if (i == globalBuddyHeader.GetBlockCount() - 1) {
            pEng->MergeToGlobalBuddyChains(listLocalConsensusInfo);
            listLocalConsensusInfo.clear();
        }
    }
}

void GlobalBuddyStartTask::exec()
{
    ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

    pConsensusStatus->listRecvLocalBuddyReq.clear();

    T_SHA256 preHyperblockHash = pConsensusStatus->GetConsensusPreHyperBlockHash();
    uint32_t blockNum = static_cast<uint32>(pConsensusStatus->listLocalBuddyChainInfo.size());
    if (blockNum <= 1) {
        return;
    }

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    auto itr = pConsensusStatus->listLocalBuddyChainInfo.end();
    itr--;
    if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {

        T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyReq;

        P2pProtocolGlobalBuddyReq.uiHyperBlockHash = preHyperblockHash;
        P2pProtocolGlobalBuddyReq.SetP2pprotocolglobalconsensusreq(T_PEERADDRESS(me->getNodeId<CUInt128>()), blockNum, 1);

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        oa << P2pProtocolGlobalBuddyReq;
        for (auto &localblock : pConsensusStatus->listLocalBuddyChainInfo) {
            T_GLOBALCONSENSUS PeerInfos;
            PeerInfos.SetGlobalconsenus(localblock.GetPeer(), localblock.GetLocalBlock(), 1);
            oa << PeerInfos;
        }
        DataBuffer<GlobalBuddyStartTask> msgbuf(move(ssBuf.str()));

        pConsensusStatus->listGlobalBuddyChainInfo.push_back(pConsensusStatus->listLocalBuddyChainInfo);
        pConsensusStatus->tBuddyInfo.usChainNum = static_cast<uint16>(pConsensusStatus->listGlobalBuddyChainInfo.size());

        nodemgr->sendToAllNodes(msgbuf);
    }
}

void GlobalBuddyStartTask::execRespond()
{
    GlobalBuddyRspTask task(_payload, _payloadlen);
    task.exec();
}

void GlobalBuddyRspTask::exec()
{
    ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

    if (!pConsensusStatus->StartGlobalFlag()) {
        return;
    }

    if (pConsensusStatus->listLocalBuddyChainInfo.empty()) {
        return;
    }

    stringstream ssBuf(_buf);
    boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

    T_P2PPROTOCOLGLOBALBUDDYHEADER globalBuddyHeader;
    try {
        ia >> globalBuddyHeader;
    }
    catch (runtime_error& e) {
        g_consensus_console_logger->warn("{}", e.what());
        return;
    }

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

    bool isEndNodeBuddyChain = pEng->IsEndNode();

    if (isEndNodeBuddyChain) {
        T_SHA256 hyperblockhash = pConsensusStatus->GetConsensusPreHyperBlockHash();
        if (globalBuddyHeader.uiHyperBlockHash != hyperblockhash) {
            g_consensus_console_logger->warn("GlobalBuddyReq is refused for different hyper block hash");
            return;
        }

        MergeChainsWithMine(globalBuddyHeader, ia);

        replyChildChains(globalBuddyHeader);
    }
    else {
        auto endItr = pConsensusStatus->listLocalBuddyChainInfo.end();
        endItr--;

        DataBuffer<GlobalBuddySendTask> datamsgbuf(std::move(_buf));
        nodemgr->sendTo(endItr->GetPeer().GetPeerAddr()._nodeid, datamsgbuf);
    }
}

void GlobalBuddyRspTask::replyChildChains(T_P2PPROTOCOLGLOBALBUDDYHEADER &globalBuddyHeader)
{
    ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

    uint32_t blockNum = 0;
    auto itrGlobal = pConsensusStatus->listGlobalBuddyChainInfo.begin();
    for (; itrGlobal != pConsensusStatus->listGlobalBuddyChainInfo.end(); itrGlobal++) {
        blockNum += static_cast<uint32_t>(itrGlobal->size());
    }

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    uint64 tempNum = pConsensusStatus->listGlobalBuddyChainInfo.size();

    T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyHeader;
    P2pProtocolGlobalBuddyHeader.uiHyperBlockHash = globalBuddyHeader.uiHyperBlockHash;
    P2pProtocolGlobalBuddyHeader.SetBlockCount(blockNum);
    P2pProtocolGlobalBuddyHeader.SetPeerAddr(T_PEERADDRESS(me->getNodeId<CUInt128>()));
    P2pProtocolGlobalBuddyHeader.SetChainCount(tempNum);

    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    oa << P2pProtocolGlobalBuddyHeader;

    uint32_t chainNum = 0;
    itrGlobal = pConsensusStatus->listGlobalBuddyChainInfo.begin();
    for (; itrGlobal != pConsensusStatus->listGlobalBuddyChainInfo.end(); itrGlobal++) {
        chainNum++;
        auto subItr = itrGlobal->begin();
        for (; subItr != itrGlobal->end(); subItr++) {
            T_GLOBALCONSENSUS PeerInfos;
            PeerInfos.SetLocalBlock((*subItr).GetLocalBlock());
            PeerInfos.SetPeer((*subItr).GetPeer());
            PeerInfos.SetChainNo(chainNum);
            oa << PeerInfos;
        }
    }
    DataBuffer<GlobalBuddyRspTask> msgbuf(move(ssBuf.str()));

    if (globalBuddyHeader.GetPeerAddr()._nodeid != me->getNodeId<CUInt128>()) {
        CUInt128 _peerid = globalBuddyHeader.GetPeerAddr()._nodeid;
        nodemgr->sendTo(_peerid, msgbuf);
    }
}

void GlobalBuddyRspTask::execRespond()
{
    ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

    if (!pConsensusStatus->StartGlobalFlag()) {
        return;
    }

    T_SHA256 hyperblockhash = pConsensusStatus->GetConsensusPreHyperBlockHash();

    string sBuf(_payload, _payloadlen);
    stringstream ssBuf(sBuf);
    boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

    T_P2PPROTOCOLGLOBALBUDDYHEADER globalBuddyHeader;
    try {
        ia >> globalBuddyHeader;
    }
    catch (runtime_error& e) {
        g_consensus_console_logger->warn("{}", e.what());
        return;
    }

    if (globalBuddyHeader.uiHyperBlockHash != hyperblockhash) {
        g_consensus_console_logger->error("GlobalBuddyRsp is refused for different hyper block hash");
        return;
    }

    MergeChainsWithMine(globalBuddyHeader, ia);
}

void GlobalBuddySendTask::exec()
{
    ConsensusEngine *pEng = Singleton<ConsensusEngine>::getInstance();
    T_P2PMANAGERSTATUS *pConsensusStatus = pEng->GetConsunsusState();

    if (!pConsensusStatus->StartGlobalFlag()) {
        return;
    }

    if (!pEng->IsEndNode()) {
        return;
    }

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    T_SHA256 hyperblockhash = pConsensusStatus->GetConsensusPreHyperBlockHash();
    uint32_t blockCount = 0;
    auto itr = pConsensusStatus->listGlobalBuddyChainInfo.begin();

    for (; itr != pConsensusStatus->listGlobalBuddyChainInfo.end(); itr++) {
        blockCount += static_cast<uint32_t>(itr->size());
    }

    if (blockCount == 0) {
        return;
    }

    T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyHeader;
    P2pProtocolGlobalBuddyHeader.uiHyperBlockHash = hyperblockhash;
    P2pProtocolGlobalBuddyHeader.SetP2pprotocolglobalconsensusreq( T_PEERADDRESS(me->getNodeId<CUInt128>()),
        blockCount, pConsensusStatus->listGlobalBuddyChainInfo.size());

    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    oa << P2pProtocolGlobalBuddyHeader;

    uint32_t chainNum = 0;
    auto itrSend = pConsensusStatus->listGlobalBuddyChainInfo.begin();
    for (; itrSend != pConsensusStatus->listGlobalBuddyChainInfo.end(); itrSend++) {
        chainNum++;
        auto subItr = itrSend->begin();
        for (; subItr != itrSend->end(); subItr++) {
            T_GLOBALCONSENSUS PeerInfos;
            PeerInfos.SetGlobalconsenus((*subItr).GetPeer(), (*subItr).GetLocalBlock(), chainNum);
            oa << PeerInfos;
        }
    }

    DataBuffer<GlobalBuddySendTask> msgbuf(move(ssBuf.str()));
    g_consensus_console_logger->info("Boardcast my Hyperblock chain to do Global Consensus: {}",
                                        P2pProtocolGlobalBuddyHeader.uiHyperBlockHash.toHexString());
    nodemgr->sendToAllNodes(msgbuf);
}

void GlobalBuddySendTask::execRespond()
{
    GlobalBuddyRspTask task(_payload, _payloadlen);
    task.exec();
}