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
#include "globalbuddytask.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

extern bool MergeToGlobalBuddyChains(LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo);
extern bool isEndNode();

void MergeChainsWithMine(T_P2PPROTOCOLGLOBALBUDDYHEADER &globalBuddyHeader, boost::archive::binary_iarchive &ia)
{
    LIST_T_LOCALCONSENSUS listLocalConsensusInfo;
    uint64 uiChainCountNum = 0;

    //HC: ���յ������ϲ�������ȫ��������listGlobalBuddyChainInfo
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
                //HC: ����������ɣ��ϲ���ȫ����������
                MergeToGlobalBuddyChains(listLocalConsensusInfo);
                listLocalConsensusInfo.clear();
            }
        }

        listLocalConsensusInfo.emplace_back(localInfo);

        if (i == globalBuddyHeader.GetBlockCount() - 1) {
            //HC: ����������ɣ��ϲ�ȫ����������
            MergeToGlobalBuddyChains(listLocalConsensusInfo);
            listLocalConsensusInfo.clear();
        }
    }
}

void GlobalBuddyStartTask::exec()
{
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
    g_tP2pManagerStatus.listRecvLocalBuddyReq.clear();

    T_SHA256 preHyperblockHash = g_tP2pManagerStatus.GetConsensusPreHyperBlockHash();
    CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
    uint32_t blockNum = static_cast<uint32>(g_tP2pManagerStatus.listLocalBuddyChainInfo.size());
    if (blockNum <= 1) {
        //HC: No any buddy block need to handle
        return;
    }

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    auto itr = g_tP2pManagerStatus.listLocalBuddyChainInfo.end();
    //HC: Take out the tail local block in the local chain.
    itr--;
    if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
        //HC: The tail local block is created by me.

        T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyReq;

        P2pProtocolGlobalBuddyReq.uiHyperBlockHash = preHyperblockHash;
        P2pProtocolGlobalBuddyReq.SetP2pprotocolglobalconsensusreq(T_PEERADDRESS(me->getNodeId<CUInt128>()), blockNum, 1);

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        oa << P2pProtocolGlobalBuddyReq;
        for (auto &localblock : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
            T_GLOBALCONSENSUS PeerInfos;
            PeerInfos.SetGlobalconsenus(localblock.GetPeer(), localblock.GetLocalBlock(), 1);
            oa << PeerInfos;
        }
        DataBuffer<GlobalBuddyStartTask> msgbuf(move(ssBuf.str()));

        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
        g_tP2pManagerStatus.listGlobalBuddyChainInfo.push_back(g_tP2pManagerStatus.listLocalBuddyChainInfo);
        g_tP2pManagerStatus.tBuddyInfo.usChainNum = static_cast<uint16>(g_tP2pManagerStatus.listGlobalBuddyChainInfo.size());

        nodemgr->sendToAllNodes(msgbuf);
    }
}

void GlobalBuddyStartTask::execRespond()
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<GlobalBuddyRspTask>(_payload, _payloadlen));
}

void GlobalBuddyRspTask::exec()
{
    if (!g_tP2pManagerStatus.StartGlobalFlag()) {
        return;
    }

    {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
        if (g_tP2pManagerStatus.listLocalBuddyChainInfo.empty()) {
            return;
        }
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

    bool isEndNodeBuddyChain = isEndNode();

    if (isEndNodeBuddyChain) {
        T_SHA256 hyperblockhash = g_tP2pManagerStatus.GetConsensusPreHyperBlockHash();
        if (globalBuddyHeader.uiHyperBlockHash != hyperblockhash) {
            g_consensus_console_logger->error("GlobalBuddyReq is refused for different hyper block hash");
            return;
        }

        MergeChainsWithMine(globalBuddyHeader, ia);

        //HC: ����Ӧ�����ݲ��ظ����Է�
        //HC: TO DO��Ӧ�����ݿ��Ż�������ҺͶԷ���������ȫһ������Ӧ���κ�����
        replyChildChains(globalBuddyHeader);

    }
    else {
        //HC: forward chain data to last node in chain
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
        auto endItr = g_tP2pManagerStatus.listLocalBuddyChainInfo.end();
        endItr--;

        DataBuffer<GlobalBuddySendTask> datamsgbuf(std::move(_buf));
        nodemgr->sendTo(endItr->GetPeer().GetPeerAddr()._nodeid, datamsgbuf);
    }
}

void GlobalBuddyRspTask::replyChildChains(T_P2PPROTOCOLGLOBALBUDDYHEADER &globalBuddyHeader)
{
    uint32_t blockNum = 0;
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
    auto itrGlobal = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
    for (; itrGlobal != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itrGlobal++) {
        blockNum += static_cast<uint32_t>(itrGlobal->size());
    }

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    uint64 tempNum = g_tP2pManagerStatus.listGlobalBuddyChainInfo.size();

    T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyHeader;
    P2pProtocolGlobalBuddyHeader.uiHyperBlockHash = globalBuddyHeader.uiHyperBlockHash;
    P2pProtocolGlobalBuddyHeader.SetBlockCount(blockNum);
    P2pProtocolGlobalBuddyHeader.SetPeerAddr(T_PEERADDRESS(me->getNodeId<CUInt128>()));
    P2pProtocolGlobalBuddyHeader.SetChainCount(tempNum);

    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    oa << P2pProtocolGlobalBuddyHeader;

    uint32_t chainNum = 0;
    itrGlobal = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
    for (; itrGlobal != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itrGlobal++) {
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
    //HC: send to requester
    DataBuffer<GlobalBuddyRspTask> msgbuf(move(ssBuf.str()));

    if (globalBuddyHeader.GetPeerAddr()._nodeid != me->getNodeId<CUInt128>()) {
        CUInt128 _peerid = globalBuddyHeader.GetPeerAddr()._nodeid;
        nodemgr->sendTo(_peerid, msgbuf);
    }
}

void GlobalBuddyRspTask::execRespond()
{
    if (!g_tP2pManagerStatus.StartGlobalFlag()) {
        return;
    }

    T_SHA256 hyperblockhash = g_tP2pManagerStatus.GetConsensusPreHyperBlockHash();

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
    if (!g_tP2pManagerStatus.StartGlobalFlag()) {
        return;
    }

    if (!isEndNode()) {
        return;
    }

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    T_SHA256 hyperblockhash = g_tP2pManagerStatus.GetConsensusPreHyperBlockHash();
    uint32_t blockCount = 0;
    CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
    auto itr = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
    for (; itr != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itr++) {
        blockCount += static_cast<uint32_t>(itr->size());
    }

    T_P2PPROTOCOLGLOBALBUDDYHEADER P2pProtocolGlobalBuddyHeader;
    P2pProtocolGlobalBuddyHeader.uiHyperBlockHash = hyperblockhash;
    P2pProtocolGlobalBuddyHeader.SetP2pprotocolglobalconsensusreq( T_PEERADDRESS(me->getNodeId<CUInt128>()),
        blockCount, g_tP2pManagerStatus.listGlobalBuddyChainInfo.size());

    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    oa << P2pProtocolGlobalBuddyHeader;

    uint32_t chainNum = 0;
    auto itrSend = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
    for (; itrSend != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itrSend++) {
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
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<GlobalBuddyRspTask>(_payload, _payloadlen));
}