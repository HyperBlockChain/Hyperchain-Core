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
#include "buddyinfo.h"
#include "onchaintask.hpp"
#include "onchainconfirmtask.hpp"
#include "../node/TaskThreadPool.h"
#include "db/HyperchainDB.h"
#include "consensus_engine.h"
#include "consensus/globalbuddytask.h"
#include "consensus/hyperblockTask.hpp"

#include "headers/commonstruct.h"
#include "headers/lambda.h"
#include "headers/inter_public.h"

#include "../node/IAccessPoint.h"
#include "../node/UdpAccessPoint.hpp"
#include "../HyperChain/HyperData.h"
#include "../HyperChain/HyperChainSpace.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#define MAX_BUF_LEN (1024 * 32)

void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type);
void ChangeLocalBlockPreHash(LIST_T_LOCALCONSENSUS &localList);
bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);
void ReOnChainFun();
void GetOnChainInfo();
void updateMyBuddyBlock();
void SendConfirmReq(const CUInt128 &peerid, uint64 hyperblocknum, const string &hash, uint8 type);
void mergeChains(LIST_T_LOCALCONSENSUS &globallist, LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo);
bool CreateHyperBlock(T_HYPERBLOCK &tHyperChainBlock);
bool isConfirming(string &currBuddyHash);
bool isHyperBlockMatched(uint64 hyperblockid, const T_SHA256 &hash, const CUInt128 &peerid);
bool isEndNode();

void ConsensusEngine::TestOnchain()
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    UdpAccessPoint udpAP("127.0.0.1", 0);
    HCNode::APList &aplist = me->getAPList();

    string strIP("127.0.0.1");
    auto ap = aplist.begin();
    if (ap != aplist.end() && udpAP.id() == ap->get()->id()) {
        strIP = (reinterpret_cast<UdpAccessPoint*>(ap->get()))->ip();
    }

    std::function<void(int)> sleepfn = [this](int sleepseconds) {
        int i = 0;
        int maxtimes = sleepseconds * 1000 / 200;
        while (i++ < maxtimes) {
            if (_isstoptest) {
                break;
            }
            this_thread::sleep_for(chrono::milliseconds(200));
        }
    };

    int i = 0;
    while (!_isstoptest) {
        size_t s = 0;
        {
            CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistOnChainReq);
            s = g_tP2pManagerStatus.GetListOnChainReq().size();
        }
        if (s > 3) {
            sleepfn(30);
            continue;
        }

        string sPayLoad = strIP + "-" + to_string(i);
        string requestid;

        AddNewBlockEx(sPayLoad, requestid);
        cout << "Created a test block: " << requestid << endl;

        i++;
        sleepfn(30);
    }
}

uint32 ConsensusEngine::AddNewBlockEx(const string &strdata, string& requestid)
{
    g_tP2pManagerStatus.SetSendRegisReqNum(g_tP2pManagerStatus.GetSendRegisReqNum() + 1);
    g_tP2pManagerStatus.SetSendConfirmingRegisReqNum(g_tP2pManagerStatus.GetSendConfirmingRegisReqNum() + 1);

    T_LOCALBLOCK tLocalBlock;
    tLocalBlock.SetPayLoad(strdata);

    T_SHA256 preHyperBlockHash;
    uint64 localprehyperblockid = 0;
    g_tP2pManagerStatus.GetPreHyperBlockIDAndHash(localprehyperblockid, preHyperBlockHash);
    tLocalBlock.SetPreHyperBlock(localprehyperblockid,preHyperBlockHash);
    tLocalBlock.Rebuild();
    tLocalBlock.CalculateHashSelf();
    requestid = tLocalBlock.GetUUID(); //HC: base58

    g_tP2pManagerStatus.trackLocalBlock(tLocalBlock);

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    T_SHA256 h;
    GetSHA256(h.data(), strdata.c_str(), strdata.size());

    T_LOCALCONSENSUS LocalConsensusInfo(
        T_BLOCKSTATEADDR(T_PEERADDRESS(me->getNodeId<CUInt128>()), T_PEERADDRESS(me->getNodeId<CUInt128>())),
        tLocalBlock,
        0,
        (char*)h.data());

    //HC: 放入待上链链表排队，等待处理
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistOnChainReq);
    g_tP2pManagerStatus.GetListOnChainReq().push_back(std::move(LocalConsensusInfo));
    g_tP2pManagerStatus.SetSendPoeNum(g_tP2pManagerStatus.GetSendPoeNum() + 1);
    return static_cast<uint32>(g_tP2pManagerStatus.GetListOnChainReq().size());
}

void ConsensusEngine::start()
{
    g_tP2pManagerStatus.loadHyperBlockCache();
    if (g_tP2pManagerStatus.GetMaxBlockID() == 0) {
        GreateGenesisBlock();
    }

    _threads.emplace_back(&ConsensusEngine::exec, this);
    _threads.emplace_back(&ConsensusEngine::localBuddyReqThread, this);
    _threads.emplace_back(&ConsensusEngine::localBuddyRspThread, this);
    _threads.emplace_back(&ConsensusEngine::SearchOnChainStateThread, this);

    g_tP2pManagerStatus.tBuddyInfo.uiCurBuddyNo = g_tP2pManagerStatus.GetMaxBlockID() + 1;
    g_tP2pManagerStatus.tBuddyInfo.eBuddyState = IDLE;
}

void ConsensusEngine::stop()
{
    _isstop = true;
    for (auto& t : _threads) {
        t.join();
    }
    _threads.clear();
}

bool ConsensusEngine::checkConsensusCond()
{
    uint64 currMaxBlockNum = g_tP2pManagerStatus.GetMaxBlockID();
    CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    uint64 maxBlockNum = hyperchainspace->GetGlobalLatestHyperBlockNo();

    if (maxBlockNum > currMaxBlockNum) {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
        if (g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 0 &&
            g_tP2pManagerStatus.GetListOnChainReq().size() > 0) {
            //HC: 本节点当前没有参与本轮共识，但有数据在等待上链，所以需要获取最新超块
            g_tP2pManagerStatus.SetHaveOnChainReq(true);
            if (!_is_requested_latest_hyperblock) {
                GetLatestHyperBlock();
                _is_requested_latest_hyperblock = true;
            }
            SLEEP(2 * ONE_SECOND);
        }
        _is_able_to_consensus = false;
    }
    else {
        _is_able_to_consensus = true;
    }

    return _is_able_to_consensus;
}

void ConsensusEngine::prepareLocalBuddy()
{
    if (g_tP2pManagerStatus.HaveOnChainReq()) {
        {
            CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
            //put the block into pending-on-chain-list
            ReOnChainFun();
        }

        g_tP2pManagerStatus.SetHaveOnChainReq(false);
    }

    this_thread::sleep_for(chrono::milliseconds(200));
}

void ConsensusEngine::exec()
{
    bool indexGlobal = true;
    bool bFirstTimes = true;
    bool bCreatBlock = false;
    bool bNeedGetLastBlock = true;
    system_clock::time_point sendtimepoint = system_clock::now();
    while (!_isstop) {
        switch (g_tP2pManagerStatus.GetCurrentConsensusPhase())
        {
        case CONSENSUS_PHASE::PREPARE_LOCALBUDDY_PHASE:
            bFirstTimes = true;
            bNeedGetLastBlock = true;

            //HC: 处理上一个共识周期本地的上链数据，如果没有成功那么本周期准备重新上链
            updateMyBuddyBlock();

            g_tP2pManagerStatus.cleanConsensusEnv();

            if (checkConsensusCond()) {
                prepareLocalBuddy();
            }
            break;
        case CONSENSUS_PHASE::LOCALBUDDY_PHASE:
        {
            if (!_is_able_to_consensus) {
                if (checkConsensusCond()) {
                    prepareLocalBuddy();
                }
                break;
            }

            bCreatBlock = false;
            uint64 tempNum = 0;
            {
                CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
                tempNum = g_tP2pManagerStatus.listCurBuddyRsp.size();
            }
            if (tempNum != 0) {
                SLEEP(2 * ONE_SECOND);
                break;
            }

            indexGlobal = false;

            if (!g_tP2pManagerStatus.HaveOnChainReq()) {
                //HC: 将要共识的块数据放到共识队列 listLocalBuddyChainInfo
                GetOnChainInfo();
            }

            uint64 tempNum2 = 0;
            {
                CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
                tempNum2 = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
            }

            if (tempNum2 == 0) {
                SLEEP(2 * ONE_SECOND);
                break;
            }

            g_consensus_console_logger->trace("The Node enter LOCAL_BUDDY status, broadcast Local Consensus Request");
            g_tP2pManagerStatus.tBuddyInfo.eBuddyState = LOCAL_BUDDY;

            SendLocalBuddyReq();
            SLEEP(10 * ONE_SECOND);

            break;
        }
        case CONSENSUS_PHASE::GLOBALBUDDY_PHASE:
        {
            uint64 tempNum = 0;
            {
                CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
                tempNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
            }
            if (tempNum == 0 || tempNum == 1) {
                SLEEP(2 * ONE_SECOND);
                break;
            }

            if (!indexGlobal) {
                indexGlobal = true;
                g_consensus_console_logger->trace("The Node enter GLOBAL_BUDDY status");
                g_tP2pManagerStatus.SetStartGlobalFlag(true);
                g_tP2pManagerStatus.tBuddyInfo.eBuddyState = GLOBAL_BUDDY;
                StartGlobalBuddy();
            }
            else {
                //HC: Broadcast Global Consensus Request every 20 seconds
                if (system_clock::now() - sendtimepoint > std::chrono::seconds(20)) {
                    SendGlobalBuddyReq();
                    sendtimepoint = system_clock::now();
                }
            }
            SLEEP(2 * ONE_SECOND);
            break;
        }
        case CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE:
        {
            g_tP2pManagerStatus.SetStartGlobalFlag(false);
            indexGlobal = false;
            _is_able_to_consensus = false;
            _is_requested_latest_hyperblock = false;

            uint64 tempNum = 0;
            uint64 tempNum1 = 0;

            if (bFirstTimes) {
                {
                    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
                    tempNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();

                    CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
                    tempNum1 = g_tP2pManagerStatus.listGlobalBuddyChainInfo.size();
                }
                if (tempNum != 0 && tempNum1 != 0) {
                    bCreatBlock = isEndNode();
                    if (bCreatBlock) {
                        //HC: create hyper block
                        T_HYPERBLOCK tHyperChainBlock;
                        if (CreateHyperBlock(tHyperChainBlock)) {
                            //HC: update hyper into block memory cache
                            if (g_tP2pManagerStatus.updateHyperBlockCache(tHyperChainBlock)) {

                                bNeedGetLastBlock = false;
                                //HC: send hyper block to neighbors
                                TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
                                taskpool->put(make_shared<BoardcastHyperBlockTask>());
                            }
                        }
                    }
                }
                if (bNeedGetLastBlock) {
                    GetLatestHyperBlock();
                }

                bFirstTimes = false;
            }
            SLEEP(5 * ONE_SECOND);
            break;
        }
        }
    }
}

void ConsensusEngine::localBuddyReqThread()
{
    while (!_isstop) {
        if (g_tP2pManagerStatus.GetCurrentConsensusPhase() != CONSENSUS_PHASE::LOCALBUDDY_PHASE) {
            {
                CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyReq);
                g_tP2pManagerStatus.listCurBuddyReq.clear();

                CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
                g_tP2pManagerStatus.listRecvLocalBuddyReq.clear();
            }
            SLEEP(2 * ONE_SECOND);
            continue;
        }

        uint64 tempNum = 0;
        uint64 tempNum1 = 0;
        {
            CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyReq);
            tempNum1 = g_tP2pManagerStatus.listCurBuddyReq.size();

            CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
            tempNum = g_tP2pManagerStatus.listRecvLocalBuddyReq.size();
        }

        if (tempNum == 0) {
            SLEEP(2 * ONE_SECOND);
            continue;
        }

        if (tempNum1 > LIST_BUDDY_RSP_NUM) {
            SLEEP(2 * ONE_SECOND);
            continue;
        }
        else {
            T_BUDDYINFO localInfo;
            {
                CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
                localInfo = g_tP2pManagerStatus.listRecvLocalBuddyReq.front();
                g_tP2pManagerStatus.listRecvLocalBuddyReq.pop_front();
            }
            g_tP2pManagerStatus.tLocalBuddyAddr = localInfo.GetRequestAddress();

            TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
            taskpool->put(make_shared<OnChainRspTask>(localInfo.GetRequestAddress()._nodeid,
                std::move(localInfo.GetBuffer()),
                localInfo.GetBufferLength()));
        }
    }
}

void ConsensusEngine::localBuddyRspThread()
{
    while (!_isstop) {
        if (g_tP2pManagerStatus.GetCurrentConsensusPhase() != CONSENSUS_PHASE::LOCALBUDDY_PHASE) {
            {
                CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
                g_tP2pManagerStatus.listCurBuddyRsp.clear();

                CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
                g_tP2pManagerStatus.listRecvLocalBuddyRsp.clear();
            }
            SLEEP(2 * ONE_SECOND);
            continue;
        }

        uint64 tempNumTest = 0;
        uint64 tempNum = 0;
        {
            CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
            tempNum = g_tP2pManagerStatus.listCurBuddyRsp.size();

            CAutoMutexLock muxAuto2(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
            tempNumTest = g_tP2pManagerStatus.listRecvLocalBuddyRsp.size();
        }

        if (tempNumTest == 0) {
            SLEEP(2 * ONE_SECOND);
            continue;
        }

        if (tempNum > LIST_BUDDY_RSP_NUM) {
            SLEEP(2 * ONE_SECOND);
            continue;
        }
        else {
            T_BUDDYINFO localInfo;
            {
                CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
                localInfo = g_tP2pManagerStatus.listRecvLocalBuddyRsp.front();
                g_tP2pManagerStatus.listRecvLocalBuddyRsp.pop_front();
            }
            g_tP2pManagerStatus.tLocalBuddyAddr = localInfo.GetRequestAddress();

            ProcessOnChainRspMsg(localInfo.GetRequestAddress()._nodeid,
                const_cast<char*>(localInfo.GetBuffer().c_str()), localInfo.GetBufferLength());
        }
    }
}

time_t convert_str_to_tm(const char * str_time)
{
    struct tm tt;
    memset(&tt, 0, sizeof(tt));
    tt.tm_year = atoi(str_time) - 1900;
    tt.tm_mon = atoi(str_time + 5) - 1;
    tt.tm_mday = atoi(str_time + 8);
    tt.tm_hour = atoi(str_time + 11);
    tt.tm_min = atoi(str_time + 14);
    tt.tm_sec = atoi(str_time + 17);
    return mktime(&tt);
}

const uint64 GENESISBLOCKID = -1;

void ConsensusEngine::GreateGenesisBlock()
{
    T_SHA512 h(1);
    ostringstream oss;
    oss << "HyperChain, 2019/1/17";

    time_t t = convert_str_to_tm("2019-03-06 15:50:52");

    //HC:To GenesisBlock,block id is 0,previous hyper block id is -1
    T_LOCALBLOCK tLocalBlock;
    tLocalBlock.SetID(1);
    tLocalBlock.SetCTime(t);
    tLocalBlock.SetChainNum(1);
    tLocalBlock.SetPreHyperBlock(GENESISBLOCKID, T_SHA256(0));
    tLocalBlock.SetPayLoad(oss.str());
    tLocalBlock.Rebuild();
    tLocalBlock.CalculateHashSelf();

    LIST_T_LOCALBLOCK ListLocalBlock;
    ListLocalBlock.push_back(tLocalBlock);

    T_HYPERBLOCK tHyperBlock;
    tHyperBlock.SetID(0);
    tHyperBlock.SetCTime(t);
    tHyperBlock.SetWeight(1);
    tHyperBlock.SetPreHash(T_SHA256(0));
    tHyperBlock.SetPreHeaderHash(T_SHA256(0));

    tHyperBlock.AddChildChain(std::move(ListLocalBlock));
    tHyperBlock.Rebuild();

    g_tP2pManagerStatus.updateHyperBlockCache(tHyperBlock);

    g_tP2pManagerStatus.SetHaveOnChainReq(false);

}


void ConsensusEngine::ProcessOnChainRspMsg(const CUInt128 &peerid, char* pBuf, unsigned int uiBufLen)
{
    string sBuf(pBuf, uiBufLen);
    stringstream ssBuf(sBuf);
    boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

    T_P2PPROTOCOLONCHAINRSP P2pProtocolOnChainRspRecv;
    try {
        ia >> P2pProtocolOnChainRspRecv;
    }
    catch (runtime_error& e) {
        g_consensus_console_logger->warn("{}", e.what());
        return;
    }

    size_t nodeSize = 0;
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
    nodeSize = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
    if (nodeSize == 0) {
        return;
    }

    if (nodeSize != ONE_LOCAL_BLOCK && P2pProtocolOnChainRspRecv.GetBlockCount() != ONE_LOCAL_BLOCK) {
        return;
    }

    //HC: 如果超块不匹配拒绝并退出处理
    uint64 hyperchainnum = P2pProtocolOnChainRspRecv.GetHyperBlockNum();
    if (!isHyperBlockMatched(hyperchainnum, P2pProtocolOnChainRspRecv.tHyperBlockHash, peerid)) {
        g_consensus_console_logger->info("Refuse buddy request for different hyper block from {}", peerid.ToHexString());
        SendRefuseReq(peerid,
            string(P2pProtocolOnChainRspRecv.GetHash(), DEF_STR_HASH256_LEN), RECV_REQ);
        return;
    }

    //HC: 已经放入块集合中了吗？
    CAutoMutexLock muxAuto3(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
    ITR_LIST_T_BUDDYINFOSTATE itr = g_tP2pManagerStatus.listCurBuddyRsp.begin();
    for (; itr != g_tP2pManagerStatus.listCurBuddyRsp.end(); itr++) {
        if (0 == strncmp((*itr).strBuddyHash, P2pProtocolOnChainRspRecv.GetHash(), DEF_STR_HASH256_LEN)) {
            return;
        }
    }

    T_BUDDYINFOSTATE buddyInfo;
    copyLocalBuddyList(buddyInfo.localList, g_tP2pManagerStatus.listLocalBuddyChainInfo);

    bool index = false;
    bool isExistMyBlock = false;
    NodeManager *nodemanger = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemanger->myself();

    //HC: 这里取收到的所有块和已有的块合并
    for (uint64 i = 0; i < P2pProtocolOnChainRspRecv.GetBlockCount(); i++) {
        T_LOCALCONSENSUS  LocalBlockInfo;
        try {
            ia >> LocalBlockInfo;
        }
        catch (runtime_error& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        isExistMyBlock = false;
        if (LocalBlockInfo.GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            isExistMyBlock = true;
        }
        index = JudgExistAtLocalBuddy(buddyInfo.GetList(), LocalBlockInfo);
        if (isExistMyBlock && !index) {
            //HC: 出现2个本节点块,LocalBlockInfo此块是本节点的，但是已经不在buddy队列里
            g_consensus_console_logger->error("There are my two blocks in a consensus period,Skip...");
            //HC: Skip this buddy.
            return;
        }

        if (index)
            continue;

        buddyInfo.LocalListPushBack(LocalBlockInfo);
        buddyInfo.LocalListSort();
    }

    buddyInfo.Set(P2pProtocolOnChainRspRecv.GetHash(), RECV_ON_CHAIN_RSP, _tpeeraddress(peerid));

    //HC: listCurBuddyRsp中存储所有待共识的buddy组合
    g_tP2pManagerStatus.listCurBuddyRsp.push_back(buddyInfo);

    //HC: if my status isn't confirming, then send confirm request.
    //HC: here cannot call isConfirming function because MuxlistCurBuddyRsp object is used in isConfirming function.
    for (auto &buddy : g_tP2pManagerStatus.listCurBuddyRsp) {
        if (buddy.GetBuddyState() == SEND_CONFIRM) {
            return;
        }
    }
    SendConfirmReq(peerid, P2pProtocolOnChainRspRecv.uiHyperBlockNum,
        P2pProtocolOnChainRspRecv.GetHash(), P2P_PROTOCOL_SUCCESS);
}

void GetOnChainInfo()
{
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
    {
        if (g_tP2pManagerStatus.listOnChainReq.empty()) {
            g_tP2pManagerStatus.tBuddyInfo.eBuddyState = IDLE;
            return;
        }

        T_LOCALCONSENSUS onChainInfo;
        onChainInfo = g_tP2pManagerStatus.listOnChainReq.front();
        g_tP2pManagerStatus.listOnChainReq.pop_front();

        g_tP2pManagerStatus.listLocalBuddyChainInfo.push_back(onChainInfo);

        g_consensus_console_logger->info("GetOnChainInfo,listLocalBuddyChainInfo phase:{} push a block:{}",
            (uint8)g_tP2pManagerStatus.GetCurrentConsensusPhase(),
            onChainInfo.GetLocalBlock().GetPayLoadPreview());

        g_tP2pManagerStatus.listLocalBuddyChainInfo.sort(CmpareOnChain());

        int i = 0;
        for (auto &b : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
            g_consensus_console_logger->info("GetOnChainInfo,listLocalBuddyChainInfo:{} {}", ++i, b.GetLocalBlock().GetPayLoadPreview());
        }

        g_tP2pManagerStatus.tBuddyInfo.usBlockNum = static_cast<uint16>(g_tP2pManagerStatus.listLocalBuddyChainInfo.size());

        g_tP2pManagerStatus.tBuddyInfo.uiCurBuddyNo = g_tP2pManagerStatus.GetMaxBlockID() + 1;
        g_tP2pManagerStatus.tBuddyInfo.eBuddyState = LOCAL_BUDDY;
        g_tP2pManagerStatus.uiNodeState = CONFIRMING;

        g_tP2pManagerStatus.curBuddyBlock = onChainInfo;

    }

    g_tP2pManagerStatus.SetHaveOnChainReq(true);

    return;
}

void SendConfirmReq(const CUInt128 &peerid, uint64 hyperblocknum, const string &hash, uint8 type)
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<OnChainConfirmTask>(peerid, hyperblocknum, hash, type));
}

void ConsensusEngine::SendLocalBuddyReq()
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<OnChainTask>());
}

void copyLocalBuddyList(LIST_T_LOCALCONSENSUS &endList, LIST_T_LOCALCONSENSUS fromList)
{
    ITR_LIST_T_LOCALCONSENSUS itrList = fromList.begin();
    for (; itrList != fromList.end(); itrList++)
    {
        T_LOCALCONSENSUS tempBlock;
        tempBlock.SetLoaclConsensus((*itrList).GetPeer(), (*itrList).GetLocalBlock());
        endList.push_back(tempBlock);
    }
}

void putStream(boost::archive::binary_oarchive &oa, T_HYPERBLOCK &hyperblock)
{
    oa << hyperblock.GetHashSelf();
    oa << hyperblock;

    const vector<LIST_T_LOCALBLOCK>& childchains = hyperblock.GetChildChains();

    assert(hyperblock.GetChildChainsCount() == childchains.size());
    size_t totalBlocks = 0;
    for (auto &cchain : childchains) {
		uint32 blocknum = cchain.size();
		oa << blocknum;
		for (auto iter = cchain.begin(); iter != cchain.end(); iter++) {
			oa << (*iter);
		}
        totalBlocks += blocknum;
    }
    assert(hyperblock.GetChildBlockCount() == totalBlocks);
}


void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type)
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<OnChainRefuseTask>(peerid, hash, type));
}

void SendCopyLocalBlock(T_LOCALCONSENSUS &localBlock)
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<CopyBlockTask>(localBlock));
}

bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo)
{
    ITR_LIST_T_LOCALCONSENSUS itrList = localList.begin();
    for (; itrList != localList.end(); itrList++) {
        if (((*itrList).GetPeer().GetPeerAddr() == localBlockInfo.GetPeer().GetPeerAddr())
            && ((*itrList).GetPeer().GetPeerAddrOut() == localBlockInfo.GetPeer().GetPeerAddrOut())) {
            string h1 = (*itrList).GetLocalBlock().GetUUID();
            string h2 = localBlockInfo.GetLocalBlock().GetUUID();
            if ( h1 == h2) {
                return true;
            }
        }
    }
    return false;
}

bool MergeToGlobalBuddyChains(LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo)
{
    bool isNewChain = true;
    int num = 0;
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
    auto itr = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
    for (; itr != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itr++) {
        num++;

        size_t globalchainlen = itr->size();
        size_t localchainlen = listLocalBuddyChainInfo.size();

        LIST_T_LOCALCONSENSUS *localchain = &listLocalBuddyChainInfo;
        LIST_T_LOCALCONSENSUS *globalchain = &(*itr);
        if (globalchainlen < localchainlen) {
            //switch
            globalchain = &listLocalBuddyChainInfo;
            localchain = &(*itr);
        }
        auto globalblock = globalchain->begin();
        auto localblock = localchain->begin();

        bool isContained = true;
        LIST_T_LOCALCONSENSUS sameblocklist;
        for (; localblock != localchain->end(); localblock++) {
            globalblock = globalchain->begin();
            for (; globalblock != globalchain->end() && isContained; globalblock++) {
                if ((localblock->GetLocalBlock().GetUUID()
                    == globalblock->GetLocalBlock().GetUUID())) {
                    //HC: block is same,compare the next block.
                    sameblocklist.push_back(*localblock);
                    break;
                }
            }
            if (globalblock == globalchain->end()) {
                isContained = false;
                break;
            }
        }

        size_t sameblocknumber = sameblocklist.size();
        if (sameblocknumber > 0 && !isContained) {

            if (sameblocknumber > 1) {
                //HC: merge two chains,Two chains have 2 or more than 2 blocks is same.
                g_consensus_console_logger->info("merge two chains");
                mergeChains(*itr, listLocalBuddyChainInfo);
                return false;

            }
            else {
                //HC: This is a critical error.
                //HC: Todo
                g_consensus_console_logger->critical("Two chains have {} same block: ", sameblocknumber);
                for (auto &b : listLocalBuddyChainInfo) {
                    g_consensus_console_logger->critical("ReceivedChainInfo block: {} {}",
                        b.tLocalBlock.GetID(),
                        b.tLocalBlock.GetPayLoadPreview());
                }
                for (auto &b : *itr) {
                    g_consensus_console_logger->critical("ExistedChainInfo block is: {} {}",
                        b.tLocalBlock.GetID(),
                        b.tLocalBlock.GetPayLoadPreview());
                }
                for (auto &b : sameblocklist) {
                    g_consensus_console_logger->critical("same block is: {} {}",
                        b.tLocalBlock.GetID(),
                        b.tLocalBlock.GetPayLoadPreview());
                }
            }
        }

        if (sameblocknumber == 0 && !isContained) {
            continue;
        }
        if (isContained) {
            if (globalchainlen == localchainlen) {
                g_consensus_console_logger->trace("The chain is same with another one.");
            }
            else {
                g_consensus_console_logger->warn("The chain contains another one.");
            }
            if (globalchainlen < localchainlen) {
                g_tP2pManagerStatus.listGlobalBuddyChainInfo.erase(itr);
                isNewChain = true;
            }
            else {
                isNewChain = false;
            }
            break;
        }
    }

    if (isNewChain) {
        if (listLocalBuddyChainInfo.size() >= LEAST_START_GLOBAL_BUDDY_NUM) {
            g_tP2pManagerStatus.listGlobalBuddyChainInfo.push_back(listLocalBuddyChainInfo);
            g_tP2pManagerStatus.tBuddyInfo.usChainNum = static_cast<uint16>(g_tP2pManagerStatus.listGlobalBuddyChainInfo.size());
            g_tP2pManagerStatus.listGlobalBuddyChainInfo.sort(CmpareGlobalBuddy());
        }
    }

    return isNewChain;
}

void mergeChains(LIST_T_LOCALCONSENSUS &globallist, LIST_T_LOCALCONSENSUS &locallist)
{
    for (auto &localblock : locallist) {
        auto r = std::find_if(globallist.begin(), globallist.end(), [&](const T_LOCALCONSENSUS &globalblock) {
            if ((localblock.GetLocalBlock().GetUUID()
                == globalblock.GetLocalBlock().GetUUID())) {
                return true;
            }
            return false;
        });

        if (r == globallist.end()) {
            globallist.emplace_back(localblock);
        }
    }
}

//HC: on chain try again
void ReOnChainFun()
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();

    T_LOCALCONSENSUS localInfo;
    ITR_LIST_T_LOCALCONSENSUS itrList = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
    for (; itrList != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itrList++) {
        if ((*itrList).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            localInfo = (*itrList);

            localInfo.uiRetryTime += 1;
            g_tP2pManagerStatus.listLocalBuddyChainInfo.clear();
            g_tP2pManagerStatus.listOnChainReq.push_front(localInfo);
            g_consensus_console_logger->info("***ReOnChainFun***: phase:{} block:{}",
                (uint8)g_tP2pManagerStatus.GetCurrentConsensusPhase(),
                localInfo.GetLocalBlock().GetPayLoadPreview());
            break;
        }
    }
}

bool CurBuddyBlockInTheHyperBlock(T_HYPERBLOCK &blockInfos, T_LOCALCONSENSUS *buddyblock)
{
    bool index = false;
    auto itr = blockInfos.GetChildChains().begin();
    for (; itr != blockInfos.GetChildChains().end(); itr++) {
        ITR_LIST_T_LOCALBLOCK subItr = itr->begin();
        for (; subItr != itr->end(); subItr++) {
            //HC: don't use block hash which is variable
            if (buddyblock->GetLocalBlockUUID() == subItr->GetUUID()) {
                index = true;
                break;
            }
        }

        if (index) {
            break;
        }
    }
    return index;
}

//HC: 块数据是否上链成功，如果不成功下个共识周期继续上链
//HC: 如果上链成功，清空上链数据链表
//HC: TO DO: 这里不完善需要改进，未考虑分叉情况,一旦分叉上链的结果可能完全不同。
void updateMyBuddyBlock()
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();

    //HC: Is my local block in hyperblock?
    bool isfound = false;
    T_LOCALCONSENSUS *localInfo;
    CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
    if (g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 0) {
        return;
    }
    ITR_LIST_T_LOCALCONSENSUS itrList = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
    for (; itrList != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itrList++) {
        if ((*itrList).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
            localInfo = &(*itrList);
            isfound = true;
            break;
        }
    }

    bool isIncluded = false;
    if (isfound) {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.m_MuxHchainBlockList);
        isIncluded = CurBuddyBlockInTheHyperBlock(g_tP2pManagerStatus.GetPreHyperBlock(), localInfo);
    }
    g_consensus_console_logger->info("updateMyBuddyBlock: current buddy block included in hyperblock? {}", isIncluded);
    if (!isIncluded) {
        ReOnChainFun();
    }
    else {
        //HC: All block in hyper chain,so clear local buddy chain.
        g_tP2pManagerStatus.uiSendConfirmingRegisReqNum -= 1;
        g_tP2pManagerStatus.listLocalBuddyChainInfo.clear();
    }
}


void ConsensusEngine::StartGlobalBuddy()
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<GlobalBuddyStartTask>());
}

void ConsensusEngine::SendGlobalBuddyReq()
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<GlobalBuddySendTask>());
}


void ConsensusEngine::GetLatestHyperBlock()
{
    if (g_tP2pManagerStatus.HaveOnChainReq()) {
        uint64 localHID = g_tP2pManagerStatus.GetMaxBlockID();
        CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        uint64 globalHID = hyperchainspace->GetGlobalLatestHyperBlockNo();

        if (globalHID > localHID) {
            //HC: Download Lastest HyperBlock on Remote Node
            hyperchainspace->GetRemoteHyperBlockByID(globalHID);

            g_consensus_console_logger->info("Downloading Hyperblock {} from Hyperchain network.", globalHID);
        }
    }
}

ONCHAINSTATUS ConsensusEngine::GetOnChainState(const LB_UUID& requestId, size_t &queuenum)
{
    {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistOnChainReq);
        LIST_T_LOCALCONSENSUS::iterator itrOnChain = g_tP2pManagerStatus.listOnChainReq.begin();
        queuenum = 0;
        for (; itrOnChain != g_tP2pManagerStatus.listOnChainReq.end(); itrOnChain++) {
            queuenum++;
            if (0 == requestId.compare((*itrOnChain).GetLocalBlockUUID().c_str())) {
                return ONCHAINSTATUS::queueing;
            }
        }
    }

    {
        CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
        LIST_T_LOCALCONSENSUS::iterator itrOnChaining = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
        for (; itrOnChaining != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itrOnChaining++) {
            if (0 == requestId.compare((*itrOnChaining).GetLocalBlockUUID().c_str())) {
                CONSENSUS_PHASE phase = g_tP2pManagerStatus.GetCurrentConsensusPhase();
                if ((phase == CONSENSUS_PHASE::GLOBALBUDDY_PHASE || phase == CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE)
                    && g_tP2pManagerStatus.listLocalBuddyChainInfo.size() > 1) {
                    return ONCHAINSTATUS::onchaining2;
                }
                return ONCHAINSTATUS::onchaining1;
            }
        }
    }

    return ONCHAINSTATUS::unknown;
}

bool ConsensusEngine::CheckSearchOnChainedPool(const LB_UUID& requestId, T_LOCALBLOCKADDRESS& addr)
{
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxMapSearchOnChain);
    if (g_tP2pManagerStatus.mapSearchOnChain.count(requestId) > 0) {
        addr = g_tP2pManagerStatus.mapSearchOnChain.at(requestId).addr;
        return true;
    }
    return false;
}


void ConsensusEngine::SearchOnChainStateThread()
{
    std::function<void(int)> sleepfn = [this](int sleepseconds) {
        int i = 0;
        int maxtimes = sleepseconds * 1000 / 200;
        while (i++ < maxtimes) {
            if (_isstop) {
                break;
            }
            this_thread::sleep_for(chrono::milliseconds(200));
        }
    };
    while (!_isstop)
    {
        {
            CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxMapSearchOnChain);
            ITR_MAP_T_SEARCHONCHAIN itr = g_tP2pManagerStatus.mapSearchOnChain.begin();
            for (; itr != g_tP2pManagerStatus.mapSearchOnChain.end();) {
                size_t queuenum;
                ONCHAINSTATUS status = GetOnChainState((*itr).first, queuenum);
                uint64 timeNow = (uint64)time(nullptr);
                if (timeNow - (*itr).second.uiTime > MATURITY_TIME &&
                    status == ONCHAINSTATUS::unknown) {
                    //HC: 已经成熟且未在进行共识，删除
                    itr = g_tP2pManagerStatus.mapSearchOnChain.erase(itr);
                }
                else {
                    itr++;
                }
            }
        }

        sleepfn(5 * 60);
    }
}

LIST_T_LOCALCONSENSUS ConsensusEngine::GetPoeRecordList()
{
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistOnChainReq);
    return g_tP2pManagerStatus.listOnChainReq;
}

uint16 ConsensusEngine::GetStateOfCurrentConsensus(uint64 &blockNo, uint16 &blockNum, uint16 &chainNum)
{
    blockNo = g_tP2pManagerStatus.GetBuddyInfo().GetCurBuddyNo();
    blockNum = g_tP2pManagerStatus.GetBuddyInfo().GetBlockNum();
    chainNum = g_tP2pManagerStatus.GetBuddyInfo().GetChainNum();

    return g_tP2pManagerStatus.GetBuddyInfo().GetBuddyState();
}

void PutIntoConsensusList(T_BUDDYINFOSTATE &buddyinfostate)
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH & me = nodemgr->myself();

    buddyinfostate.uibuddyState = CONSENSUS_CONFIRMED;
    bool index = false;
    //HC: put child blocks into consensus list: listLocalBuddyChainInfo
    ITR_LIST_T_LOCALCONSENSUS itrSub = buddyinfostate.localList.begin();
    for (; itrSub != buddyinfostate.localList.end(); itrSub++) {
        index = JudgExistAtLocalBuddy(g_tP2pManagerStatus.listLocalBuddyChainInfo, (*itrSub));
        if (index)
            continue;

        g_consensus_console_logger->info("PutIntoConsensusList: push block into listLocalBuddyChainInfo: {}",
            (*itrSub).GetLocalBlock().GetPayLoadPreview());
        g_tP2pManagerStatus.listLocalBuddyChainInfo.push_back((*itrSub));
        g_tP2pManagerStatus.listLocalBuddyChainInfo.sort(CmpareOnChain());
        g_tP2pManagerStatus.tBuddyInfo.usBlockNum = static_cast<uint16>(g_tP2pManagerStatus.listLocalBuddyChainInfo.size());

        if ((*itrSub).GetPeer().GetPeerAddr()._nodeid != me->getNodeId<CUInt128>()) {
            g_tP2pManagerStatus.SetRecvPoeNum(g_tP2pManagerStatus.GetRecvPoeNum() + 1);
        }
        SendCopyLocalBlock((*itrSub));

        g_tP2pManagerStatus.SetRecvRegisReqNum(g_tP2pManagerStatus.GetRecvRegisReqNum() + 1);
        g_tP2pManagerStatus.SetRecvConfirmingRegisReqNum(g_tP2pManagerStatus.GetRecvConfirmingRegisReqNum() + 1);
    }
}

bool makeBuddy(const string & confirmhash)
{
    bool ismakebuddy = false;
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
    {
        CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
        ITR_LIST_T_BUDDYINFOSTATE itrRsp = g_tP2pManagerStatus.listCurBuddyRsp.begin();
        for (; itrRsp != g_tP2pManagerStatus.listCurBuddyRsp.end();) {
            if (0 == strncmp((*itrRsp).strBuddyHash, confirmhash.c_str(), DEF_STR_HASH256_LEN)) {
                (*itrRsp).uibuddyState = CONSENSUS_CONFIRMED;
            }
            else if ((*itrRsp).GetBuddyState() != CONSENSUS_CONFIRMED) {
                SendRefuseReq((*itrRsp).GetPeerAddrOut()._nodeid,
                    string((*itrRsp).strBuddyHash, DEF_STR_HASH256_LEN), RECV_REQ);
                itrRsp = g_tP2pManagerStatus.listCurBuddyRsp.erase(itrRsp);
                continue;
            }
            ++itrRsp;
        }
    }

    {
        CAutoMutexLock muxAutoReq(g_tP2pManagerStatus.MuxlistCurBuddyReq);

        auto itr = g_tP2pManagerStatus.listCurBuddyReq.begin();
        for (; itr != g_tP2pManagerStatus.listCurBuddyReq.end();) {
            if (0 == strncmp((*itr).strBuddyHash, confirmhash.c_str(), DEF_STR_HASH256_LEN) && (*itr).uibuddyState != CONSENSUS_CONFIRMED) {
                PutIntoConsensusList(*itr);
                int i = 0;
                for (auto &b : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
                    g_consensus_console_logger->info("makeBuddy: listLocalBuddyChainInfo: {} {}", ++i, b.GetLocalBlock().GetPayLoadPreview());
                }
                ismakebuddy = true;
            }
            else if ((*itr).GetBuddyState() != CONSENSUS_CONFIRMED) {
                SendRefuseReq((*itr).GetPeerAddrOut()._nodeid,
                    string((*itr).strBuddyHash, DEF_STR_HASH256_LEN), RECV_RSP);
                itr = g_tP2pManagerStatus.listCurBuddyReq.erase(itr);
                continue;
            }
            ++itr;
        }
    }

    g_consensus_console_logger->info("makeBuddy: listCurBuddyReq size: {} listCurBuddyRsp size: {}, makebuddy:{}",
        g_tP2pManagerStatus.listCurBuddyReq.size(),
        g_tP2pManagerStatus.listCurBuddyRsp.size(), ismakebuddy);

    if (ismakebuddy) {
        CAutoMutexLock muxAuto2(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
        g_tP2pManagerStatus.listRecvLocalBuddyRsp.clear();

        CAutoMutexLock muxAuto3(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
        g_tP2pManagerStatus.listRecvLocalBuddyReq.clear();
    }
    return ismakebuddy;
}

bool isConfirming(string &currBuddyHash)
{
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
    for (auto &buddy : g_tP2pManagerStatus.listCurBuddyRsp) {
        if (buddy.GetBuddyState() == SEND_CONFIRM) {
            currBuddyHash = string(buddy.GetBuddyHash(), DEF_STR_HASH256_LEN);
            return true;
        }
    }
    return false;
}

bool CreateHyperBlock(T_HYPERBLOCK &tHyperBlock)
{
    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);

    auto localconsensus = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();

    CAutoMutexLock muxAuto1(g_tP2pManagerStatus.m_MuxHchainBlockList);
    T_HYPERBLOCK &preHyperBlock = g_tP2pManagerStatus.GetPreHyperBlock();

    const T_SHA256& hhash = preHyperBlock.GetHashSelf();

    if (localconsensus->GetLocalBlock().GetPreHHash() != hhash) {
        if (!g_tP2pManagerStatus.getHyperBlock(localconsensus->GetLocalBlock().GetPreHHash(), preHyperBlock)) {
            g_consensus_console_logger->error("Failed to Creat HyperBlock: {}, preHyperBlock don't exist",
                localconsensus->GetLocalBlock().GetHID());
            return false;
        }
    }

    tHyperBlock.SetID(preHyperBlock.GetID() + 1);
    tHyperBlock.SetPreHash(preHyperBlock.GetHashSelf());
    tHyperBlock.SetCTime(g_tP2pManagerStatus.GettTimeOfConsensus());
    tHyperBlock.SetPreHeaderHash(preHyperBlock.calculateHeaderHashSelf());

    uint16 blockNum = 0;
    LIST_T_LOCALBLOCK listLocalBlockInfo;
    list<LIST_T_LOCALBLOCK> listPayLoad;

    g_consensus_console_logger->anyway("Creating HyperBlock: {}", tHyperBlock.header.uiID);

    uint32_t chainnum = 0;
    auto itr = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
    for (; itr != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); ++itr) {

        chainnum++;
        blockNum = 0;
        auto subItr = (*itr).begin();
        for (; subItr != (*itr).end(); ++subItr) {

            T_SHA256 hhash = subItr->GetLocalBlock().GetPreHHash();
            if (preHyperBlock.GetHashSelf() != hhash) {
                g_consensus_console_logger->error("Error prehyperblock hash, {} payload:{},skip the block...",
                    tHyperBlock.GetID(),
                    subItr->tLocalBlock.GetPayLoadPreview());
                continue;
            }
            blockNum += 1;
            g_consensus_console_logger->anyway("\t HyperBlock: {}:{} payload:{}", chainnum, blockNum,
                subItr->tLocalBlock.GetPayLoadPreview());

            listLocalBlockInfo.emplace_back((*subItr).tLocalBlock);
        }

        listLocalBlockInfo.sort(CmpareOnChainLocal());
        tHyperBlock.AddChildChain(std::move(listLocalBlockInfo));
        listLocalBlockInfo.clear();
    }

    tHyperBlock.Rebuild();

    g_consensus_console_logger->anyway("New HyperBlock: {} hash:{}", tHyperBlock.GetID(),
                                    tHyperBlock.GetHashSelf().toHexString());
    return true;
}

//HC: 计算本节点是否是共识链上最后一个节点如果是则负责创建超块
bool isEndNode()
{
    bool isEndNodeBuddyChain = false;

    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();

    CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
    if (g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 0)
        return false;
    LIST_T_LOCALCONSENSUS::iterator itr = g_tP2pManagerStatus.listLocalBuddyChainInfo.end();
    itr--;

    if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
        isEndNodeBuddyChain = true;
    }

    return isEndNodeBuddyChain;
}

bool isHyperBlockMatched(uint64 hyperblockid, const T_SHA256 &hash, const CUInt128 &peerid)
{
    T_SHA256 preHyperBlockHash;
    uint64 localhyperblockid = 0;
    g_tP2pManagerStatus.GetPreHyperBlockIDAndHash(localhyperblockid, preHyperBlockHash);

    bool isMatched = true;
    bool isNeedUpdateHyperBlock = false;
    if (localhyperblockid != hyperblockid) {
        g_consensus_console_logger->info("Refuse: local previous HyperBlockID:{}, recv buddy HyperBlockID:{}",
            localhyperblockid, hyperblockid);

        isMatched = false;
        if (localhyperblockid < hyperblockid) {
            isNeedUpdateHyperBlock = true;
        }
    }
    else if (hash != preHyperBlockHash) {
        g_consensus_console_logger->info("Refuse: local previous HyperBlock Hash:{}, recv hash:{}",
            preHyperBlockHash.toHexString(), hash.toHexString());

        isMatched = false;
        if (hash < preHyperBlockHash) {
            isNeedUpdateHyperBlock = true;
        }
    }

    if (isNeedUpdateHyperBlock) {
        //HC: give me your hyper block
        g_consensus_console_logger->info("Hello friend, give me your HyperBlock:{}", hyperblockid);
        CHyperData hyperdata;
        hyperdata.PullHyperDataByHID(hyperblockid, peerid.ToHexString());
    }
    return isMatched;
}
