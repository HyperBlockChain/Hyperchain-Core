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

#include "newLog.h"
#include "buddyinfo.h"
#include "db/HyperchainDB.h"
#include "headers/lambda.h"
#include "node/Singleton.h"
#include "node/NodeManager.h"
#include "node/MsgHandler.h"
#include "consensus_engine.h"
#include "../HyperChain/HyperChainSpace.h"


uint64 _tBuddyInfo::GetCurBuddyNo()const
{
    return uiCurBuddyNo;
}

uint16 _tBuddyInfo::GetBlockNum()const
{
    return usBlockNum;
}

uint16 _tBuddyInfo::GetChainNum()const
{
    return usChainNum;
}

uint8 _tBuddyInfo::GetBuddyState()const
{
    return eBuddyState;
}

void _tBuddyInfo::SetBlockNum(uint16 num)
{
    usBlockNum = num;
}

uint64 _tOnChainHashInfo::GetTime()const
{
    return uiTime;
}

string _tOnChainHashInfo::GetHash()const
{
    return strHash;
}

void _tOnChainHashInfo::Set(uint64 t, string h)
{
    uiTime = t;
    strHash = h;
}

void _tp2pmanagerstatus::ClearStatus()
{
    bStartGlobalFlag = false;
    bHaveOnChainReq = false;
    uiNodeState = DEFAULT_REGISREQ_STATE;
    listLocalBuddyChainInfo.clear();
    tBuddyInfo.uiCurBuddyNo = 0;
    tBuddyInfo.eBuddyState = IDLE;
    tBuddyInfo.usBlockNum = 0;
    tBuddyInfo.usChainNum = 0;
}

bool _tp2pmanagerstatus::StartGlobalFlag()const
{
    return bStartGlobalFlag;
}

bool _tp2pmanagerstatus::HaveOnChainReq()const
{
    return bHaveOnChainReq;
}

T_SHA256 _tp2pmanagerstatus::GetConsensusPreHyperBlockHash()const
{
    if (listLocalBuddyChainInfo.size() > 0) {
        auto itrLocal = listLocalBuddyChainInfo.begin();
        return itrLocal->GetLocalBlock().GetPreHHash();
    }

    auto itr = listGlobalBuddyChainInfo.begin();

    if (itr != listGlobalBuddyChainInfo.end()) {
        return itr->begin()->GetLocalBlock().GetPreHHash();
    }
    return T_SHA256(0);
}

uint16 _tp2pmanagerstatus::GetNodeState()const
{
    return uiNodeState;
}

uint64 _tp2pmanagerstatus::GettTimeOfConsensus()
{
    time_t now = time(nullptr);
    uint32 pos = now % NEXTBUDDYTIME;
    return (now - pos + NEXTBUDDYTIME);
}

CONSENSUS_PHASE _tp2pmanagerstatus::GetCurrentConsensusPhase() const
{
    time_t now = time(nullptr);
    uint32 pos = now % NEXTBUDDYTIME;
    if (pos <= LOCALBUDDYTIME) {
        return CONSENSUS_PHASE::LOCALBUDDY_PHASE;
    }
    if (pos <= GLOBALBUDDYTIME) {
        return CONSENSUS_PHASE::GLOBALBUDDY_PHASE;
    }

    if (pos < NEXTBUDDYTIME - 8) {
        return CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE;
    }
    return CONSENSUS_PHASE::PREPARE_LOCALBUDDY_PHASE;
}


T_PEERADDRESS _tp2pmanagerstatus::GetLocalBuddyAddr()const
{
    return tLocalBuddyAddr;
}

bool _tp2pmanagerstatus::ReplyMsg(int t, zmsg *msg)
{
    T_P2PMANAGERSTATUS::SERVICE st = (T_P2PMANAGERSTATUS::SERVICE)t;
    switch (st) {
        case SERVICE::GetListOnChainReqCount: {
            size_t s = GetListOnChainReqCount();
            msg->push_front(&s, sizeof(s));
            break;
        }
        case SERVICE::RequestOnChain: {

            T_LOCALCONSENSUS *LocalConsensusTemp = nullptr;
            MQMsgPop(msg, LocalConsensusTemp);

            RequestOnChain(*LocalConsensusTemp);
            break;
        }
        case SERVICE::TrackLocalBlock: {

            T_LOCALBLOCK *LocalBlockTemp = nullptr;
            MQMsgPop(msg, LocalBlockTemp);

            TrackLocalBlock(*LocalBlockTemp);
            break;
        }
    default:
        return false;
    }
    return true;
}

size_t _tp2pmanagerstatus::GetListOnChainReqCount()
{
    if (threadid == std::this_thread::get_id()) {
        return listOnChainReq.size();
    }
    else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)T_P2PMANAGERSTATUS::SERVICE::GetListOnChainReqCount);

        size_t nCount = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, nCount);
            delete rspmsg;
        }
        return nCount;
    }
};

void _tp2pmanagerstatus::RequestOnChain(const T_LOCALCONSENSUS& LocalConsensusInfo)
{
    if (threadid == std::this_thread::get_id()) {
        listOnChainReq.push_back(LocalConsensusInfo);
    }
    else {
        //stringstream ssBuf;
        //boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        //oa << LocalConsensusInfo;
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)T_P2PMANAGERSTATUS::SERVICE::RequestOnChain, &LocalConsensusInfo);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void _tp2pmanagerstatus::TrackLocalBlock(const T_LOCALBLOCK & localblock)
{
    if (threadid == std::this_thread::get_id()) {
        LB_UUID uuid = localblock.GetUUID();

        T_LOCALBLOCKADDRESS addr;
        T_SEARCHINFO searchinfo;
        mapSearchOnChain[uuid] = searchinfo;
    }
    else {
        zmsg *rspmsg = MQRequest(CONSENSUS_SERVICE, (int)T_P2PMANAGERSTATUS::SERVICE::TrackLocalBlock, &localblock);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void _tp2pmanagerstatus::SetStartGlobalFlag(bool flag)
{
    bStartGlobalFlag = flag;
}

void _tp2pmanagerstatus::SetHaveOnChainReq(bool haveOnChainReq)
{
    bHaveOnChainReq = haveOnChainReq;
}

void _tp2pmanagerstatus::SetNodeState(uint16 state)
{
    uiNodeState = state;
}

T_STRUCTBUDDYINFO _tp2pmanagerstatus::GetBuddyInfo()const
{
    return tBuddyInfo;
}

void _tp2pmanagerstatus::SetBuddyInfo(T_STRUCTBUDDYINFO info)
{
    tBuddyInfo = info;
}

void _tp2pmanagerstatus::ToAppPayloads(const T_HYPERBLOCK &hyperblock, map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload)
{
    uint32 uiChainNum = 1;

    const auto& childchainlist = hyperblock.GetChildChains();
    for (auto& childchain : childchainlist) {
        for (auto& block : childchain) {
            T_APPTYPE appt = block.GetAppType();
            T_LOCALBLOCKADDRESS address;
            address.set(hyperblock.GetID(),
                uiChainNum,
                block.GetID());

            if (mapPayload.count(appt)) {
                mapPayload[appt].emplace_back(address, block.GetPayLoad());
            }
            else {
                mapPayload.insert(make_pair(appt,
                    vector<T_PAYLOADADDR>({ T_PAYLOADADDR(address,block.GetPayLoad()) })));
            }
        }
        uiChainNum++;
    }
}

bool _tp2pmanagerstatus::ApplicationCheck(T_HYPERBLOCK &hyperblock)
{
    map<T_APPTYPE, vector<T_PAYLOADADDR>> mapPayload;
    ToAppPayloads(hyperblock, mapPayload);

    for (auto& a : mapPayload) {
        CBRET ret = AppCallback<cbindex::VALIDATECHAINIDX>(a.first, a.second);
        if (ret == CBRET::REGISTERED_FALSE) {
            return false;
        }
    }
    return true;
}

bool _tp2pmanagerstatus::ApplicationAccept(uint32_t hidFork, T_HYPERBLOCK &hyperblock, bool isLatest)
{
    map<T_APPTYPE, vector<T_PAYLOADADDR>> mapPayload;
    ToAppPayloads(hyperblock, mapPayload);

    T_APPTYPE genesisledger(APPTYPE::ledger, 0, 0, 0);
    if (mapPayload.count(genesisledger)) {
        AppCallback<cbindex::HANDLEGENESISIDX>(genesisledger, mapPayload.at(genesisledger));
        mapPayload.erase(genesisledger);
    }

    T_APPTYPE genesisparacoin(APPTYPE::paracoin, 0, 0, 0);
    if (mapPayload.count(genesisparacoin)) {
        AppCallback<cbindex::HANDLEGENESISIDX>(genesisparacoin, mapPayload.at(genesisparacoin));
        mapPayload.erase(genesisparacoin);
    }

    T_SHA256 thash = hyperblock.GetHashSelf();
    uint32_t hid = hyperblock.GetID();

    AllAppCallback<cbindex::ACCEPTCHAINIDX>(mapPayload, hidFork, hid, thash, isLatest);
    return true;
}


void _tp2pmanagerstatus::UpdateOnChainingState(const T_HYPERBLOCK &hyperblock)
{
    bool isfound = false;
    uint32 uiChainNum = 1;
    auto childchainlist = hyperblock.GetChildChains();
    for (auto &childchain : childchainlist) {
        std::find_if(childchain.begin(), childchain.end(), [this, &isfound, &hyperblock, uiChainNum](const T_LOCALBLOCK & elem) {
            LB_UUID uuid = elem.GetUUID();
            if (mapSearchOnChain.count(uuid) > 0) {
                isfound = true;
                T_SEARCHINFO searchInfo;
                searchInfo.addr.set(hyperblock.GetID(), uiChainNum, elem.GetID());
                mapSearchOnChain[uuid] = searchInfo;

                Singleton<DBmgr>::instance()->updateOnChainState(uuid, searchInfo.addr);
                return true;
            }
            return false;
        });
        uiChainNum++;
        if (isfound) {
            break;
        }
    }
}

void _tp2pmanagerstatus::UpdateLocalBuddyBlockToLatest(uint64 prehyperblockid, const T_SHA256& preHyperBlockHash)
{
    if (listLocalBuddyChainInfo.size() == ONE_LOCAL_BLOCK) {

        auto itr = listLocalBuddyChainInfo.begin();
        T_LOCALBLOCK& localblock = itr->GetLocalBlock();
        string newPayload;
        CBRET ret = AppCallback<cbindex::REONCHAINIDX>(localblock.GetAppType(),
            localblock.GetPayLoad(), newPayload);
        if (ret == CBRET::REGISTERED_TRUE) {
            localblock.SetPayLoad(newPayload);
            localblock.CalculateHashSelf();
        }

        localblock.updatePreHyperBlockInfo(prehyperblockid, preHyperBlockHash);
    }
}

void _tp2pmanagerstatus::CleanConsensusEnv()
{
    listGlobalBuddyChainInfo.clear();
    listCurBuddyRsp.clear();
    listRecvLocalBuddyRsp.clear();
    listCurBuddyReq.clear();
    listRecvLocalBuddyReq.clear();
}


void _tp2pmanagerstatus::InitOnChainingState(uint64 hid)
{
    for (auto & elem : mapSearchOnChain) {
        if (hid == elem.second.GetHyperID()) {
            T_SEARCHINFO &searchInfo = elem.second;
            searchInfo.addr.set(hid, -1, -1);
        }
    }
    Singleton<DBmgr>::instance()->initOnChainState(hid);
}

void _tp2pmanagerstatus::RehandleOnChainingState(uint64 hid)
{
    uint64 hyperid = 0;
    for (auto & elem : mapSearchOnChain) {
        hyperid = elem.second.GetHyperID();
        if (hyperid >= hid) {
            T_SEARCHINFO &searchInfo = elem.second;
            searchInfo.addr.set(hyperid, -1, -1);
        }
    }
    Singleton<DBmgr>::instance()->rehandleOnChainState(hid);
}

void _tp2pmanagerstatus::SetAppCallback(const T_APPTYPE &app, const CONSENSUSNOTIFY &notify)
{
    _mapcbfn[app] = notify;
}

void _tp2pmanagerstatus::RemoveAppCallback(const T_APPTYPE & app)
{
    if (_mapcbfn.count(app)) {
        _mapcbfn.erase(app);
    }
}

void _tp2pmanagerstatus::GetMulticastNodes(vector<CUInt128> &MulticastNodes)
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();
    bool found = false;

    if (listGlobalBuddyChainInfo.empty()) {
        g_consensus_console_logger->warn("GetMulticastNodes(), listGlobalBuddyChainInfo empty");
        return;
    }

    ITR_LIST_T_LOCALCONSENSUS itrList;
    auto itr = listGlobalBuddyChainInfo.begin();
    for (; itr != listGlobalBuddyChainInfo.end(); itr++) {
        itrList = (*itr).end();
        itrList--;
        if ((*itrList).GetPeer().GetPeerAddr().GetNodeid() == me->getNodeId<CUInt128>()) {
            found = true;
            break;
        }
    }

    if (!found) {
        g_consensus_console_logger->warn("GetMulticastNodes(), my listGlobalBuddyChainInfo not found");
        return;
    }

    itrList = (*itr).begin();
    T_APPTYPE localapptype = (*itrList).GetLocalBlock().GetAppType();
    if (localapptype.isParaCoin() == true) {
        std::list<string> nodelist;
        CBRET ret = AppCallback<cbindex::GETNEIGHBORNODESIDX>(localapptype, nodelist);
        if (ret == CBRET::REGISTERED_TRUE) {
            std::for_each(nodelist.begin(), nodelist.end(), [&](std::list<string>::reference node) {
                MulticastNodes.push_back(CUInt128(node));
            });
        }
    }
    else {
        for (; itrList != (*itr).end(); itrList++) {
            if ((*itrList).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>())
                continue;

            MulticastNodes.push_back((*itrList).GetPeer().GetPeerAddr().GetNodeid());
        }
    }

    g_consensus_console_logger->info("GetMulticastNodes() MulticastNodes.size: [{}]", MulticastNodes.size());
}

void _tp2pmanagerstatus::SetLatestHyperBlock(uint64 hyperid, const T_SHA256 &hhash)
{
    latestHyperblockId = hyperid;
    latestHyperBlockHash = hhash;
}

