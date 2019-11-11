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
#include "db/HyperchainDB.h"
#include "headers/lambda.h"
#include "node/Singleton.h"
#include "node/NodeManager.h"
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

void _tp2pmanagerstatus::clearStatus()
{
    bStartGlobalFlag = false;
    bHaveOnChainReq = false;
    uiNodeState = DEFAULT_REGISREQ_STATE;
    usBuddyPeerCount = 0;
    uiSendRegisReqNum = 0;
    uiSendConfirmingRegisReqNum = 0;
    uiRecvRegisReqNum = 0;
    uiRecvConfirmingRegisReqNum = 0;
    listLocalBuddyChainInfo.clear();
    uiSendPoeNum = 0;
    uiRecivePoeNum = 0;
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
    {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus->MuxlistLocalBuddyChainInfo);
        if (g_tP2pManagerStatus->listLocalBuddyChainInfo.size() > 0) {
            auto itrLocal = g_tP2pManagerStatus->listLocalBuddyChainInfo.begin();
            return itrLocal->GetLocalBlock().GetPreHHash();
        }
    }

    CAutoMutexLock muxAuto1(g_tP2pManagerStatus->MuxlistGlobalBuddyChainInfo);
    auto itr = listGlobalBuddyChainInfo.begin();

    if (itr != g_tP2pManagerStatus->listGlobalBuddyChainInfo.end()) {
        return itr->begin()->GetLocalBlock().GetPreHHash();
    }
    return T_SHA256(0);
}

uint16 _tp2pmanagerstatus::GetBuddyPeerCount()const
{
    return usBuddyPeerCount;
}

uint16 _tp2pmanagerstatus::GetNodeState()const
{
    return uiNodeState;
}

uint64 _tp2pmanagerstatus::GetSendRegisReqNum()const
{
    return uiSendRegisReqNum;
}

uint64 _tp2pmanagerstatus::GetRecvRegisReqNum()const
{
    return uiRecvRegisReqNum;
}

uint64 _tp2pmanagerstatus::GetSendConfirmingRegisReqNum()const
{
    return uiSendConfirmingRegisReqNum;
}

uint64 _tp2pmanagerstatus::GetRecvConfirmingRegisReqNum()const
{
    return uiRecvConfirmingRegisReqNum;
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

LIST_T_LOCALCONSENSUS& _tp2pmanagerstatus::GetListOnChainReq()
{
    return listOnChainReq;
}

void _tp2pmanagerstatus::SetGlobalBuddyAddr(T_PEERADDRESS addr)
{
    tLocalBuddyAddr = addr;;
}

void _tp2pmanagerstatus::SetStartGlobalFlag(bool flag)
{
    bStartGlobalFlag = flag;
}

void _tp2pmanagerstatus::SetHaveOnChainReq(bool haveOnChainReq)
{
    bHaveOnChainReq = haveOnChainReq;
}

void _tp2pmanagerstatus::SetRecvRegisReqNum(uint64 num)
{
    uiRecvRegisReqNum = num;
}

uint64 _tp2pmanagerstatus::GetSendPoeNum()const
{
    return uiSendPoeNum;
}

void _tp2pmanagerstatus::SetSendPoeNum(uint64 num)
{
    uiSendPoeNum = num;
}


void _tp2pmanagerstatus::SetNodeState(uint16 state)
{
    uiNodeState = state;
}

void _tp2pmanagerstatus::SetSendRegisReqNum(uint64 num)
{
    uiSendRegisReqNum = num;
}

void _tp2pmanagerstatus::SetSendConfirmingRegisReqNum(uint64 num)
{
    uiSendConfirmingRegisReqNum = num;
}

void _tp2pmanagerstatus::SetRecvConfirmingRegisReqNum(uint64 num)
{
    uiRecvConfirmingRegisReqNum = num;
}

uint64 _tp2pmanagerstatus::GetRecvPoeNum()const
{
    return uiRecivePoeNum;
}

void _tp2pmanagerstatus::SetRecvPoeNum(uint64 num)
{
    uiRecivePoeNum = num;
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

    //
    for (auto& a : mapPayload) {
        CBRET ret = appCallback<cbindex::VALIDATECHAINIDX>(a.first, a.second);
        if (ret == CBRET::REGISTERED_FALSE) {
            return false;
        }
    }
    return true;
}

bool _tp2pmanagerstatus::ApplicationAccept(T_HYPERBLOCK &hyperblock)
{
    map<T_APPTYPE, vector<T_PAYLOADADDR>> mapPayload;
    ToAppPayloads(hyperblock, mapPayload);

    //
    T_APPTYPE genesisledger(APPTYPE::ledger, 0, 0, 0);
    if (mapPayload.count(genesisledger)) {
        CBRET ret = appCallback<cbindex::HANDLEGENESISIDX>(genesisledger, mapPayload.at(genesisledger));
        mapPayload.erase(genesisledger);
    }

    T_APPTYPE genesisparacoin(APPTYPE::paracoin, 0, 0, 0);
    if (mapPayload.count(genesisparacoin)) {
        CBRET ret = appCallback<cbindex::HANDLEGENESISIDX>(genesisparacoin, mapPayload.at(genesisparacoin));
        mapPayload.erase(genesisparacoin);
    }

    T_SHA256 thash = hyperblock.GetHashSelf();
    uint32_t hid = hyperblock.GetID();

    //
    for (auto& a : mapPayload) {
        T_APPTYPE app = a.first;
        allAppCallback<cbindex::ACCEPTCHAINIDX>(app, a.second, hid, thash);
    }
    return true;
}


void _tp2pmanagerstatus::updateOnChainingState(const T_HYPERBLOCK &hyperblock)
{
    bool isfound = false;
    uint32 uiChainNum = 1;
    auto childchainlist = hyperblock.GetChildChains();
    CAutoMutexLock muxAutoSearch(MuxMapSearchOnChain);
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

void _tp2pmanagerstatus::updateLocalBuddyBlockToLatest()
{
    if (listLocalBuddyChainInfo.size() == ONE_LOCAL_BLOCK) {

        //
        auto itr = listLocalBuddyChainInfo.begin();
        T_LOCALBLOCK& localblock = itr->GetLocalBlock();
        string newPayload;
        CBRET ret = appCallback<cbindex::REONCHAINIDX>(localblock.GetAppType(),
            localblock.GetPayLoad(), newPayload);
        if (ret == CBRET::REGISTERED_TRUE) {
            localblock.SetPayLoad(newPayload);
            localblock.CalculateHashSelf();
        }

        //
        T_SHA256 preHyperBlockHash;
        uint64 localhyperblockid = 0;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->GetLatestHyperBlockIDAndHash(localhyperblockid, preHyperBlockHash);

        localblock.updatePreHyperBlockInfo(localhyperblockid, preHyperBlockHash);
    }
}

//
void _tp2pmanagerstatus::cleanConsensusEnv()
{
    {
        CAutoMutexLock muxAuto2(g_tP2pManagerStatus->MuxlistGlobalBuddyChainInfo);
        g_tP2pManagerStatus->listGlobalBuddyChainInfo.clear();
    }

    {
        CAutoMutexLock muxAuto1(g_tP2pManagerStatus->MuxlistCurBuddyRsp);
        g_tP2pManagerStatus->listCurBuddyRsp.clear();
    }

    {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus->MuxlistRecvLocalBuddyRsp);
        g_tP2pManagerStatus->listRecvLocalBuddyRsp.clear();
    }

    {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus->MuxlistCurBuddyReq);
        g_tP2pManagerStatus->listCurBuddyReq.clear();
    }

    {
        CAutoMutexLock muxAuto(g_tP2pManagerStatus->MuxlistRecvLocalBuddyReq);
        g_tP2pManagerStatus->listRecvLocalBuddyReq.clear();
    }
}

void _tp2pmanagerstatus::trackLocalBlock(const T_LOCALBLOCK & localblock)
{
    LB_UUID uuid = localblock.GetUUID();

    T_LOCALBLOCKADDRESS addr;
    T_SEARCHINFO searchinfo;
    CAutoMutexLock muxAuto(MuxMapSearchOnChain);
    mapSearchOnChain[uuid] = searchinfo;
}

void _tp2pmanagerstatus::initOnChainingState(uint64 hid)
{
    CAutoMutexLock muxAuto(MuxMapSearchOnChain);
    for (auto & elem : mapSearchOnChain) {
        if (hid == elem.second.GetHyperID()) {
            T_SEARCHINFO &searchInfo = elem.second;
            searchInfo.addr.set(hid, -1, -1);
        }
    }
    Singleton<DBmgr>::instance()->initOnChainState(hid);
}

void _tp2pmanagerstatus::setAppCallback(const T_APPTYPE &app, const CONSENSUSNOTIFY &notify)
{
    std::lock_guard<std::recursive_mutex> lck(_muxmapcbfn);
    _mapcbfn[app] = notify;
}

void _tp2pmanagerstatus::removeAppCallback(const T_APPTYPE & app)
{
    std::lock_guard<std::recursive_mutex> lck(_muxmapcbfn);
    if (_mapcbfn.count(app)) {
        _mapcbfn.erase(app);
    }
}

void _tp2pmanagerstatus::ClearMulticastNodes()
{
    if (!MulticastNodes.empty())
        MulticastNodes.clear();
}

void _tp2pmanagerstatus::SetMulticastNodes()
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH me = nodemgr->myself();
    bool found = false;

    ClearMulticastNodes();

    CAutoMutexLock muxAuto(MuxlistGlobalBuddyChainInfo);
    if (listGlobalBuddyChainInfo.empty()) {
        g_consensus_console_logger->warn("SetMulticastNodes(), listGlobalBuddyChainInfo empty");
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
        g_consensus_console_logger->warn("SetMulticastNodes(), my listGlobalBuddyChainInfo not found");
        return;
    }

    itrList = (*itr).begin();
    T_APPTYPE localapptype = (*itrList).GetLocalBlock().GetAppType();
    if (localapptype.isParaCoin() == true) {
        //
        std::list<string> nodelist;
        CBRET ret = appCallback<cbindex::GETNEIGHBORNODESIDX>(localapptype, nodelist);
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

    g_consensus_console_logger->info("SetMulticastNodes() MulticastNodes.size: [{}]", MulticastNodes.size());
}

vector<CUInt128> _tp2pmanagerstatus::GetMulticastNodes()
{
    return MulticastNodes;
}


T_P2PMANAGERSTATUS* g_tP2pManagerStatus = nullptr;