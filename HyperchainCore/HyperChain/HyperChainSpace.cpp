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
#include "HyperChainSpace.h"
#include "node/TaskThreadPool.h"
#include "node/Singleton.h"
#include "hyperblockTask.hpp"
#include "headerhashTask.hpp"
#include "PullChainSpaceTask.hpp"
#include "ApplicationChainTask.hpp"
#include "db/HyperchainDB.h"
#include "db/dbmgr.h"
#include "consensus/buddyinfo.h"
#include <algorithm>
#include <thread>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#define ATMOSTHYPERBLOCKINMEMORY 5

CHyperChainSpace::CHyperChainSpace(string nodeid)
{
    _isstop = false;
    sync_hid = 0;
    uiMaxBlockNum = 0;
    m_mynodeid = nodeid;
    m_localHIDReady = false;
    m_LatestBlockReady = false;
}


void CHyperChainSpace::GetHyperBlockHealthInfo(map<uint64, uint32> &out_BlockHealthInfo)
{
    lock_guard<mutex> locker(m_datalock);
    if (m_Chainspace.empty())
        return;

    out_BlockHealthInfo.clear();
    for (auto & elem : m_Chainspace) {
        out_BlockHealthInfo[elem.first] = elem.second.size();
    }
    return;
}

void CHyperChainSpace::GetUnconfirmedBlockMapShow(map<uint64, string>& out_UnconfirmedBlockMap)
{
    out_UnconfirmedBlockMap.clear();

    CAutoMutexLock muxAuto(m_MuxUnconfirmedBlockMap);
    if (m_UnconfirmedBlockMap.empty())
        return;

    char HyperblockHash[FILESIZEL] = { 0 };
    ITR_MAP_T_UNCONFIRMEDBLOCK it = m_UnconfirmedBlockMap.begin();
    for (; it != m_UnconfirmedBlockMap.end(); it++) {
        LIST_T_HYPERBLOCK blocklist = it->second;
        ITR_LIST_T_HYPERBLOCK hit = blocklist.begin();
        string msg;
        for (; hit != blocklist.end(); hit++) {
            CCommonStruct::Hash256ToStr(HyperblockHash, hit->GetHashSelf());
            msg += HyperblockHash;
            msg += ";";
        }
        out_UnconfirmedBlockMap[it->first] = msg;
    }
}

void CHyperChainSpace::GetHyperChainData(map<uint64, set<string>>& out_HyperChainData)
{
    lock_guard<mutex> locker(m_datalock);
    out_HyperChainData.clear();
    out_HyperChainData = m_Chainspace;
}

void CHyperChainSpace::GetHyperChainShow(map<string, string>& out_HyperChainShow)
{
    lock_guard<mutex> locker(m_showlock);
    out_HyperChainShow.clear();
    out_HyperChainShow = m_chainspaceshow;
}

void CHyperChainSpace::GetLocalChainShow(vector<string> & out_LocalChainShow)
{
    lock_guard<mutex> locker(m_listlock);
    out_LocalChainShow.clear();
    out_LocalChainShow = m_localHIDsection;
}

uint64 CHyperChainSpace::GetGlobalLatestHyperBlockNo()
{
    lock_guard<mutex> locker(m_datalock);
    if (m_Chainspace.empty())
        return 0;

    map<uint64, set<string>>::reverse_iterator it = m_Chainspace.rbegin();
    if (it == m_Chainspace.rend())
        return 0;

    return it->first;
}

void getPayloads(T_HYPERBLOCK& h, const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPayload)
{
    uint16 uiChainNum = 1;

    for (auto& childchain : h.GetChildChains()) {
        for (auto& block : childchain) {
            T_APPTYPE appt = block.GetAppType();
            if (block.GetAppType() == app) {
                T_LOCALBLOCKADDRESS address;
                address.set(h.GetID(), uiChainNum, block.GetID());
                vecPayload.emplace_back(address, block.GetPayLoad());
            }
        }
        uiChainNum++;
    }

}

bool CHyperChainSpace::GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, T_SHA256& hhash, vector<T_PAYLOADADDR>& vecPA)
{
    T_HYPERBLOCK h;
    if (!getHyperBlockFromDB(globalHID, h)) {
        return false;
    }
    hhash = h.GetHashSelf();
    getPayloads(h, app, vecPA);
    return true;

}

bool CHyperChainSpace::GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPA)
{
    T_SHA256 hhash;
    return GetLocalBlocksByHID(globalHID, app, hhash, vecPA);
}

void CHyperChainSpace::PullAppDataThread(const T_LOCALBLOCKADDRESS& low_addr,
                                        const T_LOCALBLOCKADDRESS& high_addr, const T_APPTYPE& app)
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<ApplicationChainTask>(low_addr, high_addr, app));
}

//
void CHyperChainSpace::GetAppBlocksByAddr(const T_LOCALBLOCKADDRESS& low_addr, const T_LOCALBLOCKADDRESS& high_addr, const T_APPTYPE& app)
{
    //
    if (m_threadPullAppBlocks && m_threadPullAppBlocks->joinable()) {
        //already pulled
        m_threadPullAppBlocks->join();
    }
    m_threadPullAppBlocks.reset(new std::thread(&CHyperChainSpace::PullAppDataThread, this, low_addr, high_addr, app));
}


int CHyperChainSpace::GetRemoteLocalBlockByAddr(const T_LOCALBLOCKADDRESS& addr)
{
    if (!m_localHID.count(addr.hid)) {
        //
        return GetRemoteHyperBlockByID(addr.hid);
    }
    return 0;
}

int CHyperChainSpace::GetRemoteHyperBlockByID(uint64 globalHID, const string& nodeid)
{
    PullHyperDataByHID(globalHID, nodeid);
    return 0;
}

int CHyperChainSpace::GetRemoteHyperBlockByID(uint64 globalHID)
{
    int i;
    lock_guard<mutex> locker(m_datalock);
    if (m_Chainspace.empty())
        return -1;

    map<uint64, set<string>>::iterator it = m_Chainspace.find(globalHID);
    if (it == m_Chainspace.end())
        return -1;

    //
    {
        CAutoMutexLock muxAuto1(m_MuxUnconfirmedBlockMap);
        if (!m_UnconfirmedBlockMap.empty()) {
            ITR_MAP_T_UNCONFIRMEDBLOCK bit = m_UnconfirmedBlockMap.find(globalHID);
            if (bit != m_UnconfirmedBlockMap.end()) {
                LIST_T_HYPERBLOCK blocklist = bit->second;
                /*ITR_LIST_T_HYPERBLOCK hit = blocklist.begin();
                for (; hit != blocklist.end(); hit++) {
                    CheckDependency(*hit);
                }*/

                return blocklist.size();
            }
        }
    }

    set<string> sendnodeset;
    CAutoMutexLock muxAuto(m_MuxReqBlockNodes);
    map<uint64, set<string>>::iterator ir = m_ReqBlockNodes.find(globalHID);
    if (ir != m_ReqBlockNodes.end()) {
        sendnodeset = ir->second;
    }

    set<string> nodeset = it->second;
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    set<string>::iterator iter = nodeset.begin();
    for (i = 0; (i < 3) && (iter != nodeset.end()); iter++) {
        ////
        //if (!sendnodeset.empty() && sendnodeset.count(*iter))
        //    continue;

        //
        if (nodemgr->GetKBuckets()->IsNodeInKBuckets(CUInt128(*iter))) {
            PullHyperDataByHID(globalHID, *iter);
            m_ReqBlockNodes[globalHID].insert(*iter);
            i++;
        }
    }

    return i;
}

bool CHyperChainSpace::GetHyperBlockHeaderHash(uint64 hid, T_SHA256 &headerhash)
{
    CAutoMutexLock muxAuto(m_MuxHeaderHashMap);
    if (!m_HeaderHashMap.empty()) {
        map<uint64, T_SHA256>::iterator it = m_HeaderHashMap.find(hid);
        if (it != m_HeaderHashMap.end()) {
            headerhash = it->second;
            return true;
        }
    }

    T_HYPERBLOCK preHyperBlock;
    if (CHyperchainDB::getHyperBlock(preHyperBlock, hid)) {
        headerhash = preHyperBlock.calculateHeaderHashSelf();
        m_HeaderHashMap[hid] = headerhash;
        return true;
    }

    return false;
}

CHECK_RESULT CHyperChainSpace::CheckDependency(const T_HYPERBLOCK &hyperblock)
{
    uint64_t blockid = hyperblock.GetID();
    if (blockid == 0)
        return CHECK_RESULT::INVALID_DATA;

    bool incompatible = false;
    T_SHA256 PreHeaderHash;
    uint64_t preblockid = blockid - 1;
    if (GetHyperBlockHeaderHash(preblockid, PreHeaderHash)) {
        if (PreHeaderHash == hyperblock.GetPreHeaderHash())
            return CHECK_RESULT::VALID_DATA;

        //
        //
        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, PreHeaderHash);
        g_consensus_console_logger->info("I have hyper block: [{}] headerhash: [{}] in hash cache", preblockid, HeaderHash);

        char pHeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(pHeaderHash, hyperblock.GetPreHeaderHash());
        g_consensus_console_logger->info("hyper block: [{}] preheaderhash: [{}] incompatible", hyperblock.GetID(), pHeaderHash);

        incompatible = true;
    }
    //else {
    //    uint64 localHID = GetLocalLatestHID();
    //    uint64 globalHID = GetGlobalLatestHyperBlockNo();

    //    if (localHID == -1 || localHID == 0) {
    //        //
    //        incompatible = false;
    //    }
    //    else {
    //        if ((globalHID < MATURITY_SIZE) || (localHID > globalHID - MATURITY_SIZE)) {
    //            //
    //            incompatible = true;
    //        }
    //    }     
    //}


    ////
    //if (isInUnconfirmedCache(blockid, hyperblock.GetHashSelf())) {
    //    if (incompatible)
    //        return CHECK_RESULT::INCOMPATIBLE_DATA;

    //    return CHECK_RESULT::UNCONFIRMED_DATA;
    //}

    if (incompatible) {
        //
        PutUnconfirmedCache(hyperblock);
        return CHECK_RESULT::INCOMPATIBLE_DATA;
    }

    //
    int ret = GetRemoteHyperBlockHeaderHash(preblockid);
    if (ret < 0)
        return CHECK_RESULT::INVALID_DATA;

    //
    PutUnconfirmedCache(hyperblock);

    return CHECK_RESULT::UNCONFIRMED_DATA;
}

int CHyperChainSpace::GetRemoteHyperBlockHeaderHash(uint64 globalHID)
{
    int i;
    lock_guard<mutex> locker(m_datalock);
    if (m_Chainspace.empty())
        return -1;

    map<uint64, set<string>>::iterator it = m_Chainspace.find(globalHID);
    if (it == m_Chainspace.end())
        return -1;

    set<string> nodeset = it->second;
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

    CAutoMutexLock muxAuto(m_MuxReqHeaderHashNodes);
    set<string>::iterator iter = nodeset.begin();
    for (i = 0; (i < 3) && (iter != nodeset.end()); iter++) {
        //
        if (nodemgr->GetKBuckets()->IsNodeInKBuckets(CUInt128(*iter))) {
            PullHeaderHashByHID(globalHID, *iter);
            m_ReqHeaderHashNodes[globalHID].insert(*iter);
            i++;
        }
    }

    return i;
}

bool CHyperChainSpace::isInUnconfirmedCache(uint64 hid, T_SHA256 blockhash)
{
    CAutoMutexLock muxAuto(m_MuxUnconfirmedBlockMap);
    if (m_UnconfirmedBlockMap.empty())
        return false;

    ITR_MAP_T_UNCONFIRMEDBLOCK it = m_UnconfirmedBlockMap.find(hid);
    if (it == m_UnconfirmedBlockMap.end())
        return false;

    char HyperblockHash[FILESIZEL] = { 0 };
    CCommonStruct::Hash256ToStr(HyperblockHash, blockhash);

    LIST_T_HYPERBLOCK blocklist = it->second;
    ITR_LIST_T_HYPERBLOCK iter = blocklist.begin();
    for (; iter != blocklist.end(); iter++) {
        if (blockhash == iter->GetHashSelf()) {
            g_consensus_console_logger->info("hyper block: [{}] hash: [{}] in unconfirmed block cache", hid, HyperblockHash);
            return true;
        }
    }

    return false;
}

void CHyperChainSpace::RehandleUnconfirmedBlock(uint64 hid, T_SHA256 headerhash)
{
    CAutoMutexLock muxAuto(m_MuxUnconfirmedBlockMap);
    if (m_UnconfirmedBlockMap.empty())
        return;

    ITR_MAP_T_UNCONFIRMEDBLOCK it = m_UnconfirmedBlockMap.find(hid + 1);
    if (it == m_UnconfirmedBlockMap.end())
        return;

    bool found = false;
    T_HYPERBLOCK hyperblock;
    LIST_T_HYPERBLOCK blocklist = it->second;
    ITR_LIST_T_HYPERBLOCK iter = blocklist.begin();
    for (; iter != blocklist.end(); iter++) {
        if (headerhash == iter->GetPreHeaderHash()) {
            hyperblock = *iter;
            found = true;
            break;
        }
    }

    if (found) {
        //
        m_UnconfirmedBlockMap.erase(it);
        muxAuto.unlock();
        updateHyperBlockCache(hyperblock);
    }

    return;
}

void CHyperChainSpace::PutUnconfirmedCache(const T_HYPERBLOCK &hyperblock)
{
    uint64_t hid = hyperblock.GetID();

    CAutoMutexLock muxAuto(m_MuxUnconfirmedBlockMap);
    ITR_MAP_T_UNCONFIRMEDBLOCK it = m_UnconfirmedBlockMap.find(hid);
    if (it == m_UnconfirmedBlockMap.end()) {
        m_UnconfirmedBlockMap[hid].push_back(std::move(hyperblock));
        return;
    }

    LIST_T_HYPERBLOCK blocklist = it->second;
    ITR_LIST_T_HYPERBLOCK iter = blocklist.begin();
    for (; iter != blocklist.end(); iter++) {
        if (hyperblock.GetHashSelf() == iter->GetHashSelf())
            return;
    }

    blocklist.push_back(std::move(hyperblock));

    return;
}

void CHyperChainSpace::PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash, string from_nodeid)
{
    bool found = false;
    bool confirmed = false;

    CAutoMutexLock muxAuto(m_MuxUnconfirmedHashMap);
    ITR_MAP_T_UNCONFIRMEDHEADERHASH it = m_UnconfirmedHashMap.find(hid);
    if (it == m_UnconfirmedHashMap.end()) {
        T_HEADERHASHINFO headerhashinfo(headerhash, from_nodeid);
        m_UnconfirmedHashMap[hid].push_back(std::move(headerhashinfo));
        return;
    }

    LIST_T_HEADERHASHINFO headerhashlist = it->second;
    ITR_LIST_T_HEADERHASHINFO iter = headerhashlist.begin();
    for (; iter != headerhashlist.end(); iter++) {
        if (headerhash == iter->GetHeaderHash()) {
            iter->PutNodeID(from_nodeid);
            found = true;
            break;
        }
    }

    if (found == false) {
        T_HEADERHASHINFO headerhashinfo(headerhash, from_nodeid);
        headerhashlist.push_back(std::move(headerhashinfo));
    }

    //
    int vote = 0;
    {
        CAutoMutexLock muxAuto1(m_MuxReqHeaderHashNodes);
        vote = m_ReqHeaderHashNodes[hid].size();
    }
    int threshold = ceil(vote * 0.6);
    iter = headerhashlist.begin();
    for (; iter != headerhashlist.end(); iter++) {
        if (iter->GetVote() >= threshold) {
            CAutoMutexLock muxAuto2(m_MuxHeaderHashMap);
            m_HeaderHashMap[hid] = headerhash;
            confirmed = true;
            break;
        }
    }

    if (confirmed == true) {
        //
        m_UnconfirmedHashMap.erase(it);
        muxAuto.unlock();

        RehandleUnconfirmedBlock(hid, headerhash);

        //
        CAutoMutexLock muxAuto1(m_MuxReqHeaderHashNodes);
        m_ReqHeaderHashNodes.erase(hid);
    }

    return;
}

void CHyperChainSpace::loadHyperBlockCache()
{
    uint64 nHyperId = GetLocalLatestHID();

    CAutoMutexLock muxAuto1(m_MuxHchainBlockList);
    m_HchainBlockList.clear();

    T_HYPERBLOCK hyperBlock;
    if (CHyperchainDB::getHyperBlock(hyperBlock, nHyperId)) {
        uiMaxBlockNum = hyperBlock.GetID();
        m_LatestHyperBlock = std::move(hyperBlock);
        g_consensus_console_logger->info("loadHyperBlockCache, uiMaxBlockNum:{}", hyperBlock.GetID());
    }
}

void CHyperChainSpace::loadHyperBlockIDCache()
{
    int ret = m_db->getAllHyperblockNumInfo(m_localHID);
    if (ret == 0)
        m_localHIDReady = true;
}

void CHyperChainSpace::loadHyperBlockHashCache()
{
    m_db->getAllHashInfo(m_BlockHashMap, m_HeaderHashMap);
}

int CHyperChainSpace::GenerateHIDSection()
{
    int ret = 0;

    if (m_localHID.empty())
        return ret;

    lock_guard<mutex> lk(m_listlock);

    //
    m_localHIDsection.clear();

    uint64 nstart = *(m_localHID.begin());
    uint64 nend = nstart;
    string data;

    for (auto &li : m_localHID) {
        //
        //
        //
        if (li == nend || li - nend == 1)
            nend = li;
        else {
            //
            if (nstart == nend)
                data = to_string(nstart);
            else
                data = to_string(nstart) + "-" + to_string(nend);

            m_localHIDsection.push_back(data);

            nstart = li;
            nend = nstart;
        }
        ret++;
    }

    if (nstart == nend)
        data = to_string(nstart);
    else
        data = to_string(nstart) + "-" + to_string(nend);
    ret++;
    m_localHIDsection.push_back(data);

    return ret;
}

void CHyperChainSpace::AnalyzeChainSpaceData(string strbuf, string nodeid)
{
    if (strbuf.empty() || strbuf.length() <= 8)
        return;

    //
    string::size_type np = strbuf.find("HyperID=");
    if (np == string::npos)
        return;

    strbuf = strbuf.substr(np + 8);

    {
        lock_guard<mutex> locker(m_showlock);
        m_chainspaceshow[nodeid] = strbuf;
    }

    vector<string> vecHID;
    SplitString(strbuf, vecHID, ";");

    vector<string>::iterator vit;
    string::size_type ns = 0;
    string strIDtoID;
    uint64 nstart, nend, ID;

    lock_guard<mutex> lk(m_datalock);
    for (auto &sid : vecHID) {
        strIDtoID = sid;

        ns = strIDtoID.find("-");
        if ((ns != string::npos) && (ns > 0)) {
            nstart = stoull(strIDtoID.substr(0, ns));
            nend = stoull(strIDtoID.substr(ns + 1, strIDtoID.length() - 1));

            for (ID = nstart; ID <= nend; ID++) {
                //if (!FindIDExistInChainIDList(ID))
                m_Chainspace[ID].insert(nodeid);
            }

        }
        else {
            ID = stoull(strIDtoID);
            //if (!FindIDExistInChainIDList(ID))
            m_Chainspace[ID].insert(nodeid);
        }
    }
}


void CHyperChainSpace::SplitString(const string& s, vector<std::string>& v, const std::string& c)
{
    string::size_type pos1 = 0, pos2;
    pos2 = s.find(c);
    while (std::string::npos != pos2) {
        v.push_back(s.substr(pos1, pos2 - pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
}

bool CHyperChainSpace::GetLocalHIDsection(string & mes)
{
    lock_guard<mutex> lk(m_listlock);
    if (m_localHIDsection.empty())
        return false;

    mes += "HyperID=";
    for (auto &li : m_localHIDsection) {
        mes += li;
        mes += ";";
    }

    return true;
}

bool CHyperChainSpace::GetLocalBlock(const T_LOCALBLOCKADDRESS& addr, T_LOCALBLOCK& localblock)
{
    if (!m_db) {
        return false;
    }
    int ret = m_db->getLocalblock(localblock, addr.hid, addr.id, addr.chainnum);
    if (ret == 0) {
        return true;
    }
    return false;
}

bool CHyperChainSpace::GetLocalBlockPayload(const T_LOCALBLOCKADDRESS &addr, string &payload)
{
    if (!m_db) {
        return false;
    }
    T_LOCALBLOCK lb;
    int ret = m_db->getLocalblock(lb, addr.hid, addr.id, addr.chainnum);
    if (ret == 0) {
        payload = std::forward<string>(lb.body.payload);
        return true;
    }
    return false;
}

void CHyperChainSpace::start(DBmgr* db)
{
    m_db = db;
    //
    loadHyperBlockIDCache();

    //
    GenerateHIDSection();

    //
    loadHyperBlockCache();

    //
    loadHyperBlockHashCache();


    m_threadpull.reset(new std::thread(&CHyperChainSpace::PullDataThread, this));
}

void CHyperChainSpace::PullHyperDataByHID(uint64 hid, string nodeid)
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<GetHyperBlockByNoReqTask>(hid, nodeid));
}

void CHyperChainSpace::PullHeaderHashByHID(uint64 hid, string nodeid)
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<GetHeaderHashByNoReqTask>(hid, nodeid));
}

void CHyperChainSpace::PullChainSpaceData()
{
    TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
    taskpool->put(make_shared<PullChainSpaceTask>());
}

void CHyperChainSpace::SyncLatestHyperBlock()
{
    uint64 localHID = GetLocalLatestHID();
    uint64 globalHID = GetGlobalLatestHyperBlockNo();

    if (globalHID <= localHID) {
        m_LatestBlockReady = true;
        return;
    }

    m_LatestBlockReady = false;

    using seconds = std::chrono::duration<double, ratio<1>>;
    system_clock::time_point curr = system_clock::now();
    seconds timespan = std::chrono::duration_cast<seconds>(curr - sync_time);

    if ((sync_hid == globalHID) && timespan.count() < 3) {
        //
        return;
    }

    //
    int ret = GetRemoteHyperBlockByID(globalHID);
    if (ret > 0) {
        sync_hid = globalHID;
        sync_time = system_clock::now();
    }
}

void CHyperChainSpace::PullDataThread()
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

    while (!_isstop) {
        PullChainSpaceData();
        sleepfn(20);
    }
}

bool CHyperChainSpace::getHyperBlockFromDB(uint64 hid, T_HYPERBLOCK& hyperblock)
{
    return CHyperchainDB::getHyperBlock(hyperblock, hid);
}

bool CHyperChainSpace::getHyperBlock(uint64 hid, T_HYPERBLOCK &hyperblock)
{
    CAutoMutexLock muxAuto(m_MuxHchainBlockList);
    return getHyperBlockwithoutMutexLock(hid, hyperblock);
}

bool CHyperChainSpace::getHyperBlockwithoutMutexLock(uint64 hid, T_HYPERBLOCK &hyperblock)
{
    if (m_localHID.empty() || !m_localHID.count(hid))
        return false;


    if (m_LatestHyperBlock.GetID() == hid) {
        hyperblock = m_LatestHyperBlock;
        return true;
    }

    auto itrList = m_HchainBlockList.begin();
    for (; itrList != m_HchainBlockList.end(); itrList++) {
        if ((*itrList).GetID() == hid) {
            //
            hyperblock = (*itrList);
            return true;
        }
    }

    //
    return CHyperchainDB::getHyperBlock(hyperblock, hid);
}

bool CHyperChainSpace::getHyperBlock(const T_SHA256 &hhash, T_HYPERBLOCK &hyperblock)
{
    CAutoMutexLock muxAuto(m_MuxHchainBlockList);

    if (m_LatestHyperBlock.GetHashSelf() == hhash) {
        hyperblock = m_LatestHyperBlock;
        return true;
    }

    auto itrList = m_HchainBlockList.begin();
    for (; itrList != m_HchainBlockList.end(); itrList++) {
        if ((*itrList).GetHashSelf() == hhash) {
            //
            hyperblock = (*itrList);
            return true;
        }
    }

    //
    return CHyperchainDB::getHyperBlock(hyperblock, hhash);
}

void CHyperChainSpace::SaveToLocalStorage(const T_HYPERBLOCK &tHyperBlock)
{
    DBmgr::Transaction t = m_db->beginTran();

    //
    if (m_db->isBlockExisted(tHyperBlock.GetID())) {
        m_db->deleteHyperblockAndLocalblock(tHyperBlock.GetID());
    }

    auto subItr = tHyperBlock.GetChildChains().begin();
    uint16 chainnum = 0;
    for (; subItr != tHyperBlock.GetChildChains().end(); subItr++) {
        chainnum++;
        auto ssubItr = (*subItr).begin();
        for (; ssubItr != (*subItr).end(); ssubItr++) {
            m_db->insertLocalblock(*ssubItr, tHyperBlock.GetID(), chainnum);
        }
    }
    m_db->insertHyperblock(tHyperBlock);
    t.set_trans_succ();
}

void CHyperChainSpace::SaveHashToLocalStorage(uint64 hid, T_SHA256 headerhash, T_SHA256 blockhash)
{
    m_db->updateHashInfo(hid, headerhash, blockhash);
}

//
bool CHyperChainSpace::updateHyperBlockCache(T_HYPERBLOCK &hyperblock)
{
    uint64_t currblockid = hyperblock.GetID();
    uint64_t blockcount = hyperblock.GetChildBlockCount();

    //
    //

    char HyperblockHash[FILESIZEL] = { 0 };
    CCommonStruct::Hash256ToStr(HyperblockHash, hyperblock.GetHashSelf());

    //
    bool isBlockAlreadyExisted = false;
    CAutoMutexLock muxAuto(m_MuxHchainBlockList);
    if (!isAcceptHyperBlock(currblockid, hyperblock, isBlockAlreadyExisted)) {
        g_consensus_console_logger->info("I have the hyper block or local is more well, refuse it: {} {} {}",
            currblockid, blockcount, HyperblockHash);
        return false;
    }

    //
    //
    //

    if (!g_tP2pManagerStatus->ApplicationCheck(hyperblock)) {
        g_consensus_console_logger->warn("found the invalid or orphant application data in hyper block : {} {} {}",
            currblockid, blockcount, HyperblockHash);
        //
        //
        //return false;
    }

    g_consensus_console_logger->info("I accept the hyper block: {} {} {}",
        currblockid, blockcount, HyperblockHash);

    //
    if (isBlockAlreadyExisted) {
        g_tP2pManagerStatus->initOnChainingState(currblockid);
    }

    g_tP2pManagerStatus->ApplicationAccept(hyperblock);
    SaveToLocalStorage(hyperblock);

    //
    g_tP2pManagerStatus->updateOnChainingState(hyperblock);

    //
    T_SHA256 headerhash = hyperblock.calculateHeaderHashSelf();
    SaveHashToLocalStorage(currblockid, headerhash, hyperblock.GetHashSelf());

    //
    {
        CAutoMutexLock muxAuto1(m_MuxHeaderHashMap);
        m_HeaderHashMap[currblockid] = headerhash;
    }

    //
    {
        CAutoMutexLock muxAuto2(m_MuxBlockHashMap);
        m_BlockHashMap[currblockid] = hyperblock.GetHashSelf();
    }

    //
    g_tP2pManagerStatus->SignalHyperBlockUpdated(hyperblock);

    //
    auto itr = m_HchainBlockList.begin();
    for (; itr != m_HchainBlockList.end();) {
        uint64_t blocknum = (*itr).GetID();
        if (blocknum == currblockid || blocknum < currblockid - ATMOSTHYPERBLOCKINMEMORY) {
            itr = m_HchainBlockList.erase(itr);
            continue;
        }
        ++itr;
    }

    if (!isBlockAlreadyExisted) {
        //
        m_localHID.insert(currblockid);
        GenerateHIDSection();
    }

    if (GetMaxBlockID() <= currblockid) {
        //
        if (m_LatestHyperBlock.GetID() != -1 && m_LatestHyperBlock.GetID() != currblockid) {
            m_HchainBlockList.emplace_back(std::move(m_LatestHyperBlock));
        }

        m_LatestHyperBlock = std::move(hyperblock);

        uint64 globalHID = GetGlobalLatestHyperBlockNo();
        uiMaxBlockNum = std::max(globalHID, currblockid);

        if (currblockid >= globalHID) {
            m_LatestBlockReady = true;

            if (currblockid != 0) {
                //
                TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
                taskpool->put(make_shared<BoardcastHyperBlockTask>());
            }
        }
    }
    else {
        //
        m_HchainBlockList.push_back(std::move(hyperblock));
    }

    muxAuto.unlock();

    RehandleUnconfirmedBlock(currblockid, headerhash);

    return true;
}

//
//
bool CHyperChainSpace::isMoreWellThanLocal(const T_HYPERBLOCK &localHyperBlock,
    uint64 blockid, uint64 blockcount, const T_SHA256 &hhashself)
{
    assert(blockid == localHyperBlock.GetID());

    uint64 currentchildcount = localHyperBlock.GetChildBlockCount();
    if (blockcount > currentchildcount) {
        return true;
    }
    if (blockcount == currentchildcount) {
        T_SHA256 h = localHyperBlock.GetHashSelf();
        if (hhashself < h) {
            return true;
        }
    }
    return false;
}

bool CHyperChainSpace::isAcceptHyperBlock(uint64 blockid, const T_HYPERBLOCK &remoteHyperBlock, bool isAlreadyExisted)
{
    T_HYPERBLOCK localHyperBlock;

    bool Existed = getHyperBlockwithoutMutexLock(blockid, localHyperBlock);
    if (!Existed) {
        isAlreadyExisted = false;
        return true;
    }

    isAlreadyExisted = true;

    //
    if ((uiMaxBlockNum > MATURITY_SIZE) && (blockid <= uiMaxBlockNum - MATURITY_SIZE)) {
        g_consensus_console_logger->info("hyper block {} has matured, refuse update", blockid);
        return false;
    }

    //
    T_SHA256 lpreheaderhash = localHyperBlock.GetPreHeaderHash();
    T_SHA256 rpreheaderhash = remoteHyperBlock.GetPreHeaderHash();

    if (lpreheaderhash != rpreheaderhash) {
        T_SHA256 PreHeaderHash;
        uint64_t preblockid = blockid - 1;
        if (GetHyperBlockHeaderHash(preblockid, PreHeaderHash)) {
            if (rpreheaderhash == PreHeaderHash) {
                g_consensus_console_logger->info("hyper block {} has furcated, update local data", blockid);
                return true;
            }
        }
    }

    uint64_t blockcount = remoteHyperBlock.GetChildBlockCount();
    T_SHA256 hhashself = remoteHyperBlock.GetHashSelf();

    if (isMoreWellThanLocal(localHyperBlock, blockid, blockcount, hhashself)) {
        g_consensus_console_logger->info("isMoreWellThanLocal is true {} {}", blockid, blockcount);
        return true;
    }

    return false;
}

void putStream(boost::archive::binary_oarchive &oa, const T_HYPERBLOCK& hyperblock)
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


