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
#include "HyperChainSpace.h"
#include "node/Singleton.h"
#include "hyperblockTask.hpp"
#include "headerhashTask.hpp"
#include "blockheaderTask.hpp"
#include "PullChainSpaceTask.hpp"
#include "ApplicationChainTask.hpp"
#include "db/HyperchainDB.h"
#include "db/dbmgr.h"
#include "consensus/buddyinfo.h"
#include "AppPlugins.h"
#include <algorithm>
#include <thread>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

CHyperChainSpace::CHyperChainSpace(string nodeid)
{
    _isstop = false;
    sync_hid = 0;
    sync_time = system_clock::now();
    sync_header_hid = 0;
    sync_header_time = system_clock::now();
    sync_header_furcated = false;
    sync_header_ready = false;
    uiGlobalMaxBlockNum = 0;
    uiMaxBlockNum = 0;
    uiMaxHeaderID = 0;
    m_mynodeid = nodeid;
    m_FullNode = false;
    m_ChainspaceReady = false;
    m_localHeaderReady = false;
    m_LatestBlockReady = false;

    if (mapHCArgs.count("-fullnode"))
        m_FullNode = true;

}

void CHyperChainSpace::startMQHandler()
{
    std::function<void(void*, zmsg*)> fwrk =
        std::bind(&CHyperChainSpace::DispatchService, this, std::placeholders::_1, std::placeholders::_2);

    _msghandler.registerWorker(HYPERCHAINSPACE_SERVICE, fwrk);
    _msghandler.registerTaskWorker(HYPERCHAINSPACE_T_SERVICE);

    

    _msghandler.registerTimer(30 * 1000, std::bind(&CHyperChainSpace::PullChainSpace, this));
    _msghandler.registerTimer(20 * 1000, std::bind(&CHyperChainSpace::PullHyperBlock, this));
    _msghandler.registerTimer(1800 * 1000, std::bind(&CHyperChainSpace::CollatingChainSpace, this));

    _hyperblock_pub = new zmq::socket_t(*g_inproc_context, ZMQ_PUB);
    _hyperblock_pub->bind(HYPERBLOCK_PUB_SERVICE);

    _msghandler.registerTaskType<PullChainSpaceTask>(TASKTYPE::HYPER_CHAIN_SPACE_PULL);
    _msghandler.registerTaskType<PullChainSpaceRspTask>(TASKTYPE::HYPER_CHAIN_SPACE_PULL_RSP);
    _msghandler.registerTaskType<GetHyperBlockByNoReqTask>(TASKTYPE::GET_HYPERBLOCK_BY_NO_REQ);
    _msghandler.registerTaskType<GetHyperBlockByPreHashReqTask>(TASKTYPE::GET_HYPERBLOCK_BY_PREHASH_REQ);
    _msghandler.registerTaskType<GetHeaderHashByNoReqTask>(TASKTYPE::GET_HEADERHASH_BY_NO_REQ);
    _msghandler.registerTaskType<GetHeaderHashByNoRspTask>(TASKTYPE::GET_HEADERHASH_BY_NO_RSP);
    _msghandler.registerTaskType<GetBlockHeaderReqTask>(TASKTYPE::GET_BLOCKHEADER_REQ);
    _msghandler.registerTaskType<GetBlockHeaderRspTask>(TASKTYPE::GET_BLOCKHEADER_RSP);
    _msghandler.registerTaskType<BoardcastHyperBlockTask>(TASKTYPE::BOARDCAST_HYPER_BLOCK);
    _msghandler.registerTaskType<NoHyperBlockRspTask>(TASKTYPE::NO_HYPERBLOCK_RSP);
    _msghandler.registerTaskType<NoBlockHeaderRspTask>(TASKTYPE::NO_BLOCKHEADER_RSP);

    _msghandler.start();
    cout << "CHyperChainSpace MQID: " << MQID() << endl;
}

void CHyperChainSpace::GetHyperBlockHealthInfo(map<uint64, uint32> &out_BlockHealthInfo)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_Chainspace.empty())
            return;

        out_BlockHealthInfo.clear();
        for (auto& elem : m_Chainspace) {
            out_BlockHealthInfo[elem.first] = elem.second.size();
        }
        return;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockHealthInfo, &out_BlockHealthInfo);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

uint64 CHyperChainSpace::GetGlobalLatestHyperBlockNo()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return uiGlobalMaxBlockNum;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetGlobalLatestHyperBlockNo);

        uint64 hid = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, hid);
            delete rspmsg;
        }

        return hid;
    }
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
    if (_msghandler.getID() == std::this_thread::get_id()) {
        T_HYPERBLOCK h;
        if (!getHyperBlock(globalHID, h)) {
            return false;
        }
        hhash = h.GetHashSelf();
        getPayloads(h, app, vecPA);
        return true;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalBlocksByHID, globalHID, &app, &hhash, &vecPA);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

//bool CHyperChainSpace::GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPA)
//{
//    T_SHA256 hhash;
//    return GetLocalBlocksByHID(globalHID, app, hhash, vecPA);
//}



void CHyperChainSpace::GetAppBlocksByAddr(const T_LOCALBLOCKADDRESS& low_addr, const T_LOCALBLOCKADDRESS& high_addr, const T_APPTYPE& app)
{
    

    //if (m_threadPullAppBlocks && m_threadPullAppBlocks->joinable()) {
    //    //already pulled
    //    m_threadPullAppBlocks->join();
    //}
    //m_threadPullAppBlocks.reset(new std::thread(&CHyperChainSpace::PullAppDataThread, this, low_addr, high_addr, app));
}


int CHyperChainSpace::GetRemoteLocalBlockByAddr(const T_LOCALBLOCKADDRESS& addr)
{
    if (!m_localHID.count(addr.hid)) {
        

        return GetRemoteHyperBlockByID(addr.hid);
    }
    return 0;
}

int CHyperChainSpace::GetRemoteHyperBlockByID(uint64 globalHID, const string& nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        PullHyperDataByHID(globalHID, nodeid);
        return 0;
    }
    else {
        MQRequestNoWaitResult(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetRemoteHyperBlockByIDFromNode, globalHID, nodeid);
        return 0;
    }
}

int CHyperChainSpace::GetRemoteBlockHeader(uint64 startHID, uint16 range, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        PullBlockHeaderData(startHID, range, nodeid);
        return 0;
    }
    else {
        MQRequestNoWaitResult(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetRemoteBlockHeaderFromNode, startHID, range, nodeid);
        return 0;
    }
}

int CHyperChainSpace::GetRemoteHyperBlockByID(uint64 globalHID)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_Chainspace.empty())
            return -1;

        map<uint64, set<string>>::iterator it = m_Chainspace.find(globalHID);
        if (it == m_Chainspace.end())
            return -1;

        

        std::set<CUInt128> ActiveNodes;
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->GetAllNodes(ActiveNodes);
        if (ActiveNodes.empty())
            return -1;

        int i;
        set<string> nodeset = it->second;
        set<string>::iterator iter = nodeset.begin();
        for (i = 0; (i < 3) && (iter != nodeset.end()); iter++) {
            

            if (ActiveNodes.count(CUInt128(*iter))) {
                PullHyperDataByHID(globalHID, *iter);
                i++;
            }
        }

        return i;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetRemoteHyperBlockByID, globalHID);

        int ret = -1;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

int CHyperChainSpace::GetRemoteHyperBlockByPreHash(uint64 globalHID, T_SHA256 prehash)
{
    if (m_Chainspace.empty())
        return -1;

    map<uint64, set<string>>::iterator it = m_Chainspace.find(globalHID);
    if (it == m_Chainspace.end())
        return -1;

    

    std::set<CUInt128> ActiveNodes;
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty())
        return -1;

    int i;
    set<string> nodeset = it->second;
    set<string>::iterator iter = nodeset.begin();
    for (i = 0; (i < 3) && (iter != nodeset.end()); iter++) {
        

        if (ActiveNodes.count(CUInt128(*iter))) {
            PullHyperDataByPreHash(globalHID, prehash, *iter);
            i++;
        }
    }

    return i;
}

bool CHyperChainSpace::GetHyperBlockHeaderHash(uint64 hid, T_SHA256 &headerhash)
{
    if (m_HeaderHashMap.count(hid)) {
        headerhash = m_HeaderHashMap[hid];
        return true;
    }

    /*T_HYPERBLOCK preHyperBlock;
    if (CHyperchainDB::getHyperBlock(preHyperBlock, hid)) {
        headerhash = preHyperBlock.calculateHeaderHashSelf();
        m_HeaderHashMap[hid] = headerhash;
        if (hid > uiMaxHeaderID)
            uiMaxHeaderID = hid;
        return true;
    }*/

    return false;
}

void CHyperChainSpace::GetHyperBlockHeaderHash(uint64 id, uint16 range, vector<T_SHA256> &vecheaderhash)
{
    for (uint64 hid = id; hid < id + range; hid++) {
        if (m_HeaderHashMap.count(hid)) {
            vecheaderhash.push_back(m_HeaderHashMap[hid]);
            continue;
        }

        /*T_HYPERBLOCK preHyperBlock;
        if (CHyperchainDB::getHyperBlock(preHyperBlock, hid)) {
            T_SHA256 headerhash = preHyperBlock.calculateHeaderHashSelf();
            m_HeaderHashMap[hid] = headerhash;
            vecheaderhash.push_back(headerhash);
            if (hid > uiMaxHeaderID)
                uiMaxHeaderID = hid;
        }*/
    }
}

void CHyperChainSpace::PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash)
{
    m_HeaderHashMap[hid] = headerhash;
}

void CHyperChainSpace::SaveHyperblock(const T_HYPERBLOCK &hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        T_SHA256 hash = hyperblock.GetHashSelf();

        if (m_db->isBlockExistedbyHash(hash))
            return;

        //DBmgr::Transaction t = m_db->beginTran();

        auto subItr = hyperblock.GetChildChains().begin();
        uint16 chainnum = 0;
        for (; subItr != hyperblock.GetChildChains().end(); subItr++) {
            chainnum++;
            auto ssubItr = (*subItr).begin();
            for (; ssubItr != (*subItr).end(); ssubItr++) {
                m_db->SaveLocalblock(*ssubItr, hyperblock.GetID(), chainnum, hash);
            }
        }

        m_db->SaveHyperblock(hyperblock);
        //t.set_trans_succ();
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::SaveHyperblock, &hyperblock);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}


CHECK_RESULT CHyperChainSpace::CheckDependency(const T_HYPERBLOCK &hyperblock, string nodeid)
{
    uint64_t blockid = hyperblock.GetID();
    T_SHA256 blockheaderhash = hyperblock.calculateHeaderHashSelf();

    if (blockid == 0 || blockid == -1)
        return CHECK_RESULT::INVALID_DATA;

    

    if (pro_ver == ProtocolVer::NET::INFORMAL_NET && blockid < INFORMALNET_GENESISBLOCKID) {
        return CHECK_RESULT::VALID_DATA;
    }

    SaveHyperblock(hyperblock);

    T_HYPERBLOCKHEADER header = hyperblock.GetHeader();
    PutHyperBlockHeader(header, nodeid);

    T_SHA256 headerhash;
    if (GetHyperBlockHeaderHash(blockid, headerhash)) {
        if (headerhash == blockheaderhash)
            return CHECK_RESULT::VALID_DATA;

        

        

        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        g_daily_logger->info("I have hyper block: [{}] headerhash: [{}] in hash cache", blockid, HeaderHash);

        char pHeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(pHeaderHash, blockheaderhash);
        g_daily_logger->info("hyper block: [{}] headerhash: [{}] incompatible", blockid, pHeaderHash);
    }

    //

    //if (isInUnconfirmedCache(blockid, hyperblock.GetHashSelf())) {
    //    if (incompatible)
    //        return CHECK_RESULT::INCOMPATIBLE_DATA;

    //    return CHECK_RESULT::UNCONFIRMED_DATA;
    //}

    

    auto ir = m_SingleHeaderMap.find(blockheaderhash);
    if (ir != m_SingleHeaderMap.end()) {
        return CHECK_RESULT::UNCONFIRMED_DATA;
    }

    return CHECK_RESULT::INCOMPATIBLE_DATA;
}

int CHyperChainSpace::GetRemoteHyperBlockHeaderHash(uint64 globalHID)
{
    if (m_Chainspace.empty())
        return -1;

    map<uint64, set<string>>::iterator it = m_Chainspace.find(globalHID);
    if (it == m_Chainspace.end())
        return -1;

    

    std::set<CUInt128> ActiveNodes;
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty())
        return -1;

    int i;
    set<string> nodeset = it->second;

    set<string>::iterator iter = nodeset.begin();
    for (i = 0; (i < 3) && (iter != nodeset.end()); iter++) {
        

        if (ActiveNodes.count(CUInt128(*iter))) {
            PullHeaderHashByHID(globalHID, *iter);
            m_ReqHeaderHashNodes[globalHID].insert(*iter);
            i++;
        }
    }

    return i;
}

int CHyperChainSpace::GetRemoteBlockHeader(uint64 startHID, uint16 range)
{
    

    std::set<CUInt128> ActiveNodes;
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    nodemgr->GetAllNodes(ActiveNodes);
    if (ActiveNodes.empty())
        return -1;

    int i = 0;
    for (auto& node : ActiveNodes) {
        

        string nodeid = node.ToHexString();

        auto ir = m_chainspaceheader.find(nodeid);
        if (ir == m_chainspaceheader.end())
            continue;

        if (ir->second < startHID)
            continue;

        PullBlockHeaderData(startHID, range, nodeid);
        g_daily_logger->info("Pull Block Header, startid:[{}] range:[{}] from:[{}]", startHID, range, nodeid);

        i++;

        if (i == 3)
            break;
    }

    return i;
}


bool CHyperChainSpace::isInUnconfirmedCache(uint64 hid, T_SHA256 blockhash)
{
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
            g_daily_logger->info("hyper block: [{}] hash: [{}] in unconfirmed block cache", hid, HyperblockHash);
            return true;
        }
    }

    return false;
}

void CHyperChainSpace::RehandleUnconfirmedBlock(uint64 hid, T_SHA256 headerhash)
{
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
        

        m_UnconfirmedBlockMap.erase(it);
        updateHyperBlockCache(hyperblock);
    }

    return;
}

void CHyperChainSpace::PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash, string from_nodeid)
{
    bool found = false;
    bool confirmed = false;

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

    

    int vote = m_ReqHeaderHashNodes[hid].size();
    int threshold = ceil(vote * 0.6);
    iter = headerhashlist.begin();
    for (; iter != headerhashlist.end(); iter++) {
        if (iter->GetVote() >= threshold) {
            m_HeaderHashMap[hid] = headerhash;
            confirmed = true;
            break;
        }
    }

    if (confirmed == true) {
        

        m_UnconfirmedHashMap.erase(it);

        RehandleUnconfirmedBlock(hid, headerhash);

        

        m_ReqHeaderHashNodes.erase(hid);
    }

    return;
}

void CHyperChainSpace::loadHyperBlockCache()
{
    uint64 nHyperId = GetLocalLatestHID();
    if (nHyperId == -1)
        return;

    T_HYPERBLOCK hyperBlock;
    if (CHyperchainDB::getHyperBlock(hyperBlock, nHyperId)) {
        uiMaxBlockNum = hyperBlock.GetID();
        m_LatestHyperBlock = std::move(hyperBlock);
        g_daily_logger->info("loadHyperBlockCache, uiMaxBlockNum:{}", hyperBlock.GetID());
    }
}

void CHyperChainSpace::loadHyperBlockIDCache()
{
    int ret = m_db->getAllHyperblockNumInfo(m_localHID);
    if (ret != 0) {
        g_daily_logger->error("loadHyperBlockIDCache failed!");
        g_console_logger->error("loadHyperBlockIDCache failed!");
    }
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

    

    m_localHIDsection.clear();

    uint64 nstart = *(m_localHID.begin());
    uint64 nend = nstart;
    string data;

    for (auto &li : m_localHID) {
        

        

        

        if (li == nend || li - nend == 1)
            nend = li;
        else {
            

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

void CHyperChainSpace::NoHyperBlock(uint64 hid, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_Chainspace.empty())
            return;

        map<uint64, set<string>>::iterator it = m_Chainspace.find(hid);
        if (it == m_Chainspace.end())
            return;

        set<string> nodeset = it->second;
        nodeset.erase(nodeid);
        if (nodeset.empty()) {
            m_Chainspace.erase(it);

            if (hid == uiGlobalMaxBlockNum)
                uiGlobalMaxBlockNum--;
        }
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::NoHyperBlock, hid, nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::NoHyperBlockHeader(uint64 hid, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_chainspaceheader.empty())
            return;

        map<string, uint64>::iterator it = m_chainspaceheader.find(nodeid);
        if (it == m_chainspaceheader.end())
            return;

        if (hid <= it->second)
            it->second = hid--;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::NoHyperBlockHeader, hid, nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}


void CHyperChainSpace::AnalyzeChainSpaceData(string strbuf, string nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (strbuf.empty() || strbuf.length() <= 8)
            return;

        

        string::size_type np = strbuf.find("BlockID=");
        if (np == string::npos)
            return;

        string::size_type no = strbuf.find("HeaderID=");
        if (no == string::npos)
            return;

        m_chainspaceshow[nodeid] = strbuf;

        string buf = strbuf.substr(no + 9);
        m_chainspaceheader[nodeid] = stoull(buf);

        strbuf = strbuf.substr(np + 8, no - np - 8);

        vector<string> vecHID;
        SplitString(strbuf, vecHID, ";");

        vector<string>::iterator vit;
        string::size_type ns = 0;
        string strIDtoID;
        uint64 nstart, nend, ID;

        m_ChainspaceReady = true;

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

        map<uint64, set<string>>::reverse_iterator it = m_Chainspace.rbegin();
        if (it == m_Chainspace.rend())
            return;

        if (uiGlobalMaxBlockNum < it->first)
            uiGlobalMaxBlockNum = it->first;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::AnalyzeChainSpaceData, strbuf, nodeid);
        if (rspmsg) {
            delete rspmsg;
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
    if (_msghandler.getID() == std::this_thread::get_id()) {
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
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalBlockPayload, &addr);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret, payload);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::start(DBmgr* db)
{
    m_db = db;
    

    loadHyperBlockIDCache();

    

    GenerateHIDSection();

    

    loadHyperBlockCache();

    

    //loadHyperBlockHashCache();

    

    m_db->getAllHeaderHashInfo(m_HeaderHashMap);
    uiMaxHeaderID = m_HeaderHashMap.empty() ? 0 : m_HeaderHashMap.rbegin()->first;

    

    m_db->getAllHeaderIndex(m_HeaderIndexMap);

    

    m_db->getAllSingleHeaderInfo(m_SingleHeaderMap);

    startMQHandler();

    CheckLocalData();

}

void CHyperChainSpace::CheckLocalData()
{
    uint64 localHID = GetLocalLatestHID();
    uint64 headerHID = GetHeaderHashCacheLatestHID();

    if (localHID == -1)
        return;

    if (pro_ver == ProtocolVer::NET::INFORMAL_NET && headerHID < INFORMALNET_GENESISBLOCKID && localHID > INFORMALNET_GENESISBLOCKID) {
        

        for (uint64 i = INFORMALNET_GENESISBLOCKID; i <= localHID; i++) {
            T_HYPERBLOCKHEADER header;
            if (!m_db->getHyperblockshead(header, i)) {
                PutHyperBlockHeader(header, "myself");
            }
        }
    }
}

void CHyperChainSpace::PullHyperDataByPreHash(uint64 globalHID, T_SHA256 prehash, string nodeid)
{
    GetHyperBlockByPreHashReqTask task(globalHID, prehash, nodeid);
    task.exec();
}

void CHyperChainSpace::PullHyperDataByHID(uint64 hid, string nodeid)
{
    GetHyperBlockByNoReqTask task(hid, nodeid);
    task.exec();
}

void CHyperChainSpace::PullHeaderHashByHID(uint64 hid, string nodeid)
{
    GetHeaderHashByNoReqTask task(hid, nodeid);
    task.exec();
}

void CHyperChainSpace::PullBlockHeaderData(uint64 hid, uint16 range, string nodeid)
{
    GetBlockHeaderReqTask task(hid, range, nodeid);
    task.exec();
}

void CHyperChainSpace::PullChainSpace()
{
    if (_isstop) {
        return;
    }

    PullChainSpaceTask task;
    task.exec();
}

uint64 CHyperChainSpace::GetMaxBlockID()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return uiMaxBlockNum;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetMaxBlockID);

        uint64 nblockNo = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, nblockNo);
            delete rspmsg;
        }

        return nblockNo;
    }
}

void CHyperChainSpace::GetLatestHyperBlockIDAndHash(uint64 &id, T_SHA256 &hash) {
    if (_msghandler.getID() == std::this_thread::get_id()) {
        id = m_LatestHyperBlock.GetID();
        hash = m_LatestHyperBlock.GetHashSelf();
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLatestHyperBlockIDAndHash);

        if (rspmsg) {
            MQMsgPop(rspmsg, id, hash);
            delete rspmsg;
        }
    }
}

bool CHyperChainSpace::IsLatestHyperBlockReady()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return m_LatestBlockReady;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::IsLatestHyperBlockReady);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::GetLatestHyperBlock(T_HYPERBLOCK& hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        hyperblock = m_LatestHyperBlock;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLatestHyperBlock, &hyperblock);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::GetLocalHIDs(uint64 nStartHID, set<uint64>& setHID)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        auto iter = m_localHID.lower_bound(nStartHID);
        for (; iter != m_localHID.end(); ++iter) {
            setHID.insert(*iter);
        }
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalHIDs, nStartHID, &setHID);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::GetHyperChainShow(map<string, string>& chainspaceshow)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        chainspaceshow = m_chainspaceshow;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperChainShow, &chainspaceshow);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::GetHyperChainData(map<uint64, set<string>>& chainspacedata)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        chainspacedata = m_Chainspace;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperChainData, &chainspacedata);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::GetLocalHIDsection(vector <string>& hidsection)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        hidsection = m_localHIDsection;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalHIDsection, &hidsection);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

size_t CHyperChainSpace::GetLocalChainIDSize()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return m_localHID.size();
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetLocalChainIDSize);

        size_t idnums = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, idnums);
            delete rspmsg;
        }

        return idnums;
    }
}

uint64 CHyperChainSpace::GetHeaderHashCacheLatestHID()
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        return uiMaxHeaderID;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHeaderHashCacheLatestHID);

        uint64 hid = 0;
        if (rspmsg) {
            MQMsgPop(rspmsg, hid);
            delete rspmsg;
        }

        return hid;
    }
}

void CHyperChainSpace::DispatchService(void *wrk, zmsg *msg)
{
    HCMQWrk *realwrk = reinterpret_cast<HCMQWrk*>(wrk);

    string reply_who = msg->unwrap();
    string u = msg->pop_front();

    int service_t = 0;
    memcpy(&service_t, u.c_str(), sizeof(service_t));

    switch ((SERVICE)service_t) {
    case SERVICE::GetMaxBlockID: {
        uint64 nblockNo = GetMaxBlockID();
        MQMsgPush(msg, nblockNo);
        break;
    }
    case SERVICE::GetLatestHyperBlockIDAndHash: {
        uint64 id = 0;
        T_SHA256 hash;
        GetLatestHyperBlockIDAndHash(id, hash);
        MQMsgPush(msg, id, hash);
        break;
    }
    case SERVICE::IsLatestHyperBlockReady: {
        bool ret = IsLatestHyperBlockReady();
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetLatestHyperBlock: {
        T_HYPERBLOCK *pHyperblock = nullptr;
        MQMsgPop(msg, pHyperblock);
        GetLatestHyperBlock(*pHyperblock);
        break;
    }
    case SERVICE::GetHyperBlockByID: {
        uint64_t blockid;
        T_HYPERBLOCK *pHyperblock = nullptr;
        MQMsgPop(msg, blockid, pHyperblock);

        bool ret = getHyperBlock(blockid, *pHyperblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetHyperBlockByHash: {
        T_SHA256 hhash;
        T_HYPERBLOCK *pHyperblock = nullptr;
        MQMsgPop(msg, hhash, pHyperblock);

        bool ret = getHyperBlock(hhash, *pHyperblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetHyperBlockByPreHash: {
        T_SHA256 prehash;
        T_HYPERBLOCK *pHyperblock = nullptr;
        MQMsgPop(msg, prehash, pHyperblock);

        bool ret = getHyperBlockByPreHash(prehash, *pHyperblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetLocalBlocksByHID: {
        uint64_t blockid;
        T_APPTYPE *pApp = nullptr;
        T_SHA256 hhash;
        vector<T_PAYLOADADDR> *pvecPA = nullptr;
        MQMsgPop(msg, blockid, pApp, hhash, pvecPA);

        bool ret = GetLocalBlocksByHID(blockid, *pApp, hhash, *pvecPA);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetLocalBlockPayload: {
        T_LOCALBLOCKADDRESS *paddr = nullptr;
        MQMsgPop(msg, paddr);

        string payload;
        bool ret = GetLocalBlockPayload(*paddr, payload);
        MQMsgPush(msg, ret, payload);
        break;
    }
    case SERVICE::GetLocalHIDs: {
        uint64_t blockid;
        set<uint64> *psetHID = nullptr;
        MQMsgPop(msg, blockid, psetHID);
        GetLocalHIDs(blockid, *psetHID);
        break;
    }

    case SERVICE::AnalyzeChainSpaceData: {
        string strbuf;
        string nodeid;
        MQMsgPop(msg, strbuf, nodeid);
        AnalyzeChainSpaceData(strbuf, nodeid);
        break;
    }
    case SERVICE::UpdateHyperBlockCache: {
        T_HYPERBLOCK *pHyperblock = nullptr;
        MQMsgPop(msg, pHyperblock);

        bool ret = updateHyperBlockCache(*pHyperblock);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetMulticastNodes: {
        vector<CUInt128> *pnodes;
        MQMsgPop(msg, pnodes);
        GetMulticastNodes(*pnodes);
        break;
    }
    case SERVICE::NoHyperBlock: {
        uint64_t blockid;
        string nodeid;
        MQMsgPop(msg, blockid, nodeid);
        NoHyperBlock(blockid, nodeid);
        break;
    }
    case SERVICE::PutHyperBlock: {
        T_HYPERBLOCK *pHyperblock = nullptr;
        string nodeid;
        vector<CUInt128> *pnodes = nullptr;
        MQMsgPop(msg, pHyperblock, nodeid, pnodes);
        PutHyperBlock(*pHyperblock, nodeid, *pnodes);
        break;
    }
    case SERVICE::SaveHyperblock: {
        T_HYPERBLOCK *pHyperblock = nullptr;
        MQMsgPop(msg, pHyperblock);
        SaveHyperblock(*pHyperblock);
        break;
    }
    case SERVICE::GetHyperChainShow: {
        map<string, string> *pChainspaceShow = nullptr;
        MQMsgPop(msg, pChainspaceShow);
        GetHyperChainShow(*pChainspaceShow);
        break;
    }
    case SERVICE::GetHyperChainData: {
        map<uint64, set<string>> *pChainspaceData = nullptr;
        MQMsgPop(msg, pChainspaceData);
        GetHyperChainData(*pChainspaceData);
        break;
    }
    case SERVICE::GetLocalHIDsection: {
        vector <string> *pHidsection = nullptr;
        MQMsgPop(msg, pHidsection);
        GetLocalHIDsection(*pHidsection);
        break;
    }
    case SERVICE::GetLocalChainIDSize: {
        size_t idnums = GetLocalChainIDSize();
        MQMsgPush(msg, idnums);
        break;
    }
    case SERVICE::GetHyperBlockHealthInfo: {
        map<uint64, uint32> *pBlockHealthInfo = nullptr;
        MQMsgPop(msg, pBlockHealthInfo);
        GetHyperBlockHealthInfo(*pBlockHealthInfo);
        break;
    }
    case SERVICE::GetHeaderHashCacheLatestHID: {
        uint64 hid = GetHeaderHashCacheLatestHID();
        MQMsgPush(msg, hid);
        break;
    }
    case SERVICE::GetGlobalLatestHyperBlockNo: {
        uint64 hid = GetGlobalLatestHyperBlockNo();
        MQMsgPush(msg, hid);
        break;
    }
    case SERVICE::GetRemoteHyperBlockByID: {
        uint64 blockid = 0;
        MQMsgPop(msg, blockid);

        int ret = GetRemoteHyperBlockByID(blockid);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::GetRemoteHyperBlockByIDFromNode: {
        uint64 blockid = 0;
        string nodeid;
        MQMsgPop(msg, blockid, nodeid);

        GetRemoteHyperBlockByID(blockid, nodeid);
        return;
    }
    case SERVICE::GetRemoteBlockHeaderFromNode: {
        uint64 blockid = 0;
        uint16 range = 0;
        string nodeid;
        MQMsgPop(msg, blockid, range, nodeid);

        GetRemoteBlockHeader(blockid, range, nodeid);
        return;
    }
    case SERVICE::GetHyperBlockHeader: {
        uint64 hid = 0;
        uint16 range = 0;
        vector<T_HYPERBLOCKHEADER> *pvecblockheader = nullptr;
        MQMsgPop(msg, hid, range, pvecblockheader);

        bool ret = GetHyperBlockHeader(hid, range, *pvecblockheader);
        MQMsgPush(msg, ret);
        break;
    }
    case SERVICE::PutHyperBlockHeader: {
        T_HYPERBLOCKHEADER *phyperblockheader = nullptr;
        string nodeid;
        MQMsgPop(msg, phyperblockheader, nodeid);
        PutHyperBlockHeader(*phyperblockheader, nodeid);
        break;
    }
    case SERVICE::PutHyperBlockHeaderList: {
        vector<T_HYPERBLOCKHEADER> *phyperblockheaders = nullptr;
        string nodeid;
        MQMsgPop(msg, phyperblockheaders, nodeid);
        PutHyperBlockHeader(*phyperblockheaders, nodeid);
        break;
    }
    case SERVICE::NoHyperBlockHeader: {
        uint64_t blockid;
        string nodeid;
        MQMsgPop(msg, blockid, nodeid);
        NoHyperBlockHeader(blockid, nodeid);
        break;
    }

    default:
        break;
    }
    realwrk->reply(reply_who, msg);
}

void CHyperChainSpace::SyncBlockHeaderData()
{
    if (!m_ChainspaceReady) {
        return;
    }

    uint64 headerHID = GetHeaderHashCacheLatestHID();
    uint64 globalHID = GetGlobalLatestHyperBlockNo();

    if ((headerHID != -1 && headerHID >= globalHID)) {
        m_localHeaderReady = true;
        return;
    }

    if (m_db->isHeaderIndexExisted(globalHID)) {
        m_localHeaderReady = true;
        return;
    }

    m_localHeaderReady = false;

    int ret = 0;
    uint16 range = 0;
    uint64 startHID = 0;
    uint64 endHID = 0;
    uint16 nums = 0;
    uint16 once = 4;

    if (headerHID == 0) {
        

        if (pro_ver == ProtocolVer::NET::INFORMAL_NET && startHID < INFORMALNET_GENESISBLOCKID) {
            

            startHID = INFORMALNET_GENESISBLOCKID - 1;
        }

        nums = globalHID - startHID;
        startHID++;

        do
        {
            range = nums > MATURITY_SIZE ? MATURITY_SIZE : nums;
            ret = GetRemoteBlockHeader(startHID, range);
            startHID += range;
            nums -= range;
            once--;
        } while (nums > 0 && once > 0);

        return;
    }

    if (sync_header_hid == 0 && headerHID > 0) {
        sync_header_hid = headerHID;
        ret = GetRemoteBlockHeader(sync_header_hid, 1);
        if (ret <= 0) {
            g_daily_logger->error("SyncBlockHeaderData failed! GetRemoteBlockHeader, hid: [{}]", sync_header_hid);
            g_console_logger->error("SyncBlockHeaderData failed! GetRemoteBlockHeader, hid: [{}]", sync_header_hid);
            return;
        }

        sync_header_time = system_clock::now();
        sync_header_ready = false;
        sync_header_furcated = false;
        return;
    }

    if (!sync_header_ready) {
        using seconds = std::chrono::duration<double, ratio<1>>;
        system_clock::time_point curr = system_clock::now();
        seconds timespan = std::chrono::duration_cast<seconds>(curr - sync_header_time);

        if (timespan.count() < 3)
            return;

        

        ret = GetRemoteBlockHeader(sync_header_hid, 1);
        if (ret <= 0) {
            g_daily_logger->error("SyncBlockHeaderData failed! GetRemoteBlockHeader, hid: [{}]", sync_header_hid);
            g_console_logger->error("SyncBlockHeaderData failed! GetRemoteBlockHeader, hid: [{}]", sync_header_hid);
            return;
        }

        sync_header_time = system_clock::now();
        return;
    }

    

    if (/*sync_header_ready && */sync_header_furcated) {
        sync_header_hid = sync_header_hid > MATURITY_SIZE ? sync_header_hid - MATURITY_SIZE : 0;
        if ((pro_ver == ProtocolVer::NET::SAND_BOX && sync_header_hid > 0) || (pro_ver == ProtocolVer::NET::INFORMAL_NET &&
            sync_header_hid > INFORMALNET_GENESISBLOCKID)) {
            ret = GetRemoteBlockHeader(sync_header_hid, 1);
            if (ret <= 0) {
                g_daily_logger->error("SyncBlockHeaderData failed! GetRemoteBlockHeader, hid: [{}]", sync_header_hid);
                g_console_logger->error("SyncBlockHeaderData failed! GetRemoteBlockHeader, hid: [{}]", sync_header_hid);
                return;
            }

            sync_header_time = system_clock::now();
            sync_header_ready = false;
            sync_header_furcated = false;
            return;
        }
    }

    bool furcated = false;
    startHID = sync_header_hid;
    endHID = globalHID;

    if (sync_header_hid < headerHID) {
        endHID = headerHID;
        furcated = true;
    }

    sync_header_hid = 0;

    if (pro_ver == ProtocolVer::NET::INFORMAL_NET && startHID < INFORMALNET_GENESISBLOCKID) {
        

        startHID = INFORMALNET_GENESISBLOCKID - 1;
    }

    nums = endHID - startHID;
    startHID++;

    if (furcated) {
        do
        {
            range = nums > MATURITY_SIZE ? MATURITY_SIZE : nums;
            GetRemoteBlockHeader(startHID, range);
            startHID += range;
            nums -= range;
        } while (nums > 0);
        return;
    }

    once = 4;
    do
    {
        range = nums > MATURITY_SIZE ? MATURITY_SIZE : nums;
        GetRemoteBlockHeader(startHID, range);
        startHID += range;
        nums -= range;
        once--;
    } while (nums > 0 && once > 0);
}

void CHyperChainSpace::SyncHyperBlockData()
{
    if ((!m_FullNode && !m_localHeaderReady) ||
        (m_FullNode && !m_ChainspaceReady)) {
        return;
    }

    uint64 headerHID = GetHeaderHashCacheLatestHID();
    uint64 localHID = GetLocalLatestHID();
    bool DataReady = true;

    uint64 syncHID = headerHID;

    if (m_FullNode) {
        if (m_localHIDsection.size() > 1) {
            DataReady = false;

            string strIDtoID = m_localHIDsection[0];
            string::size_type ns = strIDtoID.find("-");
            if ((ns != string::npos) && (ns > 0)) {
                syncHID = stoull(strIDtoID.substr(ns + 1, strIDtoID.length() - 1));
            }
            else {
                syncHID = stoull(strIDtoID);
            }

            syncHID++;
        }
    }

    if (DataReady && (headerHID == localHID)) {
        m_LatestBlockReady = true;
        return;
    }

    using seconds = std::chrono::duration<double, ratio<1>>;
    system_clock::time_point curr = system_clock::now();
    seconds timespan = std::chrono::duration_cast<seconds>(curr - sync_time);

    if ((sync_hid == syncHID) && timespan.count() < 3) {
        

        return;
    }

    T_SHA256 prehash;
    T_SHA256 headerhash;
    if (!GetHyperBlockHeaderHash(syncHID, headerhash)) {
        g_daily_logger->error("SyncHyperBlockData failed! GetHyperBlockHeaderHash, hid:[{}]", syncHID);
        g_console_logger->error("SyncHyperBlockData failed! GetHyperBlockHeaderHash, hid:[{}]", syncHID);
        return;
    }

    auto it = m_HeaderIndexMap.find(headerhash);
    if (it == m_HeaderIndexMap.end()) {
        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        g_daily_logger->error("SyncHyperBlockData failed! Can't find headerhash: [{}]", HeaderHash);
        g_console_logger->error("SyncHyperBlockData failed! Can't find headerhash: [{}]", HeaderHash);
        return;
    }

    prehash = it->second.prehash;

    int ret = GetRemoteHyperBlockByPreHash(syncHID, prehash);
    if (ret <= 0) {
        char PreHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(PreHash, prehash);
        g_daily_logger->error("SyncHyperBlockData failed! GetRemoteHyperBlockByPreHash, hid: {}, prehash: [{}]", syncHID, PreHash);
        g_console_logger->error("SyncHyperBlockData failed! GetRemoteHyperBlockByPreHash, hid: {}, prehash: [{}]", syncHID, PreHash);
        return;
    }

    sync_hid = syncHID;
    sync_time = system_clock::now();
}

void CHyperChainSpace::PullHyperBlock()
{
    if (_isstop) {
        return;
    }

    SyncBlockHeaderData();
    SyncHyperBlockData();
}

void CHyperChainSpace::CollatingChainSpace()
{
    if (_isstop) {
        return;
    }

    CollatingChainSpaceDate();
}



void CHyperChainSpace::GetMulticastNodes(vector<CUInt128> &nodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        nodes = m_MulticastNodes;
        m_MulticastNodes.clear();
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetMulticastNodes, &nodes);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::PutHyperBlock(T_HYPERBLOCK &hyperblock, string from_nodeid, vector<CUInt128> &multicastnodes)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        uint64 blockid = hyperblock.GetID();

        if (0 == from_nodeid.compare("myself")) {
            

            if (uiMaxBlockNum > blockid) {
                g_daily_logger->warn("Create invalid hyper block: [{}] for block id check failed, Current MaxBlockID: [{}]", blockid, uiMaxBlockNum);
                g_console_logger->warn("Create invalid hyper block: [{}] for block id check failed, Current MaxBlockID: [{}]", blockid, uiMaxBlockNum);
                return;
            }

            m_MulticastNodes = multicastnodes;
        }

        

        CHECK_RESULT ret = CheckDependency(hyperblock, from_nodeid);
        if (CHECK_RESULT::VALID_DATA == ret) {
            

            updateHyperBlockCache(hyperblock);
            return;
        }

        if (0 == from_nodeid.compare("myself")) {
            g_daily_logger->warn("Create invalid hyper block: {} for dependency check failed", blockid);
            g_console_logger->warn("Create invalid hyper block: {} for dependency check failed", blockid);
            return;
        }

        if (CHECK_RESULT::INVALID_DATA == ret) {
            g_daily_logger->warn("Received invalid hyper block: {} for dependency check failed", blockid);
            g_console_logger->warn("Received invalid hyper block: {} for dependency check failed", blockid);
            return;
        }

        if (CHECK_RESULT::UNCONFIRMED_DATA == ret) {
            g_console_logger->warn("Received hyper block: {} for dependency check failed", blockid);

            uint64 startid = blockid > MATURITY_SIZE ? blockid - MATURITY_SIZE : 0;
            if (pro_ver == ProtocolVer::NET::INFORMAL_NET && startid < INFORMALNET_GENESISBLOCKID) {
                

                startid = INFORMALNET_GENESISBLOCKID;
            }

            uint16 range = blockid - startid;
            PullBlockHeaderData(startid + 1, range, from_nodeid);
            g_daily_logger->warn("Pull Block Header, startid:[{}] range:[{}] from:[{}] for dependency check", startid, range, from_nodeid);
            g_console_logger->warn("Pull Block Header, startid:[{}] range:[{}] from:[{}] for dependency check", startid, range, from_nodeid);
        }
    }
    else {
        //MQRequestNoWaitResult(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlock, &hyperblock, from_nodeid, &multicastnodes);
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlock, &hyperblock, from_nodeid, &multicastnodes);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

bool CHyperChainSpace::GetHyperBlockHeader(uint64 hid, uint16 range, vector<T_HYPERBLOCKHEADER>& vecblockheader)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (!m_db) {
            return false;
        }

        vector<T_SHA256> vecheaderhash;
        GetHyperBlockHeaderHash(hid, range, vecheaderhash);

        map<T_SHA256, T_HYPERBLOCKHEADER> mapblockheader;
        m_db->getHeadersByID(mapblockheader, hid, range + hid);

        for (auto &headerhash : vecheaderhash) {
            if (mapblockheader.count(headerhash))
                vecblockheader.push_back(mapblockheader[headerhash]);
        }

        return vecblockheader.size() > 0;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockHeader, hid, range, &vecblockheader);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}







bool CHyperChainSpace::isBetterThanLocalChain(const T_HEADERINDEX &localHeaderIndex, const T_HEADERINDEX &HeaderIndex)
{
    if (HeaderIndex.total_weight < localHeaderIndex.total_weight) {
        return false;
    }

    if (HeaderIndex.total_weight > localHeaderIndex.total_weight) {
        return true;
    }

    if (HeaderIndex.ctime > localHeaderIndex.ctime) {
        return false;
    }

    if (HeaderIndex.ctime < localHeaderIndex.ctime) {
        return true;
    }

    if (HeaderIndex.headerhash < localHeaderIndex.headerhash) {
        return true;
    }

    return false;
}

void CHyperChainSpace::CollatingChainSpaceDate()
{
    int num = 0;
    bool foundSingleHeader;
    bool foundBlocksHeaderHash;
    bool foundHeaderIndex;
    T_SHA256 headerhash;
    uint64 maxblockid = uiMaxBlockNum;

    if (!m_LatestBlockReady)
        return;

    if (maxblockid <= MATURITY_SIZE)
        return;

    uint64 startid = maxblockid - MATURITY_SIZE;
    vector<T_SHA256> vecheaderhash;

    for (uint64 i = startid; i > 1; i--) {
        if (!GetHyperBlockHeaderHash(i, headerhash)) {
            g_daily_logger->error("CollatingChainSpaceDate() GetHyperBlockHeaderHash failed! hid:[{}]", i);
            g_console_logger->error("CollatingChainSpaceDate() GetHyperBlockHeaderHash failed! hid:[{}]", i);
            continue;
        }

        vecheaderhash.clear();
        if (!m_db->getFurcatedHeaderHash(i, headerhash, vecheaderhash)) {
            if (vecheaderhash.empty()) {
                num++;
                if (num >= MATURITY_SIZE) {
                    

                    break;
                }

                continue;
            }

            num = 0;
            for (auto &hhash : vecheaderhash) {
                foundSingleHeader = false;
                foundBlocksHeaderHash = false;
                foundHeaderIndex = false;

                

                auto ir = m_SingleHeaderMap.find(hhash);
                if (ir != m_SingleHeaderMap.end()) {
                    m_SingleHeaderMap.erase(ir);
                    foundSingleHeader = true;
                }

                if (foundSingleHeader) {
                    m_db->deleteSingleHeaderInfo(hhash);
                    continue;
                }

                

                for (auto tr = m_BlocksHeaderHash.begin(); tr != m_BlocksHeaderHash.end(); tr++) {
                    if ((*tr).empty())
                        continue;

                    auto ir = (*tr).begin();
                    if (*ir != hhash)
                        continue;

                    for (auto &hh : (*tr)) {
                        

                        auto it = m_HeaderIndexMap.find(hh);
                        if (it != m_HeaderIndexMap.end()) {
                            m_HeaderIndexMap.erase(it);
                            foundHeaderIndex = true;
                        }

                        if (foundHeaderIndex) {
                            m_db->deleteHeaderIndex(hh);
                        }

                        

                        m_db->deleteHyperblockAndLocalblock(hh);
                    }

                    (*tr).clear();
                    m_BlocksHeaderHash.erase(tr);
                    foundBlocksHeaderHash = true;
                    break;
                }

                if (foundBlocksHeaderHash)
                    continue;

                

                auto it = m_HeaderIndexMap.find(hhash);
                if (it != m_HeaderIndexMap.end()) {
                    m_HeaderIndexMap.erase(it);
                    foundHeaderIndex = true;
                }

                if (foundHeaderIndex) {
                    m_db->deleteHeaderIndex(hhash);
                }

                

                m_db->deleteHyperblockAndLocalblock(hhash);

                

                m_db->deleteHeader(hhash);
            }
        }
    }
}

bool CHyperChainSpace::SaveHeaderIndex(T_SHA256 headerhash, T_SHA256 preheaderhash, T_HYPERBLOCKHEADER header, string from_nodeid, bool &Flag)
{
    int ret;
    bool isBetter = false;
    bool AcceptFlag = false;
    bool IsBestHeader = false;
    bool IsGensisBlock = false;
    uint32 total = 0;
    uint32 weight = 0;
    uint64 hid = header.GetID();
    T_SHA256 LBestHeaderHash;
    T_HEADERINDEX headerindex;
    T_HEADERINDEX LBestHeaderIndex;

    if ((pro_ver == ProtocolVer::NET::SAND_BOX && hid == 0) || (pro_ver == ProtocolVer::NET::INFORMAL_NET &&
        hid == INFORMALNET_GENESISBLOCKID && headerhash == INFORMALNET_GENESISBLOCK_HEADERHASH)) {
        

        total = 0;
        AcceptFlag = true;
        IsGensisBlock = true;
    }
    else {
        auto it = m_HeaderIndexMap.find(preheaderhash);
        if (it != m_HeaderIndexMap.end()) {
            total = it->second.total_weight;
            AcceptFlag = true;
        }
    }

    if (!AcceptFlag) {
        if (hid == sync_header_hid) {
            sync_header_furcated = true;
        }

        auto ir = m_SingleHeaderMap.find(headerhash);
        if (ir == m_SingleHeaderMap.end()) {
            

            T_SINGLEHEADER singleheader;
            singleheader.headerhash = headerhash;
            singleheader.preheaderhash = preheaderhash;
            singleheader.from_id = from_nodeid;

            m_SingleHeaderMap[headerhash] = singleheader;

            

            ret = m_db->updateSingleHeaderInfo(singleheader);
            if (ret != 0) {
                char HeaderHash[FILESIZEL] = { 0 };
                CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
                g_daily_logger->error("updateSingleHeaderInfo failed!({}) headerhash: [{}]", ret, HeaderHash);
                g_console_logger->error("updateSingleHeaderInfo failed!({}) headerhash: [{}]", ret, HeaderHash);
            }

            

            /*if (m_SingleHeaderMap.find(preheaderhash) == m_SingleHeaderMap.end()){
                uint64 startid = hid > MATURITY_SIZE ? hid - MATURITY_SIZE : 0;
                if (pro_ver ==  ProtocolVer::NET::INFORMAL_NET && startid < INFORMALNET_GENESISBLOCKID) {
                    HC: 测试网数据校验起始块为INFORMALNET_GENESISBLOCKID
                    startid = INFORMALNET_GENESISBLOCKID;
                }

                uint16 range = hid - startid;
                PullBlockHeaderData(startid + 1, range, from_nodeid);
                g_console_logger->warn("Pull Block Header, startid:[{}] range:[{}] from:[{}] for dependency check", startid, range, from_nodeid);
            }*/
        }

        return isBetter;
    }

    bool headerindex_exist = false;
    auto irt = m_HeaderIndexMap.find(headerhash);
    if (irt != m_HeaderIndexMap.end()) {
        headerindex = irt->second;
        headerindex_exist = true;
    }
    else {
        weight = header.GetChildBlockCount();

        headerindex.id = hid;
        headerindex.prehash = header.GetPreHash();
        headerindex.headerhash = headerhash;
        headerindex.preheaderhash = preheaderhash;
        headerindex.ctime = header.GetCTime();
        headerindex.weight = weight;
        headerindex.total_weight = total + weight;
        headerindex.from_id = from_nodeid;

        m_HeaderIndexMap[headerhash] = headerindex;

        

        ret = m_db->updateHeaderIndex(headerindex);
        if (ret != 0) {
            g_daily_logger->error("updateHeaderIndex failed!({}) hid: [{}]", ret, hid);
            g_console_logger->error("updateHeaderIndex failed!({}) hid: [{}]", ret, hid);
        }
    }

    

    if (IsGensisBlock == true) {
        m_HeaderHashMap[hid] = headerhash;
        LBestHeaderHash = headerhash;
        IsBestHeader = true;
    }
    else if (!m_HeaderHashMap.empty()) {
        auto ir = m_HeaderHashMap.end();
        ir--;

        LBestHeaderHash = ir->second;
        if ((ir->first == hid - 1) && (LBestHeaderHash == preheaderhash)) {
            

            m_HeaderHashMap[hid] = headerhash;
            LBestHeaderHash = headerhash;
            IsBestHeader = true;
        }
    }

    if (IsBestHeader == true) {
        m_db->updateHeaderHashInfo(hid, headerhash);
        if (hid > uiMaxHeaderID)
            uiMaxHeaderID = hid;
        /*char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        g_console_logger->info("IsBestHeader {} [{}]", hid, HeaderHash);*/
    }
    else if (!headerindex_exist) {
        

        auto it = m_HeaderIndexMap.find(LBestHeaderHash);
        if (it != m_HeaderIndexMap.end()) {
            LBestHeaderIndex = it->second;
        }

        

        bool finded = false;
        for (auto tr = m_BlocksHeaderHash.begin(); tr != m_BlocksHeaderHash.end(); tr++) {
            if ((*tr).empty())
                continue;

            auto ir = (*tr).end();
            ir--;

            if (*ir == preheaderhash) {
                (*tr).push_back(headerhash);
                m_HashChain = tr;
                finded = true;
                break;
            }
        }

        if (finded == false) {
            list<T_SHA256> listhash;
            listhash.emplace_back(headerhash);
            m_BlocksHeaderHash.push_back(listhash);
            m_HashChain = m_BlocksHeaderHash.end() - 1;
        }

        if (isBetterThanLocalChain(LBestHeaderIndex, headerindex)) {
            char HeaderHash[FILESIZEL] = { 0 };
            CCommonStruct::Hash256ToStr(HeaderHash, headerindex.headerhash);
            g_daily_logger->info("isBetterThanLocalChain is true. id:[{}], total_weight:[{}], headerhash:[{}]",
                headerindex.id, headerindex.total_weight, HeaderHash);
            isBetter = true;

            return isBetter;
        }
    }

    Flag = true;

    return isBetter;
}

bool CHyperChainSpace::SwitchLocalBestChain()
{
    bool found = false;
    uint64 hid = 0;
    string nodeid;
    T_SHA256 preheaderhash;
    T_HEADERINDEX localheaderindex;
    list<T_SHA256> listhash;

    auto it = m_HeaderIndexMap.find(*(*m_HashChain).begin());
    if (it == m_HeaderIndexMap.end()) {
        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, *(*m_HashChain).begin());
        g_daily_logger->error("SwitchLocalBestChain failed! Can't find headerhash: [{}]", HeaderHash);
        g_console_logger->error("SwitchLocalBestChain failed! Can't find headerhash: [{}]", HeaderHash);
        return false;
    }

    hid = it->second.id;
    nodeid = it->second.from_id;
    preheaderhash = it->second.preheaderhash;

    

    T_HYPERBLOCK hblk;
    if (CHyperchainDB::getHyperBlock(hblk, hid - 1)) {
        publishNewHyperBlock(hid - 2, hblk, true, true);
    }

    if (m_db->isBlockExistedOnBestChain(hid)) {
        

        m_db->rollbackHyperblockAndLocalblock(hid);
        m_db->rollbackHashInfo(hid);

        g_daily_logger->info("rollbackHyperBlockCache, starting hid:{}", hid);

        for (uint64 currblockid = hid; currblockid <= uiMaxHeaderID; currblockid++) {
            m_localHID.erase(currblockid);

            

            m_BlockHashMap.erase(currblockid);
        }

        GenerateHIDSection();

        

        uint64 nHyperId = GetLocalLatestHID();
        T_HYPERBLOCK hyperBlock;
        if (CHyperchainDB::getHyperBlock(hyperBlock, nHyperId)) {
            uiMaxBlockNum = nHyperId;
            m_LatestHyperBlock = std::move(hyperBlock);
            g_daily_logger->info("rollbackHyperBlockCache, uiMaxBlockNum:{}", hyperBlock.GetID());
        }

        found = true;
    }

    

    m_db->rollbackHeaderHashInfo(hid);

    for (auto ir = m_HeaderHashMap.find(hid); ir != m_HeaderHashMap.end();) {
        listhash.emplace_back(ir->second);

        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, ir->second);
        g_daily_logger->info("SwitchLocalBestChain, m_HeaderHashMap, delete hid:[{}], headerhash: [{}]", ir->first, HeaderHash);

        m_HeaderHashMap.erase(ir++);
    }

    

    for (auto ir = (*m_HashChain).begin(); ir != (*m_HashChain).end(); ir++, hid++) {
        m_HeaderHashMap[hid] = *ir;
        m_db->updateHeaderHashInfo(hid, *ir);

        char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, *ir);
        g_daily_logger->info("SwitchLocalBestChain, m_HeaderHashMap, insert hid:[{}], headerhash: [{}]", hid, HeaderHash);

        

        if (m_db->isBlockExistedbyHeaderHash(*ir)) {
            T_HYPERBLOCK hyperblock;
            if (CHyperchainDB::getHyperBlockbyHeaderHash(hyperblock, *ir)) {
                updateHyperBlockCache(hyperblock);
                continue;
            }
        }

        

        //if (found) {
        //    

        //    auto irt = m_HeaderIndexMap.find(*ir);
        //    if (irt != m_HeaderIndexMap.end()) {
        //        g_daily_logger->info("SwitchLocalBestChain, GetRemoteHyperBlockByPreHash, hid:{}", hid);
        //        GetRemoteHyperBlockByPreHash(hid, irt->second.prehash);
        //    }
        //}
    }

    uiMaxHeaderID = m_HeaderHashMap.empty() ? 0 : m_HeaderHashMap.rbegin()->first;
    g_daily_logger->info("SwitchLocalBestChain, uiMaxHeaderID:{}", uiMaxHeaderID);

    (*m_HashChain).clear();

    

    m_BlocksHeaderHash.erase(m_HashChain);
    m_BlocksHeaderHash.push_back(listhash);

    return true;
}

void CHyperChainSpace::PutHyperBlockHeader(vector<T_HYPERBLOCKHEADER>& hyperblockheaders, string from_nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        for (auto iter = hyperblockheaders.begin(); iter != hyperblockheaders.end(); iter++) {
            PutHyperBlockHeader(*iter, from_nodeid);
        }

        uint64 globalHID = GetGlobalLatestHyperBlockNo();
        if (m_db->isHeaderIndexExisted(globalHID)) {
            m_localHeaderReady = true;
        }
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlockHeaderList, &hyperblockheaders, from_nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

void CHyperChainSpace::PutHyperBlockHeader(T_HYPERBLOCKHEADER& hyperblockheader, string from_nodeid)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        bool found = false;
        uint64 hid = hyperblockheader.GetID();
        if (hid == -1)
            return;

        T_SHA256 headerhash = hyperblockheader.calculateHeaderHashSelf();
        T_SHA256 preheaderhash = hyperblockheader.GetPreHeaderHash();

        /*char HeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HeaderHash, headerhash);
        char preHeaderHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(preHeaderHash, preheaderhash);
        g_console_logger->info("PutHyperBlockHeader(), hyper block: [{}] headerhash: [{}] preheaderhash: [{}] nodeid: [{}]",
            hid, HeaderHash, preHeaderHash, from_nodeid);*/

        if (hid == sync_header_hid) {
            sync_header_ready = true;
        }

        T_SHA256 blockheaderhash;
        if (GetHyperBlockHeaderHash(hid, blockheaderhash)) {
            if (headerhash == blockheaderhash)
                return;
        }

        if (m_db->isHeaderExistedbyHash(headerhash)) {
            found = true;
        }

        if (!found) {
            

            int ret = m_db->updateHeaderInfo(hid, headerhash, hyperblockheader);
            if (ret != 0) {
                g_daily_logger->error("updateHeaderInfo failed! hid: [{}]", hid);
                g_console_logger->error("updateHeaderInfo failed! hid: [{}]", hid);
                return;
            }
        }

        bool isBetter;
        bool CheckFlag = false;
        

    RETRY:
        isBetter = SaveHeaderIndex(headerhash, preheaderhash, hyperblockheader, from_nodeid, CheckFlag);
        if (isBetter) {
            

            m_LatestBlockReady = false;
            SwitchLocalBestChain();
        }

        if (CheckFlag) {
            

            bool find = false;
            T_SINGLEHEADER singleheader;
            auto ir = m_SingleHeaderMap.begin();
            for (; ir != m_SingleHeaderMap.end(); ir++) {
                if (ir->second.preheaderhash != headerhash)
                    continue;

                singleheader = ir->second;
                find = true;
                break;
            }

            if (!find) {
                return;
            }

            

            int ret;
            T_HYPERBLOCKHEADER header;
            ret = m_db->getHeaderByHash(header, singleheader.headerhash);
            if (ret != 0) {
                char HeaderHash[FILESIZEL] = { 0 };
                CCommonStruct::Hash256ToStr(HeaderHash, singleheader.headerhash);
                g_daily_logger->error("getHeaderByHash failed! hash: [{}]", HeaderHash);
                g_console_logger->error("getHeaderByHash failed! hash: [{}]", HeaderHash);
                return;
            }

            

            ret = m_db->deleteSingleHeaderInfo(singleheader.headerhash);
            if (ret != 0) {
                char HeaderHash[FILESIZEL] = { 0 };
                CCommonStruct::Hash256ToStr(HeaderHash, singleheader.headerhash);
                g_daily_logger->error("deleteSingleHeaderInfo failed!({}) headerhash: [{}]", ret, HeaderHash);
                g_console_logger->error("deleteSingleHeaderInfo failed!({}) headerhash: [{}]", ret, HeaderHash);
            }

            

            m_SingleHeaderMap.erase(ir);

            headerhash = singleheader.headerhash;
            preheaderhash = singleheader.preheaderhash;
            hyperblockheader = header;
            from_nodeid = singleheader.from_id;
            CheckFlag = false;
            goto RETRY;
        }
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::PutHyperBlockHeader, &hyperblockheader, from_nodeid);
        if (rspmsg) {
            delete rspmsg;
        }
    }
}

bool CHyperChainSpace::getHyperBlock(uint64 hid, T_HYPERBLOCK &hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_localHID.empty() || !m_localHID.count(hid))
            return false;

        if (m_LatestHyperBlock.GetID() == hid) {
            hyperblock = m_LatestHyperBlock;
            return true;
        }

        

        return CHyperchainDB::getHyperBlock(hyperblock, hid);
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockByID, hid, &hyperblock);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

bool CHyperChainSpace::getHyperBlock(const T_SHA256 &hhash, T_HYPERBLOCK &hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_LatestHyperBlock.GetHashSelf() == hhash) {
            hyperblock = m_LatestHyperBlock;
            return true;
        }

        

        return CHyperchainDB::getHyperBlock(hyperblock, hhash);
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockByHash, &hhash, &hyperblock);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

bool CHyperChainSpace::getHyperBlockByPreHash(T_SHA256 &prehash, T_HYPERBLOCK &hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        if (m_LatestHyperBlock.GetPreHash() == prehash) {
            hyperblock = m_LatestHyperBlock;
            return true;
        }

        

        return CHyperchainDB::getHyperBlock(hyperblock, prehash);
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::GetHyperBlockByPreHash, &prehash, &hyperblock);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::SaveToLocalStorage(const T_HYPERBLOCK &tHyperBlock)
{
    DBmgr::Transaction t = m_db->beginTran();

    

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



bool CHyperChainSpace::updateHyperBlockCache(T_HYPERBLOCK &hyperblock)
{
    if (_msghandler.getID() == std::this_thread::get_id()) {
        uint64_t currblockid = hyperblock.GetID();
        uint64_t blockcount = hyperblock.GetChildBlockCount();

        

        


        char HyperblockHash[FILESIZEL] = { 0 };
        CCommonStruct::Hash256ToStr(HyperblockHash, hyperblock.GetHashSelf());

        

        bool isBlockAlreadyExisted = false;
        if (!isAcceptHyperBlock(currblockid, hyperblock, isBlockAlreadyExisted)) {
            g_daily_logger->info("I have the hyper block or local is more well, refuse it: {} {} {}",
                currblockid, blockcount, HyperblockHash);
            return false;
        }

        

        

        


        g_daily_logger->info("I accept the hyper block: {} {} {}",
            currblockid, blockcount, HyperblockHash);

        //g_tP2pManagerStatus->ApplicationAccept(currblockid - 1, hyperblock, uiMaxBlockNum <= currblockid);
        SaveToLocalStorage(hyperblock);

        

        T_SHA256 headerhash = hyperblock.calculateHeaderHashSelf();
        m_db->updateHashInfo(currblockid, headerhash, hyperblock.GetHashSelf());

        

        m_BlockHashMap[currblockid] = hyperblock.GetHashSelf();

        if (!isBlockAlreadyExisted) {
            

            m_localHID.insert(currblockid);
            GenerateHIDSection();
        }

        if (uiMaxBlockNum <= currblockid) {
            

            uiMaxBlockNum = currblockid;
            m_LatestHyperBlock = std::move(hyperblock);

            

            publishNewHyperBlock(currblockid - 1, m_LatestHyperBlock, true, false);

            uint64 headerHID = GetHeaderHashCacheLatestHID();
            if (m_localHeaderReady && currblockid >= headerHID) {
                m_LatestBlockReady = true;

                if (currblockid != 0) {
                    

                    BoardcastHyperBlockTask task;
                    task.exec();
                }
            }
        }
        else {
            publishNewHyperBlock(currblockid - 1, hyperblock, false, false);
        }

        return true;
    }
    else {
        zmsg *rspmsg = MQRequest(HYPERCHAINSPACE_SERVICE, (int)SERVICE::UpdateHyperBlockCache, &hyperblock);

        bool ret = false;
        if (rspmsg) {
            MQMsgPop(rspmsg, ret);
            delete rspmsg;
        }

        return ret;
    }
}

void CHyperChainSpace::publishNewHyperBlock(uint32_t hidFork, const T_HYPERBLOCK &hyperblock, bool isLatest, bool needSwitch)
{
    stringstream ssBuf;
    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
    putStream(oa, hyperblock);

    zmsg msg;
    MQMsgPush(&msg, hidFork, ssBuf.str(), isLatest, needSwitch);
    msg.send(*_hyperblock_pub);
}





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

    bool Existed = getHyperBlock(blockid, localHyperBlock);
    if (!Existed) {
        isAlreadyExisted = false;
        return true;
    }

    isAlreadyExisted = true;

    T_SHA256 lblockhash = localHyperBlock.GetHashSelf();
    T_SHA256 rblockhash = remoteHyperBlock.GetHashSelf();
    if (lblockhash == rblockhash) {
        g_daily_logger->info("I have the hyper block: {}", blockid);
        return false;
    }

    g_daily_logger->info("hyper block {} has furcated, update local data", blockid);
    return true;
}

void getFromStream(boost::archive::binary_iarchive &ia, T_HYPERBLOCK& hyperblock, T_SHA256 &hash)
{
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

void putStream(boost::archive::binary_oarchive &oa, const vector<T_HYPERBLOCKHEADER>& hyperblockheader)
{
    uint32 headernum = hyperblockheader.size();
    oa << headernum;
    for (auto iter = hyperblockheader.begin(); iter != hyperblockheader.end(); iter++) {
        oa << (*iter);
    }
}
