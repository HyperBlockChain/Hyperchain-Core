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

#include "headers/commonstruct.h"
#include "utility/MutexObj.h"
#include "node/MsgHandler.h"

#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include "../Types.h"
using namespace std;
using std::chrono::system_clock;

#define MATURITY_SIZE	50
#define MAX_BLOCKHEADER_NUMS  100
#define INFORMALNET_GENESISBLOCKID  48600
#define INFORMALNET_GENESISBLOCK_HEADERHASH CCommonStruct::StrToHash256("91bc676065c8613c130050e14c9fd9bd287501e934ac1b7f40894c9c9781c5c1")

typedef struct _difficultyinfo
{
    uint64 startid;  

    uint16 count;    

    _difficultyinfo(uint64 id, uint16 num) {
        startid = id;
        count = num;
    }

    uint64 GetStartid()const {
        return startid;
    }

    uint16 GetCount()const {
        return count;
    }

}T_DIFFICULTYINFO, *T_PDIFFICULTYINFO;

typedef struct _theaderhashinfo
{
    T_SHA256 headerhash;   

    set<string> nodeids;   

    _theaderhashinfo(T_SHA256 hash, string nodeid) {
        headerhash = hash;
        nodeids.insert(nodeid);
    }

    void PutNodeID(string nodeid) {
        nodeids.insert(nodeid);
        return;
    }

    T_SHA256 GetHeaderHash()const {
        return headerhash;
    }

    size_t GetVote()const {
        return nodeids.size();
    }

}T_HEADERHASHINFO, *T_PHEADERHASHINFO;

typedef list<T_HEADERHASHINFO> LIST_T_HEADERHASHINFO;
typedef LIST_T_HEADERHASHINFO::iterator ITR_LIST_T_HEADERHASHINFO;

typedef map<uint64, LIST_T_HEADERHASHINFO> MAP_T_UNCONFIRMEDHEADERHASH;
typedef MAP_T_UNCONFIRMEDHEADERHASH::iterator ITR_MAP_T_UNCONFIRMEDHEADERHASH;

typedef map<uint64, LIST_T_HYPERBLOCK> MAP_T_UNCONFIRMEDBLOCK;
typedef MAP_T_UNCONFIRMEDBLOCK::iterator ITR_MAP_T_UNCONFIRMEDBLOCK;

typedef map<string, LIST_T_HYPERBLOCKHEADER> MAP_T_UNCONFIRMEDBLOCKHEADER;
typedef MAP_T_UNCONFIRMEDBLOCKHEADER::iterator ITR_MAP_T_UNCONFIRMEDBLOCKHEADER;

typedef vector<list<T_SHA256>>::iterator ITR_HASH_LIST;

enum class CHECK_RESULT :char {
    INVALID_DATA = 0,
    VALID_DATA,
    UNCONFIRMED_DATA,
    INCOMPATIBLE_DATA
};

class DBmgr;
class CHyperChainSpace
{
public:
    CHyperChainSpace(string nodeid);
    ~CHyperChainSpace() { stop(); }

    void start(DBmgr* db);
    void stop() {
        _isstop = true;
        _msghandler.stop();

        for (auto& t : m_threads) {
            t.join();
        }
        m_threads.clear();

        if (m_threadPullAppBlocks && m_threadPullAppBlocks->joinable()) {
            m_threadPullAppBlocks->join();
        }
    }

    void NoHyperBlock(uint64 hid, string nodeid);
    void NoHyperBlockHeader(uint64 hid, string nodeid);
    void PutHyperBlock(T_HYPERBLOCK &hyperblock, string from_nodeid, vector<CUInt128> &multicastnodes);
    bool GetHyperBlockHeader(uint64 hid, uint16 range, vector<T_HYPERBLOCKHEADER>& blockheader);
    void PutHyperBlockHeader(vector<T_HYPERBLOCKHEADER>& blockheader, string from_nodeid);
    void PutHyperBlockHeader(T_HYPERBLOCKHEADER& blockheader, string from_nodeid);
    void GetHyperBlockHeaderHash(uint64 hid, uint16 range, vector<T_SHA256> &vecheaderhash);
    bool GetHyperBlockHeaderHash(uint64 hid, T_SHA256 &headerhash);
    void PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash);
    void PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash, string from_nodeid);
    void GetHyperBlockHealthInfo(map<uint64, uint32> &out_BlockHealthInfo);
    int GetRemoteHyperBlockByID(uint64 globalHID);
    int GetRemoteHyperBlockByID(uint64 globalHID, const string& nodeid);
    int GetRemoteHyperBlockByPreHash(uint64 globalHID, T_SHA256 prehash);
    int GetRemoteHyperBlockHeaderHash(uint64 globalHID);
    int GetRemoteBlockHeader(uint64 startHID, uint16 range, string nodeid);
    int GetRemoteLocalBlockByAddr(const T_LOCALBLOCKADDRESS& addr);

    void GetAppBlocksByAddr(const T_LOCALBLOCKADDRESS& low_addr, const T_LOCALBLOCKADDRESS& high_addr, const T_APPTYPE& app);

    bool GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, T_SHA256& hhash, vector<T_PAYLOADADDR>& vecPA);
    //bool GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPA);

    bool GetLocalBlockPayload(const T_LOCALBLOCKADDRESS& addr, string& payload);
    bool GetLocalBlock(const T_LOCALBLOCKADDRESS& addr, T_LOCALBLOCK& localblock);

    

    bool getHyperBlock(uint64 hid, T_HYPERBLOCK &hyperblock);
    bool getHyperBlock(const T_SHA256 &hhash, T_HYPERBLOCK &hyperblock);
    bool getHyperBlockByPreHash(T_SHA256 &prehash, T_HYPERBLOCK &hyperblock);
    bool updateHyperBlockCache(T_HYPERBLOCK &hyperblock);
    void PullHyperDataByPreHash(uint64 globalHID, T_SHA256 prehash, string nodeid);
    void PullHeaderHashByHID(uint64 hid, string nodeid);

    void CheckLocalData();
    void SaveHyperblock(const T_HYPERBLOCK &hyperblock);

    void GetHyperChainData(map<uint64, set<string>>& chainspacedata);
    void GetHyperChainShow(map<string, string>& chainspaceshow);
    void GetLocalHIDsection(vector <string>& hidsection);
    T_SHA256 GetLatestHyperBlockHash() { return m_LatestHyperBlock.GetHashSelf(); }
    size_t GetLocalChainIDSize();

    uint64 GetMaxBlockID();
    void GetLatestHyperBlockIDAndHash(uint64 &id, T_SHA256 &hash);
    bool IsLatestHyperBlockReady();
    void GetLatestHyperBlock(T_HYPERBLOCK& hyperblock);
    void GetLocalHIDs(uint64 nStartHID, set<uint64>& setHID);
    void GetMulticastNodes(vector<CUInt128> &MulticastNodes);
    void AnalyzeChainSpaceData(string strbuf, string nodeid);

    uint64 GetLocalLatestHID() { return m_localHID.empty() ? -1 : *m_localHID.rbegin(); }
    uint64 GetHeaderHashCacheLatestHID();
    uint64 GetGlobalLatestHyperBlockNo();

    std::thread::id MQID()
    {
        return _msghandler.getID();
    }

private:
    int  GenerateHIDSection();
    void SyncBlockHeaderData();
    void SyncHyperBlockData();
    void loadHyperBlockCache();
    void loadHyperBlockIDCache();
    void loadHyperBlockHashCache();
    void CollatingChainSpaceDate();
    void PullHyperDataByHID(uint64 hid, string nodeid);
    void SaveToLocalStorage(const T_HYPERBLOCK &tHyperBlock);
    void RehandleUnconfirmedBlock(uint64 hid, T_SHA256 headerhash);
    bool isInUnconfirmedCache(uint64 hid, T_SHA256 blockhash);
    bool isAcceptHyperBlock(uint64 blockNum, const T_HYPERBLOCK &remoteHyperBlock, bool isAlreadyExisted);
    bool isMoreWellThanLocal(const T_HYPERBLOCK &localHyperBlock, uint64 blockid, uint64 blockcount, const T_SHA256& hhashself);
    bool isBetterThanLocalChain(const T_HEADERINDEX &localHeaderIndex, const T_HEADERINDEX &HeaderIndex);
    void SplitString(const string& s, vector<std::string>& v, const std::string& c);
    bool SaveHeaderIndex(T_SHA256 headerhash, T_SHA256 preheaderhash, T_HYPERBLOCKHEADER header, string from_nodeid, bool &Flag);
    bool SwitchLocalBestChain();

    void startMQHandler();
    CHECK_RESULT CheckDependency(const T_HYPERBLOCK &hyperblock, string nodeid);
    void publishNewHyperBlock(uint32_t hidFork, const T_HYPERBLOCK &hyperblock, bool isLatest, bool needSwitch);
    void PullBlockHeaderData(uint64 hid, uint16 range, string nodeid);
    int  GetRemoteBlockHeader(uint64 startHID, uint16 range);
    void DispatchService(void *wrk, zmsg *msg);
    void PullChainSpace();
    void PullHyperBlock();
    void CollatingChainSpace();

private:

    bool m_FullNode;                        

    string m_mynodeid;                      

    std::set<uint64> m_localHID;            

    vector <string> m_localHIDsection;      

    vector<CUInt128> m_MulticastNodes;      


    DBmgr* m_db = nullptr;

    uint64 sync_hid;                        

    system_clock::time_point sync_time;     


    bool m_LatestBlockReady;                 

    T_HYPERBLOCK m_LatestHyperBlock;         

    std::atomic<uint64> uiMaxBlockNum;       

    std::atomic<uint64> uiGlobalMaxBlockNum; 


    map<uint64, T_SHA256> m_BlockHashMap;    


    bool m_localHeaderReady;                 

    std::atomic<uint64> uiMaxHeaderID;       


    map<uint64, T_SHA256> m_HeaderHashMap;   


    uint64 sync_header_hid;                     

    system_clock::time_point sync_header_time;  

    bool sync_header_furcated;
    bool sync_header_ready;

    ITR_HASH_LIST m_HashChain;
    vector<list<T_SHA256>> m_BlocksHeaderHash;  


    MAP_T_HEADERINDEX m_HeaderIndexMap;      


    map<uint64, std::set<string>> m_ReqHeaderHashNodes;  


    map<T_SHA256, T_SINGLEHEADER> m_SingleHeaderMap;      


    MAP_T_UNCONFIRMEDBLOCK m_UnconfirmedBlockMap;         


    MAP_T_UNCONFIRMEDHEADERHASH m_UnconfirmedHashMap;     


    bool m_ChainspaceReady;
    map<uint64, std::set<string>> m_Chainspace; 


    map<uint64, uint32> m_BlockHealthInfo;      


    map<string, string> m_chainspaceshow;       


    map<string, uint64> m_chainspaceheader;     


    std::list<thread>  m_threads;
    unique_ptr<thread> m_threadPullAppBlocks;
    bool _isstop;

    

    MsgHandler _msghandler;
    zmq::socket_t *_hyperblock_pub = nullptr;

    enum class SERVICE : short
    {
        GetMaxBlockID = 1,
        GetLatestHyperBlockIDAndHash,
        IsLatestHyperBlockReady,
        GetLatestHyperBlock,
        GetHyperBlockByID,
        GetHyperBlockByHash,
        GetHyperBlockByPreHash,
        GetLocalBlocksByHID,
        GetLocalBlockPayload,
        GetLocalHIDs,

        AnalyzeChainSpaceData,
        UpdateHyperBlockCache,
        GetMulticastNodes,
        SaveHyperblock,
        PutHyperBlock,
        NoHyperBlock,

        GetHyperChainShow,
        GetHyperChainData,
        GetLocalHIDsection,
        GetLocalChainIDSize,
        GetHyperBlockHealthInfo,
        GetHeaderHashCacheLatestHID,
        GetGlobalLatestHyperBlockNo,

        GetRemoteHyperBlockByID,
        GetRemoteHyperBlockByIDFromNode,
        GetRemoteBlockHeaderFromNode,
        GetHyperBlockHeader,
        PutHyperBlockHeader,
        PutHyperBlockHeaderList,
        NoHyperBlockHeader,
    };
};
