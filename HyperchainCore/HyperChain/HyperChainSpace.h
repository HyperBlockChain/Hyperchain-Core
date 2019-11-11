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

#include "headers/commonstruct.h"
#include "utility/MutexObj.h"

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

#define MATURITY_SIZE	12

typedef struct _theaderhashinfo
{
    T_SHA256 headerhash;   //
    set<string> nodeids;   //
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
        if (m_threadpull->joinable()) {
            m_threadpull->join();
        }
        if (m_threadPullAppBlocks && m_threadPullAppBlocks->joinable()) {
            m_threadPullAppBlocks->join();
        }
    }

    bool GetHyperBlockHeaderHash(uint64 hid, T_SHA256 &headerhash);
    void PutHyperBlockHeaderHash(uint64 hid, T_SHA256 headerhash, string from_nodeid);
    void GetHyperBlockHealthInfo(map<uint64, uint32> &out_BlockHealthInfo);
    void GetUnconfirmedBlockMapShow(map<uint64, string>& out_UnconfirmedBlockMap);
    void GetHyperChainData(map<uint64, set<string>>& out_HyperChainData);
    void GetHyperChainShow(map<string, string>& out_HyperChainShow);
    void GetLocalChainShow(vector<string> & out_LocalChainShow);
    size_t GetLocalChainIDSize() { return m_localHID.size(); }
    uint64 GetGlobalLatestHyperBlockNo();
    int GetRemoteHyperBlockByID(uint64 globalHID);
    int GetRemoteHyperBlockByID(uint64 globalHID, const string& nodeid);
    int GetRemoteHyperBlockHeaderHash(uint64 globalHID);
    int GetRemoteLocalBlockByAddr(const T_LOCALBLOCKADDRESS& addr);

    void GetAppBlocksByAddr(const T_LOCALBLOCKADDRESS& low_addr, const T_LOCALBLOCKADDRESS& high_addr, const T_APPTYPE& app);

    bool GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, T_SHA256& hhash, vector<T_PAYLOADADDR>& vecPA);
    bool GetLocalBlocksByHID(uint64 globalHID, const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPA);

    bool GetLocalBlockPayload(const T_LOCALBLOCKADDRESS& addr, string& payload);
    bool GetLocalBlock(const T_LOCALBLOCKADDRESS& addr, T_LOCALBLOCK& localblock);

    //
    bool getHyperBlock(uint64 hid, T_HYPERBLOCK &hyperblock);
    bool getHyperBlockFromDB(uint64 hid, T_HYPERBLOCK& hyperblock);
    bool getHyperBlock(const T_SHA256 &hhash, T_HYPERBLOCK &hyperblock);
    bool getHyperBlockwithoutMutexLock(uint64 hid, T_HYPERBLOCK &hyperblock);
    bool IsLatestHyperBlockReady() { return m_LatestBlockReady; }
    bool updateHyperBlockCache(T_HYPERBLOCK &hyperblock);
    void PullHyperDataByHID(uint64 hid, string nodeid);
    void PullHeaderHashByHID(uint64 hid, string nodeid);

    CHECK_RESULT CheckDependency(const T_HYPERBLOCK &hyperblock);

    T_HYPERBLOCK& GetLatestHyperBlock() {
        return m_LatestHyperBlock;
    }

    uint64 GetMaxBlockID() const {
        return uiMaxBlockNum;
    }

    T_SHA256 GetLatestHyperBlockHash() {
        CAutoMutexLock muxAuto(m_MuxHchainBlockList);
        return m_LatestHyperBlock.GetHashSelf();
    }

    void GetLatestHyperBlockIDAndHash(uint64 &id, T_SHA256 &hash) {
        CAutoMutexLock muxAuto(m_MuxHchainBlockList);
        hash = m_LatestHyperBlock.GetHashSelf();
        id = m_LatestHyperBlock.GetID();
    }

    void SyncLatestHyperBlock();
    bool GetLocalHIDsection(string & mes);
    void AnalyzeChainSpaceData(string strbuf, string nodeid);

    uint64 GetLocalLatestHID() { return m_localHID.empty() ? 0 : *m_localHID.rbegin(); }

private:
    void PullDataThread();
    void PullAppDataThread(const T_LOCALBLOCKADDRESS& low_addr, const T_LOCALBLOCKADDRESS& high_addr, const T_APPTYPE& app);
    void PullChainSpaceData();
    int  GenerateHIDSection();
    void loadHyperBlockCache();
    void loadHyperBlockIDCache();
    void loadHyperBlockHashCache();
    void SaveToLocalStorage(const T_HYPERBLOCK &tHyperBlock);
    void SaveHashToLocalStorage(uint64 currblockid, T_SHA256 headerhash, T_SHA256 blockhash);
    void RehandleUnconfirmedBlock(uint64 hid, T_SHA256 headerhash);
    void PutUnconfirmedCache(const T_HYPERBLOCK &hyperblock);
    bool isInUnconfirmedCache(uint64 hid, T_SHA256 blockhash); 
    bool isAcceptHyperBlock(uint64 blockNum, const T_HYPERBLOCK &remoteHyperBlock, bool isAlreadyExisted);
    bool isMoreWellThanLocal(const T_HYPERBLOCK &localHyperBlock, uint64 blockid, uint64 blockcount, const T_SHA256& hhashself);
    void SplitString(const string& s, vector<std::string>& v, const std::string& c);

private:

    string m_mynodeid;						//
    set<uint64> m_localHID;					//
    bool m_localHIDReady;					//
    vector <string> m_localHIDsection;		//
    mutex m_listlock;

    DBmgr* m_db = nullptr;

    uint64 sync_hid;                        //
    system_clock::time_point sync_time;     //
    
    bool m_LatestBlockReady;				//
    T_HYPERBLOCK m_LatestHyperBlock;        //
    std::atomic<uint64> uiMaxBlockNum;      //
    
    LIST_T_HYPERBLOCK m_HchainBlockList;	//
    CMutexObj m_MuxHchainBlockList;

    map<uint64, T_SHA256> m_BlockHashMap;    //
    CMutexObj m_MuxBlockHashMap;

    map<uint64, T_SHA256> m_HeaderHashMap;    //
    CMutexObj m_MuxHeaderHashMap;

    map<uint64, set<string>> m_ReqBlockNodes;       //
    CMutexObj m_MuxReqBlockNodes;

    map<uint64, set<string>> m_ReqHeaderHashNodes;  //
    CMutexObj m_MuxReqHeaderHashNodes;

    MAP_T_UNCONFIRMEDBLOCK m_UnconfirmedBlockMap;         //
    CMutexObj m_MuxUnconfirmedBlockMap;

    MAP_T_UNCONFIRMEDHEADERHASH m_UnconfirmedHashMap;     //
    CMutexObj m_MuxUnconfirmedHashMap;

    map<uint64, set<string>> m_Chainspace;	//
    mutex m_datalock;

    map<uint64, uint32> m_BlockHealthInfo;	//

    map<string, string> m_chainspaceshow;	//
    mutex m_showlock;

    unique_ptr<thread> m_threadpull;
    unique_ptr<thread> m_threadPullAppBlocks;
    bool _isstop;
};
