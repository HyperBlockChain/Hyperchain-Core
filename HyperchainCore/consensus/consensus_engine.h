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

#include "utility/MutexObj.h"
#include "node/MsgHandler.h"


#include <thread>
#include <memory>
#include <functional>
#include <list>
#include <mutex>
#include <unordered_map>
using namespace std;

enum class ONCHAINSTATUS :char {
    queueing,       
    onchaining1,    
    onchaining2,    
    onchained,      
    matured,        
    nonexistent,    
    failed,         
    unknown,       
    pending,       
};

class HCMQWrk;
class zmsg;

struct _tp2pmanagerstatus;

class ConsensusEngine {
public:
    ConsensusEngine();
    ~ConsensusEngine();

    void start();
    void stop();

    std::string MQID()
    {
        return _msghandler.details();
    }

    void startTest() {
        if (_testthread) {
            return;
        }
        _isstoptest = false;
        _testthread.reset(new thread(&ConsensusEngine::TestOnchain, this));
    }
    void stopTest() {
        _isstoptest = true;
        if (!_testthread) {
            return;
        }
        if (_testthread->joinable()) {
            _testthread->join();
        }
        _testthread.release();
    }

    bool IsTestRunning() {
        if (_testthread) {
            return true;
        }
        return false;
    }

    uint32 AddNewBlockEx(const T_APPTYPE &app, const string& MTRootHash,
        const string &strdata, string& requestid);
    uint32 AddChainEx(const T_APPTYPE & app, const vector<string>& vecMTRootHash,
        const vector<string>& vecpayload, const vector<CUInt128>& vecNodeId);

    void RegisterAppCallback(const T_APPTYPE &app, const CONSENSUSNOTIFY &notify);
    void UnregisterAppCallback(const T_APPTYPE &app);

    ONCHAINSTATUS GetOnChainState(const LB_UUID& requestId, size_t &queuenum);
    bool CheckSearchOnChainedPool(const LB_UUID& requestId, T_LOCALBLOCKADDRESS& addr);
    uint GetStateOfCurrentConsensus(uint64 &blockNo, uint16 &blockNum, uint16 &chainNum);
    void GetDetailsOfCurrentConsensus(size_t &reqblknum,
        size_t &rspblknum,
        size_t &reqchainnum,
        size_t &rspchainnum,
        size_t &localchainBlocks,
        LIST_T_LOCALCONSENSUS *localbuddychaininfos,
        size_t &globalbuddychainnum);

    void InitOnChainingState(uint64_t blockid);
    void RehandleOnChainingState(uint64_t blockid);
    bool IsAbleToConsensus() { return _is_able_to_consensus; }
    bool IsEndNode();
    bool IsConfirming(string &currBuddyHash);
    bool MakeBuddy(const string & confirmhash);
    void PutIntoConsensusList(T_BUDDYINFOSTATE &buddyinfostate);
    bool MergeToGlobalBuddyChains(LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo);
    bool CheckPayload(LIST_T_LOCALCONSENSUS& localList);

    struct _tp2pmanagerstatus* GetConsunsusState()
    {
        return _tP2pManagerStatus;
    }


 private:

    void LocalBuddyReq();
    void LocalBuddyRsp();
    void SearchOnChainState();
    void CheckMyVersionThread();
    void CreateGenesisBlock();
    void SendLocalBuddyReq();
    void ProcessOnChainRspMsg(const CUInt128 &peerid, char* pBuf, size_t uiBufLen);
    void StartGlobalBuddy();
    void SendGlobalBuddyReq();

    void HyperBlockUpdated(void *sock, zmsg *msg);
    void AsyncHyperBlockUpdated(const T_HYPERBLOCK &h);

    bool CheckConsensusCond();

    void TestOnchain();

    void PrepareLocalBuddy();
    void UpdateMyBuddyBlock(const T_HYPERBLOCK &h);
    void ReOnChainFun();

    void GetOnChainInfo();
    bool CreateHyperBlock(T_HYPERBLOCK &tHyperBlock);

    void StartMQHandler();

    void DispatchService(void *wrk, zmsg *msg);
    void DispatchConsensus();

    void EmitConsensusSignal(int nDelaySecond);


private:

    enum class SERVICE : short
    {
        GetOnChainState = 1,
        AddNewBlockEx,
        AddChainEx,      
        HyperBlockUpdated,
        GetStateOfCurrentConsensus,
        GetDetailsOfCurrentConsensus,
        CheckSearchOnChainedPool,
        InitOnChainingState,
        RehandleOnChainingState,
        RegisterAppCallback,
        UnregisterAppCallback,
    };

    std::list<std::thread> _threads;
    std::unique_ptr<std::thread> _testthread;

    bool _isstop;
    bool _isstoptest = false;
    bool _is_able_to_consensus;
    bool _is_requested_latest_hyperblock = false;

    struct _tp2pmanagerstatus* _tP2pManagerStatus = nullptr;

    zmq::socket_t *_hyperblock_updated = nullptr;
    MsgHandler _msghandler;
};

