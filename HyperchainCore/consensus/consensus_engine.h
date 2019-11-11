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

#include "utility/MutexObj.h"


#include <thread>
#include <memory>
#include <functional>
#include <list>
#include <mutex>
#include <unordered_map>
using namespace std;

enum class ONCHAINSTATUS :char {
    queueing,       //
    onchaining1,    //
    onchaining2,    //
    onchained,      //
    matured,        //
    nonexistent,    //
    failed,         //
    unknown,        //
};

class ConsensusEngine {
public:
    ConsensusEngine() : _isstop(false), _is_able_to_consensus(false) {}
    ~ConsensusEngine() { stopTest(); stop(); }

    void start();
    void stop();

    //
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

    bool isTestRunning() {
        if (_testthread) {
            return true;
        }
        return false;
    }

    uint32 AddNewBlockEx(const T_APPTYPE &app, const string& MTRootHash,
        const string &strdata, string& requestid);
    uint32 AddChainEx(const T_APPTYPE & app, const vector<string>& vecMTRootHash,
        const vector<string>& vecpayload, const vector<CUInt128>& vecNodeId);


    void registerAppCallback(const T_APPTYPE &app, const CONSENSUSNOTIFY &notify);
    void unregisterAppCallback(const T_APPTYPE &app);

    void SlotHyperBlockUpdated(const T_HYPERBLOCK &h);


    ONCHAINSTATUS GetOnChainState(const LB_UUID& requestId, size_t &queuenum);
    bool CheckSearchOnChainedPool(const LB_UUID& requestId, T_LOCALBLOCKADDRESS& addr);
    LIST_T_LOCALCONSENSUS GetPoeRecordList();
    uint16 GetStateOfCurrentConsensus(uint64 &blockNo, uint16 &blockNum, uint16 &chainNum);
    bool isAbleToConsensus() { return _is_able_to_consensus; }

private:
    void exec();

    void localBuddyReqThread();
    void localBuddyRspThread();
    void SearchOnChainStateThread();
    void CheckMyVersionThread();
    void CreateGenesisBlock();
    void SendLocalBuddyReq();
    void ProcessOnChainRspMsg(const CUInt128 &peerid, char* pBuf, unsigned int uiBufLen);
    void StartGlobalBuddy();
    void SendGlobalBuddyReq();
    void AsyncHyperBlockUpdated(const T_HYPERBLOCK &h);

    bool checkConsensusCond();

    void TestOnchain();
    //void SynchronizeHyperData(shared_ptr<T_LOCALCONSENSUS>&& t);

    void prepareLocalBuddy();

private:

    std::list<std::thread> _threads;
    std::unique_ptr<std::thread> _testthread;

    bool _isstop;
    bool _isstoptest = false;
    bool _is_able_to_consensus;
    bool _is_requested_latest_hyperblock = false;

};

