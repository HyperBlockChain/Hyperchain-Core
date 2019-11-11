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

#include "headers/inter_public.h"
#include "headers/commonstruct.h"
#include "utility/MutexObj.h"
#include "p2pprotocol.h"
#include "node/ITask.hpp"
#include <boost/signals2.hpp>

#include <thread>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <unordered_map>
using namespace std;

enum _enodestate
{
    IDLE = 0,
    LOCAL_BUDDY,
    GLOBAL_BUDDY
};

typedef struct _tBuddyInfo
{
    uint64 uiCurBuddyNo;
    uint16 usBlockNum;
    uint16 usChainNum;
    uint8 eBuddyState;

    uint64 GetCurBuddyNo()const;
    uint16 GetBlockNum()const;
    uint16 GetChainNum()const;
    uint8 GetBuddyState()const;

    void SetBlockNum(uint16 num);

}T_STRUCTBUDDYINFO, * T_PSTRUCTBUDDYINFO;

typedef struct _tOnChainHashInfo
{
    uint64 uiTime;
    string strHash;

    uint64 GetTime()const;
    string GetHash()const;

    void Set(uint64 t, string h);

}T_ONCHAINHASHINFO, * T_PONCHAINHASHINFO;

enum class CONSENSUS_PHASE :char {
    LOCALBUDDY_PHASE = 0,
    GLOBALBUDDY_PHASE,
    PERSISTENCE_CHAINDATA_PHASE,
    PREPARE_LOCALBUDDY_PHASE
};

class CycleQueue
{
public:
    CycleQueue()
    {
        head = queue.begin();
        tail = queue.begin();
    }

    bool push(TASKTYPE data)
    {
        *head = data;

        head++;

        if (head == queue.end())
        {
            head = queue.begin();
        }

        if (head == tail)
        {
            tail++;
            if (tail == queue.end())
                tail = queue.begin();
        }

        return true;
    }

    bool pop(TASKTYPE* data)
    {
        if (head == tail)
        {
            return false;
        }

        *data = *tail;

        tail++;
        if (tail == queue.end())
            tail = queue.begin();

        return true;
    }

private:
    array<TASKTYPE, 100> queue;
    array<TASKTYPE, 100>::iterator head;
    array<TASKTYPE, 100>::iterator tail;
};

typedef struct _tp2pmanagerstatus
{
    bool bStartGlobalFlag;

    std::atomic<bool> bHaveOnChainReq;
    std::atomic<uint64> uiConsensusBlockNum;
    uint16 usBuddyPeerCount;
    uint16 uiNodeState;
    uint64 uiSendRegisReqNum;
    uint64 uiRecvRegisReqNum;
    uint64 uiSendConfirmingRegisReqNum;
    uint64 uiRecvConfirmingRegisReqNum;
    T_LOCALBLOCK tPreLocalBlock;
    T_PEERADDRESS tLocalBuddyAddr;

    CMutexObj		MuxCycleQueueTask;
    CycleQueue		CycleQueueTask;

    CMutexObj		 MuxlistOnChainReq;
    LIST_T_LOCALCONSENSUS listOnChainReq;

    CMutexObj		 MuxlistLocalBuddyChainInfo;
    LIST_T_LOCALCONSENSUS listLocalBuddyChainInfo;

    CMutexObj		 MuxlistGlobalBuddyChainInfo;
    LIST_LIST_GLOBALBUDDYINFO listGlobalBuddyChainInfo;

    CMutexObj		 MuxlistRecvLocalBuddyRsp;
    LIST_T_BUDDYINFO  listRecvLocalBuddyRsp;

    CMutexObj		 MuxlistCurBuddyRsp;
    LIST_T_BUDDYINFOSTATE listCurBuddyRsp;

    CMutexObj		 MuxlistRecvLocalBuddyReq;
    LIST_T_BUDDYINFO  listRecvLocalBuddyReq;

    CMutexObj		 MuxlistCurBuddyReq;
    LIST_T_BUDDYINFOSTATE listCurBuddyReq;

    CMutexObj			MuxMapSearchOnChain;
    MAP_T_SEARCHONCHAIN mapSearchOnChain;

    uint64 uiSendPoeNum;
    uint64 uiRecivePoeNum;

    T_STRUCTBUDDYINFO tBuddyInfo;

    CMutexObj		 MuxMulticastNodes;
    vector<CUInt128> MulticastNodes;

    void clearStatus();

    _tp2pmanagerstatus()
    {
        clearStatus();
    }

    bool StartGlobalFlag()const;

    bool HaveOnChainReq()const;

    //
    T_SHA256 GetConsensusPreHyperBlockHash()const;

    uint16 GetBuddyPeerCount()const;

    uint16 GetNodeState()const;

    uint64 GetSendRegisReqNum()const;

    uint64 GetRecvRegisReqNum()const;

    uint64 GetSendConfirmingRegisReqNum()const;

    uint64 GetRecvConfirmingRegisReqNum()const;

    uint64 GettTimeOfConsensus();
    CONSENSUS_PHASE GetCurrentConsensusPhase() const;

    T_PEERADDRESS GetLocalBuddyAddr()const;

    uint64 GetSendPoeNum()const;

    void SetSendPoeNum(uint64 num);

    LIST_T_LOCALCONSENSUS& GetListOnChainReq();

    void SetStartGlobalFlag(bool flag);

    void SetHaveOnChainReq(bool haveOnChainReq);

    void SetNodeState(uint16 state);

    void SetSendRegisReqNum(uint64 num);

    void SetRecvRegisReqNum(uint64 num);

    void SetSendConfirmingRegisReqNum(uint64 num);

    void SetRecvConfirmingRegisReqNum(uint64 num);

    void SetGlobalBuddyAddr(T_PEERADDRESS addr);

    uint64 GetRecvPoeNum()const;

    void SetRecvPoeNum(uint64 num);

    T_STRUCTBUDDYINFO GetBuddyInfo()const;

    void SetBuddyInfo(T_STRUCTBUDDYINFO info);

    void SetMaxBlockNum(uint64 num);
    void SetPreHyperBlock(T_HYPERBLOCK&& h);

    void SetMulticastNodes();
    void ClearMulticastNodes();
    vector<CUInt128> GetMulticastNodes();

    void updateOnChainingState(const T_HYPERBLOCK& hyperblock);

    bool ApplicationCheck(T_HYPERBLOCK& hyperblock);
    bool ApplicationAccept(T_HYPERBLOCK& hyperblock);

    void updateLocalBuddyBlockToLatest();

    void cleanConsensusEnv();

    //
    void trackLocalBlock(const T_LOCALBLOCK& localblock);
    void initOnChainingState(uint64 hid);

    void setAppCallback(const T_APPTYPE& app, const CONSENSUSNOTIFY& notify);
    void removeAppCallback(const T_APPTYPE& app);

    template<cbindex I, typename... Args>
    bool allAppCallback(Args&... args)
    {
        std::lock_guard<std::recursive_mutex> lck(_muxmapcbfn);
        for (auto appnoti : _mapcbfn) {
            auto fn = std::get<static_cast<size_t>(I)>(appnoti.second);
            if (fn) {
                fn(args...);
            }
        }
        return true;
    }

    template<cbindex I, typename... Args>
    CBRET appCallback(const T_APPTYPE& app, Args&... args)
    {
        //
        //
        std::lock_guard<std::recursive_mutex> lck(_muxmapcbfn);
        if (_mapcbfn.count(app)) {
            auto& noti = _mapcbfn.at(app);
            auto fn = std::get<static_cast<size_t>(I)>(noti);
            if (fn) {
                return fn(args...) ? (CBRET::REGISTERED_TRUE) : (CBRET::REGISTERED_FALSE);
            }
        }
        return CBRET::UNREGISTERED;
    }

    using FnHyperBlockUpdated = boost::function<void(const T_HYPERBLOCK&)>;
    void RegisterHyperBlockSignal(FnHyperBlockUpdated f) {
        SignalHyperBlockUpdated.connect(f);
    }
    void RemoveHyperBlockSignal(FnHyperBlockUpdated f) {
        SignalHyperBlockUpdated.disconnect(&f);
    }

    boost::signals2::signal<void(const T_HYPERBLOCK & h)> SignalHyperBlockUpdated;
private:

    void ToAppPayloads(const T_HYPERBLOCK& hyperblock, map<T_APPTYPE, vector<T_PAYLOADADDR>>& mapPayload);

private:

    std::recursive_mutex _muxmapcbfn;
    unordered_map<T_APPTYPE, CONSENSUSNOTIFY> _mapcbfn;

}T_P2PMANAGERSTATUS, * T_PP2PMANAGERSTATUS;


//////////////////////////////////////////////////////////////////////////
extern T_P2PMANAGERSTATUS* g_tP2pManagerStatus;