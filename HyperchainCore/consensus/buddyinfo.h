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

#ifdef WIN32
#include <winsock2.h>
#endif

#include "headers/inter_public.h"
#include "headers/commonstruct.h"
#include "utility/MutexObj.h"
#include "p2pprotocol.h"

#include <thread>
#include <memory>
#include <functional>
#include <atomic>
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

}T_STRUCTBUDDYINFO, *T_PSTRUCTBUDDYINFO;

typedef struct _tOnChainHashInfo
{
    uint64 uiTime;
    string strHash;

    uint64 GetTime()const;
    string GetHash()const;

    void Set(uint64 t, string h);

}T_ONCHAINHASHINFO, *T_PONCHAINHASHINFO;

enum class CONSENSUS_PHASE :char {
    LOCALBUDDY_PHASE = 0,
    GLOBALBUDDY_PHASE,
    PERSISTENCE_CHAINDATA_PHASE,
    PREPARE_LOCALBUDDY_PHASE
};

typedef struct _tp2pmanagerstatus
{
    bool bStartGlobalFlag;

    std::atomic<bool> bHaveOnChainReq;
    std::atomic<uint64> uiMaxBlockNum;
    std::atomic<uint64> uiConsensusBlockNum;
    uint16 usBuddyPeerCount;
    uint16 uiNodeState;
    uint64 uiSendRegisReqNum;
    uint64 uiRecvRegisReqNum;
    uint64 uiSendConfirmingRegisReqNum;
    uint64 uiRecvConfirmingRegisReqNum;
    T_HYPERBLOCK tPreHyperBlock;
    T_LOCALBLOCK tPreLocalBlock;
    T_PEERADDRESS tLocalBuddyAddr;
    T_LOCALCONSENSUS curBuddyBlock;

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


    LIST_T_HYPERBLOCK   m_HchainBlockList;
    CMutexObj   m_MuxHchainBlockList;

    void clearStatus();

    _tp2pmanagerstatus()
    {
        clearStatus();
    }

    bool StartGlobalFlag()const;

    bool HaveOnChainReq()const;

    //HC: 返回当前共识子块头里存放的前一个超块Hash,这不完全等同于本节点最新超块的hash
    T_SHA256 GetConsensusPreHyperBlockHash()const;

    uint16 GetBuddyPeerCount()const;

    uint16 GetNodeState()const;

    uint64 GetSendRegisReqNum()const;

    uint64 GetRecvRegisReqNum()const;

    uint64 GetSendConfirmingRegisReqNum()const;

    uint64 GetRecvConfirmingRegisReqNum()const;

    uint64 GettTimeOfConsensus();
    CONSENSUS_PHASE GetCurrentConsensusPhase() const;

    bool LocalBuddyChainState()const;

    T_PEERADDRESS GetLocalBuddyAddr()const;

    //HC: notice to add mutex protect(m_MuxHchainBlockList) calling this function
    T_HYPERBLOCK& GetPreHyperBlock();

    uint64 GetMaxBlockID() const {
        return uiMaxBlockNum;
    }

    T_SHA256 GetPreHyperBlockHash() {
        CAutoMutexLock muxAuto(m_MuxHchainBlockList);
        return tPreHyperBlock.GetHashSelf();
    }

    void GetPreHyperBlockIDAndHash(uint64 &id, T_SHA256 &hash) {
        CAutoMutexLock muxAuto(m_MuxHchainBlockList);
        hash = tPreHyperBlock.GetHashSelf();
        id = tPreHyperBlock.GetID();
    }

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

    void SetNextStartTimeNewest(uint64 t);

    void SetGlobalBuddyAddr(T_PEERADDRESS addr);

    uint64 GetRecvPoeNum()const;

    void SetRecvPoeNum(uint64 num);

    T_STRUCTBUDDYINFO GetBuddyInfo()const;

    void SetBuddyInfo(T_STRUCTBUDDYINFO info);

    //HC: hyper block cache function
    void loadHyperBlockCache();
    bool updateHyperBlockCache(T_HYPERBLOCK &hyperBlock);
    bool getHyperBlock(uint64 blockNum, T_HYPERBLOCK &hyperBlock);
    bool getHyperBlock(const T_SHA256 &hhash, T_HYPERBLOCK &hyperblock);

    void updateLocalBuddyBlockToLatest();

    void cleanConsensusEnv();

    //HC:跟踪本地块上链状态
    void trackLocalBlock(const T_LOCALBLOCK & localblock);
    void initOnChainingState(uint64 hid);

private:
    void SetMaxBlockNum(uint64 num);
    void SetPreHyperBlock(T_HYPERBLOCK&& h);
    void SaveToLocalStorage(const T_HYPERBLOCK &tHyperBlock);

    bool loadHyperBlock(uint64 blockNum, T_HYPERBLOCK &hyperBlock);
    bool loadHyperBlock(const T_SHA256 &hhash, T_HYPERBLOCK &hyperBlock);
    bool isAcceptHyperBlock(uint64 blockNum, uint64 blockCount, T_SHA256 tHashSelf, bool isAlreadyExisted);
    bool isMoreWellThanLocal(const T_HYPERBLOCK &localHyperBlock, uint64 blockid, uint64 blockcount, const T_SHA256& hhashself);

private:

}T_P2PMANAGERSTATUS, *T_PP2PMANAGERSTATUS;


//////////////////////////////////////////////////////////////////////////
extern T_P2PMANAGERSTATUS g_tP2pManagerStatus;