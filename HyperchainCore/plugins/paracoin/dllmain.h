/*Copyright 2016-2020 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "block.h"
#include "bignum.h"
#include "net.h"
#include "key.h"
#include "script.h"
#include "db.h"

#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"
#include "headers/inter_public.h"

#include "bloomfilter.h"

#include "cryptocurrency.h"

#include <list>
#include <algorithm>

class CBlock;
class CBlockIndex;
class CWalletTx;
class CWallet;
class CKeyItem;
class CReserveKey;
class CWalletDB;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;
class CBlockIndexSimplified;
class CBlockBloomFilter;
class CBlockDiskLocator;

template<class T>
class shared_ptr_proxy;

using CBlockIndexSP = shared_ptr_proxy<CBlockIndex>;

template<class T, class Storage>
class CCacheLocator;


#ifdef USE_UPNP
static const int fHaveUPnP = true;
#else
static const int fHaveUPnP = false;
#endif

extern CCriticalSection cs_main;
extern CCacheLocator<CBlockIndex, CTxDB_Wrapper> mapBlockIndex;
extern map<uint256, CBlock*> mapOrphanBlocks;
extern uint256 hashGenesisBlock;
extern CBlockIndexSP pindexGenesisBlock;
extern int nBestHeight;
extern CBigNum bnBestChainWork;
extern CBigNum bnBestInvalidWork;
extern uint256 hashBestChain;
extern CBlockIndexSP pindexBest;

extern unsigned int nTransactionsUpdated;
extern double dHashesPerSec;
extern int64 nHPSTimerStart;
extern int64 nTimeBestReceived;
extern CCriticalSection cs_setpwalletRegistered;
extern std::set<CWallet*> setpwalletRegistered;

extern T_LOCALBLOCKADDRESS addrMaxChain;

// Settings
extern int fGenerateBitcoins;
extern int64 nTransactionFee;
extern int fLimitProcessors;
extern int nLimitProcessors;
extern int fMinimizeToTray;
extern int fMinimizeOnClose;
extern int fUseUPnP;

extern CAddress g_seedserver;
extern std::atomic<uint32_t> g_nHeightCheckPoint;
extern std::atomic<uint256> g_hashCheckPoint;

class CBlockCacheLocator;
extern CBlockCacheLocator mapBlocks;



class CReserveKey;
class CTxDB;
class CTxIndex;

void RegisterWallet(CWallet* pwalletIn);
void UnregisterWallet(CWallet* pwalletIn);
bool CheckDiskSpace(uint64 nAdditionalBytes=0);
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool LoadBlockIndex(bool fAllowNew=true);
bool LoadBlockUnChained();
void PrintBlockTree();
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);
void GenerateBitcoins(bool fGenerate, CWallet* pwallet);
CBlock* CreateNewBlock(CReserveKey& reservekey);

bool CommitGenesisToConsensus(CBlock *pblock, std::string &requestid, std::string &errmsg);
bool CommitChainToConsensus(deque<CBlock>& deqblock, string &requestid, string &errmsg);

void IncrementExtraNonce(CBlock* pblock, unsigned int& nExtraNonce);
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);
bool CheckProofOfWork(uint256 hash, unsigned int nBits);
int GetTotalBlocksEstimate();
bool IsInitialBlockDownload();
std::string GetWarnings(std::string strFor);

bool ProcessBlock(CNode* pfrom, CBlock* pblock);
bool ProcessBlock(CNode* pfrom, CBlock* pblock, T_LOCALBLOCKADDRESS* pblockaddr);
bool ProcessBlockFromAcceptedHyperBlock(CBlock* pblock, T_LOCALBLOCKADDRESS* pblockaddr);

bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);
bool GetBlockData(const uint256& hashBlock, CBlock& block, T_LOCALBLOCKADDRESS& addrblock);

CBlockIndexSP LatestBlockIndexOnChained();

extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);

template<typename T>
bool WriteSetting(const std::string& strKey, const T& value)
{
    bool fOk = false;
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    {
        std::string strWalletFile;
        if (!GetWalletFile(pwallet, strWalletFile))
            continue;
        fOk |= CWalletDB(strWalletFile).WriteSetting(strKey, value);
    }
    return fOk;
}




/**
 * Custom serializer for CBlockHeader that omits the nonce and solution, for use
 * as input to Equihash.
 */

class CEquihashInput : private CBlock
{
public:
    CEquihashInput(const CBlock &header)
    {
        CBlock::SetNull();
        *((CBlock*)this) = header;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nHeight);
        for (size_t i = 0; i < (sizeof(nReserved) / sizeof(nReserved[0])); i++) {
            READWRITE(nReserved[i]);
        }

        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nPrevHID);
        READWRITE(hashPrevHyperBlock);
        READWRITE(hashExternData);
    )

};

class CBlockIndexSimplified
{
public:
    const uint256* phashBlock = nullptr;

    CBlockIndexSimplified* pprev = nullptr;
    CBlockIndexSimplified* pnext = nullptr;
    int nHeight = -1;

    T_LOCALBLOCKADDRESS addr;

public:
    void Set(const T_LOCALBLOCKADDRESS& addrIn, const CBlock& block)
    {
        addr = addrIn;
        nHeight = block.nHeight;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndexSimplified: \n"
            "\tHeight=%d"
            "\tAddr=%s\n"
            "\thashBlock=%s ******\n"
            "\thashPrevBlock=%s\n"
            "\thashNextBlock=%s\n",
            nHeight,
            addr.tostring().c_str(),
            phashBlock ? (phashBlock->ToString().c_str()) : "null",
            pprev ? (pprev->GetBlockHash().ToString().c_str()) : "null",
            pnext ? (pnext->GetBlockHash().ToString().c_str()) : "null");
    }

   };


//
// Used to marshal pointers into hashes for db storage.
//
class CDiskBlockIndex : public CBlockIndex
{
public:

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);

		READWRITE(nHeight);
		READWRITE(bnChainWork);


        uint32_t* hid = (uint32_t*)(&addr.hid);
        READWRITE(*hid);

        READWRITE(addr.chainnum);
        READWRITE(addr.id);
        READWRITE(addr.ns);

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);

        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nSolution);
        READWRITE(nPrevHID);
        READWRITE(hashPrevHyperBlock);
        READWRITE(hashExternData);

        READWRITE(ownerNodeID.Lower64());
        READWRITE(ownerNodeID.High64());

    )

    uint256 GetBlockHash() const
    {
        CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nHeight         = nHeight;

        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        block.nPrevHID        = nPrevHID;
        block.nSolution       = nSolution;
        block.hashPrevHyperBlock = hashPrevHyperBlock;
        block.nNonce          = nNonce;
        block.hashExternData = hashExternData;

        return block.GetHash();
    }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().substr(0,20).c_str(),
            hashNext.ToString().substr(0,20).c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};


//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
//
class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(CBlockIndexSP pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock);

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }

    void Set(CBlockIndexSP pindex)
    {
        vHave.clear();
        int nStep = 1;
        while (pindex)
        {
            vHave.push_back(pindex->GetBlockHash());

            // Exponentially larger steps back
            for (int i = 0; pindex && i < nStep; i++)
                pindex = pindex->pprev();
            if (vHave.size() > 10)
                nStep *= 2;
        }
        vHave.push_back(hashGenesisBlock);
    }

    int GetDistanceBack();

    CBlockIndexSP GetBlockIndex();

    uint256 GetBlockHash();

    int GetHeight()
    {
        CBlockIndexSP pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};

//
// Alerts are for notifying old versions if they become too obsolete and
// need to upgrade.  The message is displayed in the status bar.
// Alert messages are broadcast as a vector of signed data.  Unserializing may
// not read the entire buffer if the alert is for a newer version, but older
// versions can still relay the original data.
//
class CUnsignedAlert
{
public:
    int nVersion;
    int64 nRelayUntil;      // when newer nodes stop relaying to newer nodes
    int64 nExpiration;
    int nID;
    int nCancel;
    std::set<int> setCancel;
    int nMinVer;            // lowest version inclusive
    int nMaxVer;            // highest version inclusive
    std::set<std::string> setSubVer;  // empty matches all
    int nPriority;

    // Actions
    std::string strComment;
    std::string strStatusBar;
    std::string strReserved;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nRelayUntil);
        READWRITE(nExpiration);
        READWRITE(nID);
        READWRITE(nCancel);
        READWRITE(setCancel);
        READWRITE(nMinVer);
        READWRITE(nMaxVer);
        READWRITE(setSubVer);
        READWRITE(nPriority);

        READWRITE(strComment);
        READWRITE(strStatusBar);
        READWRITE(strReserved);
    )

    void SetNull()
    {
        nVersion = 1;
        nRelayUntil = 0;
        nExpiration = 0;
        nID = 0;
        nCancel = 0;
        setCancel.clear();
        nMinVer = 0;
        nMaxVer = 0;
        setSubVer.clear();
        nPriority = 0;

        strComment.clear();
        strStatusBar.clear();
        strReserved.clear();
    }

    std::string ToString() const
    {
        std::string strSetCancel;
        BOOST_FOREACH(int n, setCancel)
            strSetCancel += strprintf("%d ", n);
        std::string strSetSubVer;
        BOOST_FOREACH(std::string str, setSubVer)
            strSetSubVer += "\"" + str + "\" ";
        return strprintf(
                "CAlert(\n"
                "    nVersion     = %d\n"

                "    nRelayUntil  = %" PRI64d "\n"
                "    nExpiration  = %" PRI64d "\n"
                "    nID          = %d\n"
                "    nCancel      = %d\n"
                "    setCancel    = %s\n"
                "    nMinVer      = %d\n"
                "    nMaxVer      = %d\n"
                "    setSubVer    = %s\n"
                "    nPriority    = %d\n"
                "    strComment   = \"%s\"\n"
                "    strStatusBar = \"%s\"\n"
                ")\n",
            nVersion,
            nRelayUntil,
            nExpiration,
            nID,
            nCancel,
            strSetCancel.c_str(),
            nMinVer,
            nMaxVer,
            strSetSubVer.c_str(),
            nPriority,
            strComment.c_str(),
            strStatusBar.c_str());
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};

class CAlert : public CUnsignedAlert
{
public:
    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CAlert()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchMsg);
        READWRITE(vchSig);
    )

    void SetNull()
    {
        CUnsignedAlert::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const
    {
        return (nExpiration == 0);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool IsInEffect() const
    {
        return (GetAdjustedTime() < nExpiration);
    }

    bool Cancels(const CAlert& alert) const
    {
        if (!IsInEffect())
            return false; // this was a no-op before 31403
        return (alert.nID <= nCancel || setCancel.count(alert.nID));
    }

    bool AppliesTo(int nVersion, std::string strSubVerIn) const
    {
        return (IsInEffect() &&
                nMinVer <= nVersion && nVersion <= nMaxVer &&
                (setSubVer.empty() || setSubVer.count(strSubVerIn)));
    }

    bool AppliesToMe() const
    {
        return AppliesTo(VERSION, ::pszSubVer);
    }

    bool RelayTo(CNode* pnode) const
    {
        if (!IsInEffect())
            return false;
        // returns true if wasn't already contained in the set
        if (pnode->setKnown.insert(GetHash()).second)
        {
            if (AppliesTo(pnode->nVersion, pnode->strSubVer) ||
                AppliesToMe() ||
                GetAdjustedTime() < nRelayUntil)
            {
                pnode->PushMessage("alert", *this);
                return true;
            }
        }
        return false;
    }

    bool CheckSignature()
    {
        CKey key;
        if (!key.SetPubKey(ParseHex("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284")))
            return ERROR_FL("CAlert::CheckSignature() : SetPubKey failed");
        if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
            return ERROR_FL("CAlert::CheckSignature() : verify signature failed");

        // Now unserialize the data
        CDataStream sMsg(vchMsg);
        sMsg >> *(CUnsignedAlert*)this;
        return true;
    }

    bool ProcessAlert();
};

class BlockCheckPoint
{
public:
    BlockCheckPoint() = default;
    BlockCheckPoint(const BlockCheckPoint&) = delete;
    BlockCheckPoint& operator =(const BlockCheckPoint&) = delete;

    void Get(uint32_t& nHeight, uint256& hashblock)
    {
        std::lock_guard<std::mutex> guard(_mutex);
        nHeight = _nHeightCheckPoint;
        hashblock = _hashCheckPoint;
    }

    void Set(uint32_t nHeight, const uint256& hashblock)
    {
        std::lock_guard<std::mutex> guard(_mutex);
        _nHeightCheckPoint = nHeight;
        _hashCheckPoint = hashblock;
    }

private:
    std::mutex _mutex;
    uint32_t _nHeightCheckPoint = 0;
    uint256 _hashCheckPoint = 0;
};


class LatestHyperBlock {

public:
    static void Sync()
    {
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        uint64 hid;
        T_SHA256 thhash;
        hyperchainspace->GetLatestHyperBlockIDAndHash(hid, thhash);
        CRITICAL_BLOCK(_cs_latestHyperBlock)
        {
            _hid = hid;
            _hhash = uint256S(thhash.toHexString());
        }
    }

    static void CompareAndUpdate(uint32_t hid, const T_SHA256& thhash, bool isLatest)
    {
        CRITICAL_BLOCK(_cs_latestHyperBlock)
        {
            if (isLatest || _hid < hid) {
                _hid = hid;
                _hhash = uint256S(thhash.toHexString());
            }
        }
    }

    static uint32_t GetHID(uint256* hhash = nullptr)
    {
        CRITICAL_BLOCK(_cs_latestHyperBlock)
        {
            if (hhash) {
                *hhash = _hhash;
            }
            return _hid;
        }
    }
private:
    static uint32_t _hid;
    static uint256 _hhash;
    static CCriticalSection _cs_latestHyperBlock;
};


class BLOCKTRIPLEADDRESS
{
public:
    uint32 hid = 0;

    uint16 chainnum = 0;
    uint16 id = 0;

public:
    BLOCKTRIPLEADDRESS() {}

    BLOCKTRIPLEADDRESS(const T_LOCALBLOCKADDRESS& addr)
    {
        hid = addr.hid;
        chainnum = addr.chainnum;
        id = addr.id;
    }
    BLOCKTRIPLEADDRESS(const BLOCKTRIPLEADDRESS& addr)
    {
        hid = addr.hid;
        chainnum = addr.chainnum;
        id = addr.id;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(hid);
        READWRITE(chainnum);
        READWRITE(id);
    )

    T_LOCALBLOCKADDRESS ToAddr() const
    {
        T_LOCALBLOCKADDRESS addr;
        addr.hid = hid;
        addr.chainnum = chainnum;
        addr.id = id;
        return addr;
    }

    string ToString() const
    {
        return strprintf("[%d,%d,%d]", hid,chainnum,id);
    }
};

typedef struct BackTrackingProgress
{
    int nLatestBlockHeight = 0;
    std::string strLatestBlockTripleAddr;
    int nBackTrackingBlockHeight = 0;
    std::string strBackTrackingBlockHash;

} BackTrackingProgress;

class LatestParaBlock {

public:
    static void Load();
    static void CompareAndUpdate(const vector<BLOCKTRIPLEADDRESS>& vecAddrIn, const vector<CBlock>& vecBlockIn, bool isLatest);

    static CBlockIndexSimplified* Get()
    {
        return _pindexLatest;
    }

    static int GetHeight()
    {
        return _nLatestParaHeight;
    }

    static uint256 GetRootHash()
    {
        if (_pindexLatestRoot && _pindexLatestRoot->pnext) {
            return *_pindexLatestRoot->pnext->phashBlock;
        }
        return 0;
    }

    static uint256 GetBackSearchHash()
    {
        if (_pindexLatestRoot) {
            return *_pindexLatestRoot->phashBlock;
        }
        return 0;
    }

    static uint32 GetBackSearchHeight()
    {
        if (_pindexLatestRoot && _pindexLatestRoot->pnext &&  _pindexLatestRoot->pnext->nHeight >= 1) {
            return _pindexLatestRoot->pnext->nHeight - 1;
        }
        return 0;
    }

    static string GetMemoryInfo();



    static void Switch();
    static bool IsOnChain();
    static bool IsLackingBlock(std::function<void(const BackTrackingProgress &)> notiprogress);

    static bool Count(const uint256& hastblock);

    static void AddBlockTripleAddress(const uint256& hastblock, const BLOCKTRIPLEADDRESS& tripleaddr);

    static bool GetBlock(const uint256& hastblock, CBlock& block, BLOCKTRIPLEADDRESS& tripleaddr);

private:

    static bool LoadLatestBlock();
    static void SetBestIndex(CBlockIndexSimplified* pIndex)
    {
        _pindexLatest = pIndex;
        _nLatestParaHeight =  _pindexLatest->nHeight;
    }

    static CBlockIndexSimplified* AddBlockIndex(const T_LOCALBLOCKADDRESS& addrIn, const CBlock& block);
    static CBlockIndexSimplified* InsertBlockIndex(uint256 hash);

    static void PullingPrevBlocks();

private:


    static CBlockIndexSimplified* _pindexLatest;
    static int  _nLatestParaHeight;


    static map<uint256, CBlockIndexSimplified*> _mapBlockIndexLatest;
    static CBlockDiskLocator _mapBlockAddressOnDisk;

    static CBlockIndexSimplified* _pindexLatestRoot;
};


extern BlockCheckPoint g_blockChckPnt;

class MiningCondition
{
public:
    MiningCondition() = default;
    MiningCondition(const MiningCondition&) = delete;
    MiningCondition& operator =(const MiningCondition&) = delete;

    void ProgressChanged(const BackTrackingProgress &progress) {
        _backTrackingProgress = progress;
        _eStatusCode = miningstatuscode::ChainIncomplete;
    }

    bool EvaluateIsAllowed(bool NeighborIsMust = true) {

        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

        CRITICAL_BLOCK_T_MAIN(cs_main)
            CRITICAL_BLOCK(_cs_miningstatus)
            {
                if (!hyperchainspace->IsLatestHyperBlockReady()) {
                    _eStatusCode = miningstatuscode::HyperBlockNotReady;
                    return false;
                }
                else if (NeighborIsMust && vNodes.empty()) {
                    _eStatusCode = miningstatuscode::NoAnyNeighbor;
                    return false;
                }
                //else if (IsInitialBlockDownload()) {
                //    _reason += "Initial Block is downloading";
                //    return false;
                //}
                else if (!g_cryptoCurrency.CheckGenesisBlock()) {
                    _eStatusCode = miningstatuscode::InvalidGenesisBlock;
                    return false;
                }
                else if (!g_cryptoCurrency.AllowMining()) {
                    _eStatusCode = miningstatuscode::MiningSettingClosed;
                    return false;
                }

                if (!LatestParaBlock::IsOnChain()) {
                    auto f = std::bind(&MiningCondition::ProgressChanged, this, std::placeholders::_1);
                    if (!LatestParaBlock::IsLackingBlock(f)) {


                        _eStatusCode = miningstatuscode::Switching;
                        LatestParaBlock::Switch();
                    }
                    return false;
                }

                string reason;
                if (IsTooFar(reason)) {
                    return false;
                }
                _eStatusCode = miningstatuscode::Mining;
            }

        return true;
    }

    bool IsMining()
    {
        return  _eStatusCode > miningstatuscode::Switching;
    }

    string GetMiningStatus(bool* isAllowed) {

        if(isAllowed)
            *isAllowed = IsMining();

        return StatusCodeToReason();
    }

    int MiningStatusCode() const { return (int)(_eStatusCode); }
    bool IsBackTracking() const { return (_eStatusCode == miningstatuscode::ChainIncomplete); }
    bool IsSwitching() const { return (_eStatusCode == miningstatuscode::Switching); }

    BackTrackingProgress GetBackTrackingProcess() const { return _backTrackingProgress; }

private:
    bool IsTooFar(std::string& reason)
    {
        uint32_t ncount = 0;

        char szReason[1024] = { 0 };

        CRITICAL_BLOCK_T_MAIN(cs_main)
        {
            CBlockIndexSimplified* pIndex = LatestParaBlock::Get();
            uint256 hash = pIndex->GetBlockHash();

            CBlockIndexSP p = pindexBest;
            while (p && !p->addr.isValid() && p->GetBlockHash() != hash) {
                ncount++;
                p = p->pprev();
            }

            if (ncount > 40) {
                _eStatusCode = miningstatuscode::ManyBlocksNonChained;
                return true;
            }

            if (g_seedserver.IsValid()) {

                CBlockIndexSP p = pindexBest;
                uint32_t height;
                uint256 hash;
                g_blockChckPnt.Get(height, hash);
                if (height == 0) {


                    _eStatusCode = miningstatuscode::MiningWithWarning1;
                    return false;
                }


                if (height > 0) {
                    if (p->nHeight < height) {


                        _eStatusCode = miningstatuscode::MiningWithWarning2;
                        return false;
                    }

                    while (p && p->nHeight > height) {
                        p = p->pprev();
                    }

                    if (p->GetBlockHash() != hash) {


                        _eStatusCode = miningstatuscode::MiningWithWarning3;
                        return false;
                    }
                }
            }
        }
        return false;
    }

    string StatusCodeToReason()
    {
        string rs;

        if (_eStatusCode == miningstatuscode::ChainIncomplete) {
            return strprintf("The chain is incomplete, latest block height: %u(%s), backtracking block: %u(hash: %s)",
                _backTrackingProgress.nLatestBlockHeight, _backTrackingProgress.strLatestBlockTripleAddr.c_str(),
                _backTrackingProgress.nBackTrackingBlockHeight, _backTrackingProgress.strBackTrackingBlockHash.c_str());
        }

        if (_mapStatusDescription.count(_eStatusCode)) {
            return _mapStatusDescription.at(_eStatusCode);
        }

        return "";
    }

private:
    CCriticalSection _cs_miningstatus;

    enum class miningstatuscode : char {
        Mining = 1,
        MiningWithWarning1 = 2,
        MiningWithWarning2 = 3,
        MiningWithWarning3 = 4,

        Switching = 0,

        GenDisabled = -1,
        HyperBlockNotReady = -2,
        NoAnyNeighbor = -3,
        InvalidGenesisBlock = -4,
        MiningSettingClosed= -5,
        ManyBlocksNonChained= -6,
        ChainIncomplete = -7,
    };

    miningstatuscode _eStatusCode = miningstatuscode::GenDisabled;

    const map<miningstatuscode, string> _mapStatusDescription = {
        {miningstatuscode::Mining,              "Mining"},
        {miningstatuscode::MiningWithWarning1,  "Warning: Seed server's block information is unknown"},
        {miningstatuscode::MiningWithWarning2,  "Warning: Block height less than seed server's"},
        {miningstatuscode::MiningWithWarning3,  "Warning: Block hash different from seed server's"},
        {miningstatuscode::Switching,           "Switching to the best chain"},
        {miningstatuscode::GenDisabled,         "Specify \"-gen\" option to enable"},
        {miningstatuscode::HyperBlockNotReady,  "My latest hyper block isn't ready"},
        {miningstatuscode::NoAnyNeighbor,       "No neighbor found"},
        {miningstatuscode::InvalidGenesisBlock, "Genesis block error"},
        {miningstatuscode::MiningSettingClosed, "Coin's mining setting is closed"},
        {miningstatuscode::ManyBlocksNonChained, "More than 40 blocks is non-chained"},
        {miningstatuscode::ChainIncomplete,     "The chain is incomplete"},
    };

    BackTrackingProgress _backTrackingProgress;
};


class CBlockBloomFilter
{
public:
    CBlockBloomFilter();
    virtual ~CBlockBloomFilter() {};

    bool contain(const uint256& hashBlock)
    {
        return _filter.contain((char*)hashBlock.begin(), 32);
    }

    bool insert(const uint256& hashBlock)
    {
        _filter.insert((char*)hashBlock.begin(), 32);
        return true;
    }

    void clear()
    {
        _filter.clear();
    }

protected:
    BloomFilter _filter;
};

class CBlockCacheLocator
{
public:
    CBlockCacheLocator() {}
    ~CBlockCacheLocator() {}

    bool contain(const uint256& hashBlock);

    bool insert(const uint256& hashBlock)
    {
        return _filterBlock.insert(hashBlock);
    }

    bool insert(const uint256& hashBlock, const CBlock& blk);

    void clear();



    bool erase(const uint256& hashBlock);

    const CBlock& operator[](const uint256& hashBlock);

private:
    const size_t _capacity = 200;
    CBlockBloomFilter _filterBlock;

    std::map<uint256, CBlock> _mapBlock;
    std::map<int64, uint256> _mapTmJoined;
};

class CBlockDiskLocator
{
public:
    CBlockDiskLocator() {}
    ~CBlockDiskLocator() {}

    bool contain(const uint256& hashBlock);

    bool insert(const uint256& hashBlock)
    {
        return _filterBlock.insert(hashBlock);
    }

    size_t size()
    {
        return _sizeInserted;
    }

    bool insert(CBlockTripleAddressDB& btadb, const uint256& hashBlock, const BLOCKTRIPLEADDRESS& addr);
    bool insert(const uint256& hashBlock, const BLOCKTRIPLEADDRESS& addr);
    void clear();



    bool erase(const uint256& hashBlock);

    const BLOCKTRIPLEADDRESS& operator[](const uint256& hashBlock);

private:

    const size_t _capacity = 3000;

    size_t _sizeInserted = 0;
    CBlockBloomFilter _filterBlock;

    std::map<uint256, BLOCKTRIPLEADDRESS> _mapBlockTripleAddr;
    std::map<int64, uint256> _mapTmJoined;

    std::set<uint256> _setRemoved;

};

class CSpentTime
{
public:
    CSpentTime();
    uint64 Elapse();
private:
    std::chrono::system_clock::time_point  _StartTimePoint;
};


//T is non-pointer type
template<class T, class Storage>
class CCacheLocator
{
public:
    using key_type = uint256;
    using v_value_type = CBlockIndexSP;
    using value_type = std::pair<const key_type, v_value_type>;
    using iterator = typename std::map<key_type, v_value_type>::iterator;

    iterator begin() { return _mapT.begin(); }
    iterator end() { return _mapT.end(); }

    size_t size() const noexcept { return _mapT.size(); }
    bool empty() const { return _mapT.empty(); }

    v_value_type fromcache(const key_type& hashT)
    {
        v_value_type t;

        if (_mapT.count(hashT)) {
            return _mapT[hashT];
        }
        return t;
    }

    size_t count(const key_type& hashT)
    {
        if (!_filterT.contain(hashT))
            return 0;

        if (_mapT.count(hashT)) {
            return 1;
        }



        Storage db("r");
        v_value_type t;
        if (db.ReadSP(hashT, t)) {
            return 1;
        }
        return 0;
    }

    std::pair<iterator, bool> insert(const value_type& value)
    {
        return insert(value, true);
    }

    std::pair<iterator, bool> insert(const value_type& value, bool newstorageelem)
    {
        const key_type& hashT = value.first;
        const v_value_type t = value.second;

        if (newstorageelem) {
            Storage db;
            db.TxnBegin();
            db.WriteSP(t.get());
            if (!db.TxnCommit()) {
                ERROR_FL("%s : TxnCommit failed", __FUNCTION__);
                return make_pair(_mapT.end(), false);
            }
        }

        //Limit the memory capacity
        if (_mapT.size() > _capacity) {
            _mapT.erase(--_mapT.end());
        }

        std::pair<iterator, bool> ret = _mapT.insert(value);
        if (!ret.second) {
            return ret;
        }

        insert(hashT);
        return ret;
    }

    std::size_t erase(const key_type& hashT)
    {
        return _mapT.erase(hashT);
    }

    void clear()
    {
        _filterT.clear();
        _mapT.clear();
    }

    v_value_type operator[](const key_type& hashT)
    {
        if (_mapT.count(hashT)) {
            return _mapT[hashT];
        }

        Storage db("r");
        v_value_type t;

        if(!db.ReadSP(hashT, t)) {
            ERROR_FL("Failed to Read : %s", hashT.ToPreViewString().c_str());
            return t;
        }
        return t;
    }

    v_value_type get(const key_type& hashT, Storage& db)
    {
        if (_mapT.count(hashT)) {
            return _mapT[hashT];
        }

        v_value_type t;

        if (!db.ReadSP(hashT, t)) {
            ERROR_FL("Failed to Read : %s", hashT.ToPreViewString().c_str());
            return t;
        }
        return t;
    }

private:

    bool insert(const key_type& hashT)
    {
        return _filterT.insert(hashT);
    }

private:
    const size_t _capacity = 24;
    CBlockBloomFilter _filterT;

    std::map<key_type, v_value_type> _mapT;
};


#endif
