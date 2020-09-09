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

#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"
#include "node/NodeManager.h"

#include "headers.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "cryptopp/sha.h"
#include "random.h"
#include "dllmain.h"

#include "cryptocurrency.h"


#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <cstdio>

using namespace std;
using namespace boost;

#ifdef WIN32
//#include "E:/Visual_Leak_Detector/include/vld.h"
//#pragma comment(lib, "vld.lib")
#endif

//
// Global state
//

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CBlockCacheLocator mapBlocks;

static map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;

map<COutPoint, CInPoint> mapNextTx;

CCacheLocator<CBlockIndex, CTxDB_Wrapper> mapBlockIndex;
//map<uint256, CBlockIndex*> mapBlockIndex;

uint256 hashGenesisBlock;

//static CBigNum bnProofOfWorkLimit(~uint256(0) >> 32);
static CBigNum bnProofOfWorkLimit(~uint256(0) >> 4);
const int nTotalBlocksEstimate = 0;     
const int nInitialBlockThreshold = 30;  
CBlockIndexSP pindexGenesisBlock;
int nBestHeight = -1;
CBigNum bnBestChainWork = 0;
CBigNum bnBestInvalidWork = 0;
uint256 hashBestChain = 0;

T_LOCALBLOCKADDRESS addrMaxChain;

CBlockIndexSP pindexBest;

int64 nTimeBestReceived = 0;

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

map<uint256, CDataStream*> mapOrphanTransactions;
multimap<uint256, CDataStream*> mapOrphanTransactionsByPrev;


double dHashesPerSec;
int64 nHPSTimerStart;

// Settings
int fGenerateBitcoins = false;
int64 nTransactionFee = 0;
int fLimitProcessors = false;
int nLimitProcessors = 1;
int fMinimizeToTray = true;
int fMinimizeOnClose = true;
#if USE_UPNP
int fUseUPnP = true;
#else
int fUseUPnP = false;
#endif

MiningCondition g_miningCond;
BlockCheckPoint g_blockChckPnt;
extern HyperBlockMsgs hyperblockMsgs;

std::atomic_bool g_isBuiltInBlocksReady{ false };


void RequestBlockSpace(CNode* pfrom);
void RSyncGetBlock(const T_LOCALBLOCKADDRESS &addr);
extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");
extern void CheckBlockIndex(CTxDB* txdb);
extern bool SwitchChainTo(CBlockIndexSP pindexBlock);

extern void outputlog(const string& msg);

uint32_t LatestHyperBlock::_hid  = 0;
uint256 LatestHyperBlock::_hhash = 0;
CCriticalSection LatestHyperBlock::_cs_latestHyperBlock;

int LatestParaBlock::_nLatestParaHeight = 0;
CBlockIndexSimplified* LatestParaBlock::_pindexLatest = nullptr;
CBlockIndexSimplified* LatestParaBlock::_pindexLatestRoot = nullptr;

map<uint256, CBlockIndexSimplified*> LatestParaBlock::_mapBlockIndexLatest;
CBlockDiskLocator LatestParaBlock::_mapBlockAddressOnDisk;


CBlockIndexSP LatestBlockIndexOnChained()
{
    CBlockIndexSP pIndex = pindexBest;
    while (pIndex && !pIndex->addr.isValid()) {
        pIndex = pIndex->pprev();
    }
    return pIndex;
}

void RegisterWallet(CWallet* pwalletIn)
{
    CRITICAL_BLOCK(cs_setpwalletRegistered)
    {
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    CRITICAL_BLOCK(cs_setpwalletRegistered)
    {
        setpwalletRegistered.erase(pwalletIn);
    }
}

bool static IsFromMe(CTransaction& tx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}

bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx, wtx))
            return true;
    return false;
}

void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

void static SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
}

void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

void static ResendWalletTransactions()
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions();
}


//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

void static AddOrphanTx(const CDataStream& vMsg)
{
    CTransaction tx;
    CDataStream(vMsg) >> tx;
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return;
    CDataStream* pvMsg = mapOrphanTransactions[hash] = new CDataStream(vMsg);
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev.insert(make_pair(txin.prevout.hash, pvMsg));
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(txin.prevout.hash);
            mi != mapOrphanTransactionsByPrev.upper_bound(txin.prevout.hash);)
        {
            if ((*mi).second == pvMsg)
                mapOrphanTransactionsByPrev.erase(mi++);
            else
                mi++;
        }
    }
    delete pvMsg;
    mapOrphanTransactions.erase(hash);
}


//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

std::string CTransaction::ToString() const
{
    uint256 hash = GetHash();
    string strTxHash = hash.ToString();
    TRY_CRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        if (pwalletMain->mapWallet.count(hash)) {
            strTxHash += "(mine)";
        }
        else {
            strTxHash += "(other)";
        }
    }
    std::string str;
    str += strprintf("CTransaction hash=%s\n"
        "\tver=%d, vin.size=%d, vout.size=%d, nLockTime=%d\n",
        strTxHash.c_str(),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (size_t i = 0; i < vin.size(); i++)
        str += "\t" + vin[i].ToString() + "\n";
    for (size_t i = 0; i < vout.size(); i++)
        str += "\t" + vout[i].ToString() + "\n";
    return str;
}

bool CTransaction::ReadFromDisk(CDiskTxPos pos)
{
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!hyperchainspace->GetLocalBlockPayload(pos.addr, payload)) {
        return ERROR_FL("CTransaction::ReadFromDisk() : block(%s) isn't found in my local storage", pos.addr.tostring().c_str());
    }

    try {
        CAutoBuffer autobuff(std::move(payload));
        autobuff.seekg(pos.nTxPos);
        autobuff >> *this;
    }
    catch (std::ios_base::failure & e) {
        return ERROR_FL("CTransaction::ReadFromDisk() : %s", e.what());
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB_Wrapper& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.hash, txindexRet))
        return false;
    if (!ReadFromDisk(txindexRet.pos))
        return false;
    if (prevout.n >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB_Wrapper& txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB_Wrapper txdb;
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL)
        {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB_Wrapper().ReadTxIndex(GetHash(), txindex))
                return 0;
            if (!blockTmp.ReadFromDisk(txindex))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    auto mi = mapBlockIndex[hashBlock];
    if (!mi)
        return 0;
    CBlockIndex* pindex = mi.get();
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}


bool CTransaction::CheckTransaction() const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return ERROR_FL("vin empty");
    if (vout.empty())
        return ERROR_FL("vout empty");
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK) > MAX_BLOCK_SIZE)
        return ERROR_FL("size limits failed");

    // Check for negative or overflow output values
    int64 nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        if (txout.nValue < 0)
            return ERROR_FL("txout.nValue negative");
        if (txout.nValue > MAX_MONEY)
            return ERROR_FL("txout.nValue too high");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return ERROR_FL("txout total out of range");
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return false;
        vInOutPoints.insert(txin.prevout);
    }

    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return ERROR_FL("prevout is null");
    }

    return true;
}

bool CTransaction::AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs, bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction())
        return ERROR_FL("CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (IsCoinBase())
        return ERROR_FL("coinbase as individual tx");

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64)nLockTime > INT_MAX)
        return ERROR_FL("not accepting nLockTime beyond 2038 yet");

    // Safety limits
    unsigned int nSize = ::GetSerializeSize(*this, SER_NETWORK);
    // Checking ECDSA signatures is a CPU bottleneck, so to avoid denial-of-service
    // attacks disallow transactions with more than one SigOp per 34 bytes.
    // 34 bytes because a TxOut is:
    //   20-byte address + 8 byte bitcoin amount + 5 bytes of ops + 1 byte script length
    if (GetSigOpCount() > nSize / 34 || nSize < 100)
        return ERROR_FL("nonstandard transaction");

    // Rather not work on nonstandard transactions (unless -testnet)
    if (!fTestNet && !IsStandard())
        return ERROR_FL("nonstandard transaction type");

    // Do we already have it?
    uint256 hash = GetHash();
    CRITICAL_BLOCK(cs_mapTransactions)
        if (mapTransactions.count(hash))
            return false;
    if (fCheckInputs)
        if (txdb.ContainsTx(hash))
            return false;

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (int i = 0; i < vin.size(); i++)
    {
        COutPoint outpoint = vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal())
                return false;
            if (!IsNewerThan(*ptxOld))
                return false;
            for (int i = 0; i < vin.size(); i++)
            {
                COutPoint outpoint = vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        // Check against previous transactions
        map<uint256, CTxIndex> mapUnused;
        int64 nFees = 0;
        if (!ConnectInputs(txdb, mapUnused, CDiskTxPos(1), pindexBest, nFees, false, false))
        {
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return ERROR_FL("ConnectInputs failed %s", hash.ToString().substr(0, 10).c_str());
        }

        // Don't accept it if it can't get into a block
        if (nFees < GetMinFee(1000, true, true))
            return ERROR_FL("not enough fees");

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make other's transactions take longer to confirm.
        if (nFees < MIN_RELAY_TX_FEE)
        {
            static CCriticalSection cs;
            static double dFreeCount;
            static int64 nLastTime;
            int64 nNow = GetTime();

            CRITICAL_BLOCK(cs)
            {
                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0 / 600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;
                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount > GetArg("-limitfreerelay", 15) * 10 * 1000 && !IsFromMe(*this))
                    return ERROR_FL("free transaction rejected by rate limiter");
                if (fDebug)
                    printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount + nSize);
                dFreeCount += nSize;
            }
        }
    }

    // Store transaction in memory
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        if (ptxOld)
        {
            printf("AcceptToMemoryPool() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            ptxOld->RemoveFromMemoryPool();
        }
        AddToMemoryPoolUnchecked();
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());

    printf("AcceptToMemoryPool(): accepted %s\n", hash.ToString().substr(0, 10).c_str());
    return true;
}

bool CTransaction::AcceptToMemoryPool(bool fCheckInputs, bool* pfMissingInputs)
{
    CTxDB_Wrapper txdb;
    return AcceptToMemoryPool(txdb, fCheckInputs, pfMissingInputs);
}

bool CTransaction::AddToMemoryPoolUnchecked()
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call AcceptToMemoryPool to properly check the transaction first.
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        uint256 hash = GetHash();
        mapTransactions[hash] = *this;
        for (int i = 0; i < vin.size(); i++)
            mapNextTx[vin[i].prevout] = CInPoint(&mapTransactions[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTransaction::RemoveFromMemoryPool()
{
    // Remove transaction from memory pool
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            mapNextTx.erase(txin.prevout);
        mapTransactions.erase(GetHash());
        nTransactionsUpdated++;
    }
    return true;
}


int CMerkleTx::GetDepthInMainChain(int& nHeightRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    auto mi = mapBlockIndex[hashBlock];
    if (!mi)
        return 0;
    CBlockIndex* pindex = mi.get();
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }
    nHeightRet = pindex->nHeight;
    return pindexBest->nHeight - pindex->nHeight + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    //return max(0, (COINBASE_MATURITY + 20) - GetDepthInMainChain());
    return max(0, (COINBASE_MATURITY + 1) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptToMemoryPool(txdb, false);
    }
    else
    {
        return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
    }
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB_Wrapper txdb;
    return AcceptToMemoryPool(txdb);
}


bool CWalletTx::AcceptWalletTransaction(CTxDB_Wrapper& txdb, bool fCheckInputs)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!tx.IsCoinBase())
            {
                uint256 hash = tx.GetHash();
                if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptToMemoryPool(txdb, fCheckInputs);
            }
        }
        return AcceptToMemoryPool(txdb, fCheckInputs);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB_Wrapper txdb;
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const
{
    CBlock block;
    if (!block.ReadFromDisk(*this))
        return 0;
    auto mi = mapBlockIndex[block.GetHash()];
    if (!mi)
        return 0;
    CBlockIndex* pindex = mi.get();
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + nBestHeight - pindex->nHeight;
}



//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

uint256 getBlockHeaderProgPowHash(const CBlock *pblock)
{
    if (pblock->nSolution.empty()) {
        return 0;
    }

    uint64_t nonce = pblock->nNonce;

    ethash::hash256 header_hash = pblock->GetHeaderHash();

    ethash::hash256 mix;
    memcpy(mix.bytes, pblock->nSolution.data(), sizeof(mix.bytes));

    ethash::hash256 ret = progpow::verify_final_hash(header_hash, mix, nonce);

    uint256 r;
    std::reverse_copy(std::begin(ret.bytes), std::end(ret.bytes), r.begin());

    return r;
}

uint256 CBlock::GetHash() const
{
    return getBlockHeaderProgPowHash(this);
}

void CBlock::SetHyperBlockInfo()
{
    nPrevHID = LatestHyperBlock::GetHID(&hashPrevHyperBlock);

    NodeManager* mgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = mgr->myself();
    ownerNodeID = me->getNodeId<CUInt128>();

    string owner = ownerNodeID.ToHexString();
    hashExternData = Hash(owner.begin(), owner.end());
}

bool CBlock::IsMine() const
{
    NodeManager* mgr = Singleton<NodeManager>::getInstance();
    HCNodeSH& me = mgr->myself();
    return me->getNodeId<CUInt128>() == ownerNodeID;
}

bool CBlock::CheckExternalData() const
{
    string owner = ownerNodeID.ToHexString();
    uint256 h = Hash(owner.begin(), owner.end());
    return h == hashExternData;
}


int CBlock::CheckHyperBlockConsistence(CNode* pfrom) const
{
    if (nHeight == 0) {
        return 0;
    }

    T_HYPERBLOCK h;
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    if (hyperchainspace->getHyperBlock(nPrevHID, h)) {

            T_SHA256 hash = h.GetHashSelf();
            uint256 hashCurr(hash.toHexString());

            if (hashCurr != hashPrevHyperBlock) {
                WARNING_FL("Hyper block %d: In my storage hash %s !!!== %s",
                    nPrevHID, hashCurr.ToPreViewString().c_str(),
                    hashPrevHyperBlock.ToPreViewString().c_str());
                if (pfrom) {
                    RSyncRemotePullHyperBlock(nPrevHID, pfrom->nodeid);
                }
                return -1;
            }
            return 0;
        }
    RSyncRemotePullHyperBlock(nPrevHID);

    WARNING_FL("I have not Hyper block: %d", nPrevHID);
    return -2;
}

bool CBlock::IsLastestHyperBlockMatched() const
{
    uint256 currHyperBlockhash;
    uint64 id = LatestHyperBlock::GetHID(&currHyperBlockhash);

    if (id != nPrevHID) {
        return false;
    }
    if (hashPrevHyperBlock != currHyperBlockhash) {
        return false;
    }
    return true;
}

ethash::hash256 CBlock::GetHeaderHash() const
{
    CEquihashInput I{ *this };
    CDataStream ss(SER_BUDDYCONSENSUS);
    ss << I;

    auto offset = ss.size();
    ss << nNonce;

    memset((unsigned char*)&ss[offset], 0, sizeof(nNonce));
    return ethash_keccak256((unsigned char*)&ss[0], offset + sizeof(nNonce));
}

bool CBlock::ReadFromDisk(const CTxIndex& txidx, bool fReadTransactions)
{
    if (txidx.pos.addr.isValid()) {
        return ReadFromDisk(txidx.pos.addr, fReadTransactions);
    }
    CBlockIndexSP pIndex = pindexBest;
    while (pIndex)
    {
        if (pIndex->nHeight == txidx.pos.nHeight) {
            return ReadFromDisk(pIndex, fReadTransactions);
        }
        pIndex = pIndex->pprev();
    }
    return ERROR_FL("block(%d) isn't found in local node", txidx.pos.nHeight);

}

bool CBlock::ReadFromDisk(const CBlockIndexSP pindex, bool fReadTransactions)
{
    if (!fReadTransactions) {
        *this = pindex->GetBlockHeader();
        return true;
    }

    if (ReadFromMemoryPool(pindex->GetBlockHash())) {
        return true;
    }
    else {
        CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        uint256 h = pindex->GetBlockHash();
        T_SHA256 t(h.begin());

        string payload;
        if (!hyperchainspace->GetLocalBlockPayload(pindex->addr, payload)) {
            RSyncRemotePullHyperBlock(pindex->addr.hid);
            return ERROR_FL("block(%s) isn't found in my local storage", pindex->addr.tostring().c_str());
        }

        try {
            CAutoBuffer autobuff(std::move(payload));
            autobuff >> *this;
            this->ownerNodeID = pindex->ownerNodeID;
        }
        catch (std::ios_base::failure& e) {
            return ERROR_FL("%s", e.what());
        }
    }

    if (GetHash() != pindex->GetBlockHash())
        return ERROR_FL("GetHash() doesn't match index, Height: %d", pindex->nHeight);
    return true;
}

bool CBlock::ReadFromDisk(const CBlockIndexSimplified* pindex)
{
    bool isGot = false;
    if (ReadFromMemoryPool(pindex->GetBlockHash())) {
        isGot = true;
    }
    else {
        if (ReadFromDisk(pindex->addr)) {
            isGot = true;
        }
    }

    if (isGot && GetHash() == pindex->GetBlockHash())
        return true;
    return ERROR_FL("GetHash() doesn't match index, Height: %d", pindex->nHeight);
}

CBlockLocator::CBlockLocator(uint256 hashBlock)
{
    auto mi = mapBlockIndex[hashBlock];
    if (mi)
        Set(mi);
}

int CBlockLocator::GetDistanceBack()
{
    int nDistance = 0;
    int nStep = 1;
    BOOST_FOREACH(const uint256& hash, vHave)
    {
        auto mi = mapBlockIndex[hash];
        if (mi) {
            CBlockIndex* pindex = mi.get();
            if (pindex->IsInMainChain())
                return nDistance;
        }
        nDistance += nStep;
        if (nDistance > 10)
            nStep *= 2;
    }
    return nDistance;
}

CBlockIndexSP CBlockLocator::GetBlockIndex()
{
    BOOST_FOREACH(const uint256& hash, vHave)
    {
        auto mi = mapBlockIndex[hash];
        if (mi) {
            CBlockIndexSP pindex = mi;
            if (pindex->IsInMainChain())
                return pindex;
        }
    }
    return pindexGenesisBlock;
}

uint256 CBlockLocator::GetBlockHash()
{
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256& hash, vHave)
    {
        auto mi = mapBlockIndex[hash];
        if (mi) {
            CBlockIndex* pindex = mi.get();
            if (pindex->IsInMainChain())
                return hash;
        }
    }
    return hashGenesisBlock;
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

int64 static GetBlockValue(int nHeight, int64 nFees)
{
    int64 nSubsidy = g_cryptoCurrency.GetReward() * COIN;

    // Subsidy is cut in half every 4 years
    //nSubsidy >>= (nHeight / 210000);
    nSubsidy >>= (nHeight / 5045760);

    return nSubsidy + nFees;
}

unsigned int static GetNextWorkRequired(const CBlockIndexSP pindexLast)
{
    //const int64 nTargetTimespan = 14 * 24 * 60 * 60; // two weeks
    //const int64 nTargetSpacing = 10 * 60;

    const int64 nTargetTimespan = 14 * 24 * 60 * 2;
    const int64 nTargetSpacing = 20;                       

    const int64 nInterval = nTargetTimespan / nTargetSpacing;

    if (pindexLast == nullptr)
        return bnProofOfWorkLimit.GetCompact();

    if (pindexLast->nHeight < g_cryptoCurrency.GetMaxMultiCoinBaseBlockHeight()) {
        return g_cryptoCurrency.GetGenesisBits();
    }
    if (pindexLast->nHeight == g_cryptoCurrency.GetMaxMultiCoinBaseBlockHeight()) {
        return g_cryptoCurrency.GetBits();
    }

    if ((pindexLast->nHeight + 1) % nInterval != 0) {
        return pindexLast->nBits;
    }

    CBlockIndexSP pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nInterval - 1; i++)
        pindexFirst = pindexFirst->pprev();
    assert(pindexFirst);

    int64 nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    printf("  nActualTimespan = %" PRI64d "  before bounds\n", nActualTimespan);

    if (nActualTimespan < nTargetTimespan / 4)
        nActualTimespan = nTargetTimespan / 4;
    if (nActualTimespan > nTargetTimespan * 4)
        nActualTimespan = nTargetTimespan * 4;

    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    printf("GetNextWorkRequired RETARGET\n");
    printf("nTargetTimespan = %" PRI64d "    nActualTimespan = %" PRI64d "\n", nTargetTimespan, nActualTimespan);

    printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
    printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    //if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
    //    return ERROR_FL("nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return ERROR_FL("hash doesn't match nBits");

    return true;
}

// Return conservative estimate of total number of blocks, 0 if unknown
int GetTotalBlocksEstimate()
{
    if (fTestNet)
    {
        return 0;
    }
    else
    {
        return nTotalBlocksEstimate;
    }
}

bool IsInitialBlockDownload()
{
    return false;
    //if (pindexBest == NULL || nBestHeight < (GetTotalBlocksEstimate() - nInitialBlockThreshold))
    //    return true;
    //static int64 nLastUpdate;
    //static CBlockIndex* pindexLastBest;
    //if (pindexBest != pindexLastBest)
    //{
    //    pindexLastBest = pindexBest;
    //    nLastUpdate = GetTime();
    //}
    //return (GetTime() - nLastUpdate < 10 &&
    //    pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60 );
}

void static InvalidChainFound(CBlockIndexSP pindexNew)
{
    if (pindexNew->bnChainWork > bnBestInvalidWork)
    {
        bnBestInvalidWork = pindexNew->bnChainWork;
        CTxDB_Wrapper().WriteBestInvalidWork(bnBestInvalidWork);
        MainFrameRepaint();
    }
    printf("InvalidChainFound: invalid block=%s  height=%d  work=%s\n", pindexNew->GetBlockHash().ToString().substr(0, 20).c_str(), pindexNew->nHeight, pindexNew->bnChainWork.ToString().c_str());
    printf("InvalidChainFound:  current best=%s  height=%d  work=%s\n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight, bnBestChainWork.ToString().c_str());
    if (pindexBest && bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 144)
        printf("InvalidChainFound: WARNING: Displayed transactions may not be correct!  You may need to upgrade, or other nodes may need to upgrade.\n");
}



bool CTransaction::DisconnectInputs(CTxDB_Wrapper& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return ERROR_FL("ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return ERROR_FL("prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.hash, txindex))
                return ERROR_FL("UpdateTxIndex failed");
        }
    }

    // Remove transaction from index
    if (!txdb.EraseTxIndex(*this))
        return ERROR_FL("EraseTxPos failed");

    return true;
}

inline bool SearchTxInTransactions(const uint256& hashTx, CTransaction& tx)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        if (!mapTransactions.count(hashTx))
            return false;
        tx= mapTransactions[hashTx];
    }
    return true;
}

bool SeachTxInUnchainedBlocks(const uint256& hashTx, CTransaction& tx, CBlockIndex& idxBlock)
{
    bool isFound = false;
    CBlockIndexSP pIndex = pindexBest;
    while (!isFound && pIndex && !pIndex->addr.isValid()) {
        auto hash = pIndex->GetBlockHash();
        if (!mapBlocks.contain(hash)) {
            pIndex = pIndex->pprev();
            continue;
        }

        for (auto& elmTx : mapBlocks[hash].vtx)
        {
            if (elmTx.GetHash() == hashTx) {
                isFound = true;
                tx = elmTx;
                idxBlock = *pIndex;
                break;
            }
        }
        pIndex = pIndex->pprev();
    }

    return isFound;
}

bool SearchTxByBlockHeight(const uint256 & hashTx, int nBlockHeight, CTransaction& tx)
{
    CBlockIndexSP pIndex = pindexBest;
    while (pIndex) {
        if (pIndex->nHeight > nBlockHeight) {
            pIndex = pIndex->pprev();
            continue;
        }

        CBlock block;
        if (!block.ReadFromDisk(pIndex)) {
            return ERROR_FL("Failed in block: height %d", pIndex->nHeight);
        }

        for (auto& elmTx : block.vtx) {
            if (elmTx.GetHash() == hashTx) {
                tx = elmTx;
                return true;
            }
        }
        break;
    }
    return ERROR_FL("Cannot find the tx %s in block: %d", hashTx.ToPreViewString().c_str(), nBlockHeight);
}


bool CTransaction::ConnectInputs(CTxDB_Wrapper& txdb, map<uint256, CTxIndex>& mapTestPool, CDiskTxPos posThisTx,
    CBlockIndexSP pindexBlock, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee)
{
    // Take over previous transactions' spent pointers
    if (!IsCoinBase())
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;

            // Read txindex
            CTxIndex txindex;
            bool fFound = true;
            if ((fBlock || fMiner) && mapTestPool.count(prevout.hash))
            {
                // Get txindex from current proposed changes
                txindex = mapTestPool[prevout.hash];
            }
            else
            {
                // Read txindex from txdb
                fFound = txdb.ReadTxIndex(prevout.hash, txindex);
            }
            if (!fFound && (fBlock || fMiner))
                return fMiner ? false : ERROR_FL("%s prev tx %s index entry not found", GetHash().ToString().substr(0, 10).c_str(), prevout.hash.ToString().substr(0, 10).c_str());

            // Read txPrev
            CTransaction txPrev;

            if (!fFound || txindex.pos == CDiskTxPos(1))
            {
                // Get prev tx from single transactions in memory
                if(!SearchTxInTransactions(prevout.hash, txPrev))
                    return ERROR_FL("%s mapTransactions prev not found %s", GetHash().ToString().substr(0, 10).c_str(), prevout.hash.ToString().substr(0, 10).c_str());
                if (!fFound)
                    txindex.vSpent.resize(txPrev.vout.size());
            }
            else
            {
                do {
                    if (txindex.pos.addr.isValid() && txPrev.ReadFromDisk(txindex.pos)) {
                        break;
                    }

                    if (!SearchTxInTransactions(prevout.hash, txPrev)) {
                        if (!SearchTxByBlockHeight(prevout.hash, txindex.pos.nHeight, txPrev)) {
                            return ERROR_FL("%s Transactions prev not found %s", GetHash().ToString().substr(0, 10).c_str(), prevout.hash.ToString().substr(0, 10).c_str());
                        }
                    }
                } while (false);

                if (txPrev.IsCoinBase()) {
                    if (pindexBlock->nHeight - txindex.pos.nHeight < COINBASE_MATURITY) {
                        return ERROR_FL("tried to spend coinbase at depth %d", pindexBlock->nHeight - txindex.pos.nHeight);
                    }
                }
            }

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return ERROR_FL("%s prevout.n out of range %d %d %d prev tx %s\n%s", GetHash().ToString().substr(0, 10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0, 10).c_str(), txPrev.ToString().c_str());

            // If prev is coinbase, check that it's matured
            if (txPrev.IsCoinBase() && txindex.pos.addr.isValid()) {
                for (CBlockIndexSP pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < COINBASE_MATURITY; pindex = pindex->pprev())
                    if (pindex->addr == txindex.pos.addr)
                        return ERROR_FL("tried to spend coinbase at depth %d", pindexBlock->nHeight - pindex->nHeight);
            }
            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return ERROR_FL("%s VerifySignature failed", GetHash().ToString().substr(0, 10).c_str());

            // Check for conflicts
            if (!txindex.vSpent[prevout.n].IsNull())
                return fMiner ? false : ERROR_FL("%s prev tx already used at %s", GetHash().ToString().substr(0, 10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return ERROR_FL("txin values out of range");

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock || fMiner)
            {
                mapTestPool[prevout.hash] = txindex;
            }
        }

        if (nValueIn < GetValueOut())
            return ERROR_FL("%s value in < value out", GetHash().ToString().substr(0, 10).c_str());

        // Tally transaction fees
        int64 nTxFee = nValueIn - GetValueOut();
        if (nTxFee < 0)
            return ERROR_FL("%s nTxFee < 0", GetHash().ToString().substr(0, 10).c_str());
        if (nTxFee < nMinFee)
            return false;
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return ERROR_FL("nFees out of range");
    }

    if (fBlock)
    {
        // Add transaction to changes
        mapTestPool[GetHash()] = CTxIndex(posThisTx, vout.size());
    }
    else if (fMiner)
    {
        // Add transaction to test pool
        mapTestPool[GetHash()] = CTxIndex(CDiskTxPos(1), vout.size());
    }

    return true;
}


bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            COutPoint prevout = vin[i].prevout;
            if (!mapTransactions.count(prevout.hash))
                return false;
            CTransaction& txPrev = mapTransactions[prevout.hash];

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return ERROR_FL("VerifySignature failed");

            ///// this is redundant with the mapNextTx stuff, not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.n].nValue;

            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return ERROR_FL("txin values out of range");
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}


bool CBlock::DisconnectBlock(CTxDB_Wrapper& txdb, CBlockIndexSP pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size() - 1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    auto spprev = pindex->pprev();
    if (spprev)
    {
        CDiskBlockIndex blockindexPrev(spprev.get());
        blockindexPrev.GetBlockIndex()->hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return ERROR_FL("WriteBlockIndex failed");
    }

    BOOST_FOREACH(CTransaction& tx, vtx)
        EraseFromWallets(tx.GetHash());

    return true;
}

bool CBlock::ConnectBlock(CTxDB_Wrapper& txdb, CBlockIndexSP pindex)
{
    // Check it again in case a previous version let a bad block in
    if (!CheckBlock())
        return false;

    //// issue here: it doesn't know the version
    unsigned int nTxPos = ::GetSerializeSize(CBlock(), SER_BUDDYCONSENSUS) - 2 + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    int64 nFees = 0;
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        CDiskTxPos posThisTx(pindex->addr, nTxPos, nHeight);
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        if (!tx.ConnectInputs(txdb, mapQueuedChanges, posThisTx, pindex, nFees, true, false))
            return false;
    }
    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return ERROR_FL("UpdateTxIndex failed");
    }

    if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees))
        return false;

    auto spprev = pindex->pprev();
    if (spprev)
    {
        CDiskBlockIndex blockindexPrev(spprev.get());
        blockindexPrev.GetBlockIndex()->hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return ERROR_FL("WriteBlockIndex failed");
    }

    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, true);

    return true;
}


bool static Reorganize(CTxDB_Wrapper& txdb, CBlockIndexSP pindexNew)
{
    printf("REORGANIZE\n");

    // Find the fork
    CBlockIndexSP pfork = pindexBest;
    CBlockIndexSP plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev()))
                return ERROR_FL("plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev()))
            return ERROR_FL("pfork->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndexSP> vDisconnect;
    for (CBlockIndexSP pindex = pindexBest; pindex != pfork; pindex = pindex->pprev())
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndexSP> vConnect;
    for (CBlockIndexSP pindex = pindexNew; pindex != pfork; pindex = pindex->pprev())
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndexSP pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return ERROR_FL("Heigh:%d ReadFromDisk for disconnect failed", pindex->nHeight);
        if (!block.DisconnectBlock(txdb, pindex))
            return ERROR_FL("DisconnectBlock failed");

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!tx.IsCoinBase())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndexSP pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return ERROR_FL("ReadFromDisk for connect failed");
        if (!block.ConnectBlock(txdb, pindex))
        {
            // Invalid block
            txdb.TxnAbort();
            return ERROR_FL("ConnectBlock failed");
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    auto hash = pindexNew->GetBlockHash();
    if (!txdb.WriteHashBestChain(hash))
        return ERROR_FL("WriteHashBestChain failed");


    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndexSP pindex, vDisconnect)
    {
        auto spprev = pindex->pprev();
        if (spprev) {
            spprev->hashNext = 0;
            txdb.WriteBlockIndex(CDiskBlockIndex(spprev.get()));
        }
    }

    // Connect longer branch
    BOOST_FOREACH(CBlockIndexSP pindex, vConnect)
    {
        auto spprev = pindex->pprev();
        if (spprev) {
            spprev->hashNext = pindex->GetBlockHash();
            txdb.WriteBlockIndex(CDiskBlockIndex(spprev.get()));
        }
    }

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return ERROR_FL("TxnCommit failed");

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect)
        tx.AcceptToMemoryPool(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete)
        tx.RemoveFromMemoryPool();

    return true;
}

bool CBlock::SetBestChain(CTxDB_Wrapper& txdb, CBlockIndexSP pindexNew)
{
    uint256 hash = GetHash();

    txdb.TxnBegin();
    if (pindexGenesisBlock == nullptr && hash == hashGenesisBlock) {
        ConnectBlock(txdb, pindexNew);
        txdb.WriteHashBestChain(hash);
        if (!txdb.TxnCommit())
            return ERROR_FL("TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain) {
        // Adding to current best branch
        if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return ERROR_FL("ConnectBlock failed");
        }

        // Add to current best branch
        auto spprev = pindexNew->pprev();
        if (spprev) {
            spprev->hashNext = pindexNew->GetBlockHash();
            txdb.WriteBlockIndex(CDiskBlockIndex(spprev.get()));
        }

        if (!txdb.TxnCommit())
            return ERROR_FL("TxnCommit failed");

        // Delete redundant memory transactions
        BOOST_FOREACH(CTransaction& tx, vtx)
            tx.RemoveFromMemoryPool();
    }
    else {
        // New best branch
        if (!Reorganize(txdb, pindexNew)) {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return ERROR_FL("Reorganize failed");
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    if (!IsInitialBlockDownload()) {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = hash;
    pindexBest = pindexNew;
    nBestHeight = pindexBest->nHeight;
    bnBestChainWork = pindexNew->bnChainWork;
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;
    printf("SetBestChain: new best=%s  height=%d  work=%s\n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight, bnBestChainWork.ToString().c_str());

    return true;
}


bool CBlock::UpdateToBlockIndex(CBlockIndexSP pIndex, const T_LOCALBLOCKADDRESS& addr)
{
    // Check for duplicate
    pIndex->addr = addr;

    //if (pIndex->pprev) {
    //    pIndex->pprev->pnext = pIndex;
    //}

    CTxDB_Wrapper txdb;
    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pIndex.get()));
    auto spprev = pIndex->pprev();
    if (spprev) {
        spprev->hashNext = pIndex->GetBlockHash();
        txdb.WriteBlockIndex(CDiskBlockIndex(spprev.get()));
    }

    unsigned int nTxPos = ::GetSerializeSize(CBlock(), SER_BUDDYCONSENSUS) - 2 + GetSizeOfCompactSize(vtx.size());

    BOOST_FOREACH(CTransaction & tx, vtx)
    {
        CTxIndex txindex(CDiskTxPos(addr, nTxPos, nHeight), tx.vout.size());
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        uint256 txhash = tx.GetHash();
        if (!txdb.UpdateTxIndex(txhash, txindex))
            return ERROR_FL("UpdateTxIndex failed");
    }

    if (!txdb.TxnCommit())
        return false;

    return true;
}

bool CBlock::AddToBlockIndex(const T_LOCALBLOCKADDRESS& addr)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return ERROR_FL("%s already exists", hash.ToString().substr(0, 20).c_str());

    // Construct new block index object
    CBlockIndexSP pindexNew = make_shared_proxy<CBlockIndex>(addr, *this);
    if (!pindexNew)
        return ERROR_FL("new CBlockIndex failed");
    auto mi_pair = mapBlockIndex.insert(make_pair(hash, pindexNew));
    if (!mi_pair.second) {
        return ERROR_FL("insert CBlockIndex failed");
    }
    auto mi = mi_pair.first;
    pindexNew->hashBlock = ((*mi).first);
    auto miPrev = mapBlockIndex[hashPrevBlock];
    if (miPrev) {
        pindexNew->hashPrev = hashPrevBlock;// (*miPrev).second;
        pindexNew->nHeight = miPrev->nHeight + 1;
    }

    CTxDB_Wrapper txdb;
    txdb.TxnBegin();

    auto spprev = pindexNew->pprev();
    pindexNew->bnChainWork = (spprev ? spprev->bnChainWork : 0) + pindexNew->GetBlockWork();

    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew.get()));
    if (!txdb.TxnCommit()) {
        return ERROR_FL("TxnCommit CBlockIndex failed");
    }

    pindexNew->print();

    //new block
    if (!addr.isValid() &&
        (pindexNew->bnChainWork > bnBestChainWork)) {
        if (!SetBestChain(txdb, pindexNew)) {
            return ERROR_FL("SetBestChain CBlockIndex failed");
        }

        INFO_FL("Switch to: %d,PrevHID:%d,%s, %s, BestIndex: %d PrevHID:%d,%s, %s LastHID: %u", pindexNew->nHeight,
            pindexNew->nPrevHID,
            pindexNew->addr.tostring().c_str(),
            pindexNew->GetBlockHash().ToPreViewString().c_str(),
            pindexBest->nHeight, pindexBest->nPrevHID,
            pindexBest->addr.tostring().c_str(),
            pindexBest->GetBlockHash().ToPreViewString().c_str(),
            LatestHyperBlock::GetHID());
    }
    else if(addr.isValid()){
        if (!SetBestChain(txdb, pindexNew)) {
            return ERROR_FL("SetBestChain CBlockIndex failed");
        }

        INFO_FL("Switch to: %d,PrevHID:%d,%s, %s, BestIndex: %d PrevHID:%d,%s, %s LastHID: %u", pindexNew->nHeight,
            pindexNew->nPrevHID,
            pindexNew->addr.tostring().c_str(),
            pindexNew->GetBlockHash().ToPreViewString().c_str(),
            pindexBest->nHeight, pindexBest->nPrevHID,
            pindexBest->addr.tostring().c_str(),
            pindexBest->GetBlockHash().ToPreViewString().c_str(),
            LatestHyperBlock::GetHID());
         }


    if (pindexNew == pindexBest) {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    MainFrameRepaint();
    return true;
}

bool CBlock::CheckBlock() const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    //if (!CheckExternalData()) {
    //    return ERROR_FL("CheckExternalData invalid at height %d\n", nHeight);
    //}

    if (!CheckProgPow()) {
        return ERROR_FL("ProgPow invalid at height %d\n", nHeight);
    }

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK) > MAX_BLOCK_SIZE)
        return ERROR_FL("size limits failed");

    // Check proof of work matches claimed amount
    if (!CheckProofOfWork(GetHash(), nBits))
        return ERROR_FL("proof of work failed");

    // Check timestamp
    //if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
    //    return ERROR_FL("block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return ERROR_FL("first tx is not coinbase");

    if (nHeight > g_cryptoCurrency.GetMaxMultiCoinBaseBlockHeight()) {
        for (int i = 1; i < vtx.size(); i++)
            if (vtx[i].IsCoinBase())
                return ERROR_FL("more than one coinbase");
    }

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction())
            return ERROR_FL("CheckTransaction failed");

    // Check that it's not full of nonstandard transactions
    if (GetSigOpCount() > MAX_BLOCK_SIGOPS)
        return ERROR_FL("too many nonstandard transactions");

    // Check merkleroot
    if (hashMerkleRoot != BuildMerkleTree())
        return ERROR_FL("hashMerkleRoot mismatch");

    return true;
}

bool CBlock::CheckTrans()
{
    uint256 hash = GetHash();

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
            if (!txin.IsFinal())
                return ERROR_FL("contains a non-final transaction");
    }
    return true;
}

bool CBlock::CheckProgPow() const
{
    if (nSolution.empty()) {
        return false;
    }

    uint64_t nonce = nNonce;

    uint32_t epoch = ethash::get_epoch_number(nHeight);
    ethash_epoch_context epoch_ctx = ethash::get_global_epoch_context(epoch);

    ethash::hash256 header_hash = GetHeaderHash();

    ethash::hash256 mix;

    const unsigned char *p = &*(nSolution.begin());
    memcpy(mix.bytes, &p[0], 32);

    ethash::hash256 target;
    CBigNum bnNew;
    bnNew.SetCompact(nBits);
    uint256 hashTarget = bnNew.getuint256();

    std::reverse_copy(hashTarget.begin(), hashTarget.end(), target.bytes);

    if (progpow::verify(epoch_ctx, nHeight,header_hash,
        mix, nonce, target)) {
        return true;
    }
    else {
        return ERROR_FL("verify_progpow failed");
    }

}

bool CBlock::AddToMemoryPool(const uint256 &nBlockHash)
{
    return mapBlocks.insert(nBlockHash, *this);
}

bool CBlock::AddToMemoryPool()
{
    uint256 hash = GetHash();
    return AddToMemoryPool(hash);
}

bool CBlock::RemoveFromMemoryPool()
{
    uint256 hash = GetHash();
    return mapBlocks.erase(hash);
}

bool CBlock::ReadFromMemoryPool(uint256 nBlockHash)
{
    SetNull();

    CBlockDB_Wrapper blockdb;
    if (mapBlocks.contain(nBlockHash)) {
        *this = mapBlocks[nBlockHash];
    }
    else {
        return blockdb.ReadBlock(nBlockHash, *this);
    }
    return true;
}

bool CBlock::AcceptBlock()
{
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash)) {
        return true;
    }

    auto mi = mapBlockIndex[hashPrevBlock];
    if (!mi) {
        CRITICAL_BLOCK(cs_vNodes)
        {
            BOOST_FOREACH(CNode* pnode, vNodes)
                pnode->PushInventory(CInv(MSG_BLOCK, hashPrevBlock));
        }
        return WARNING_FL("prev block not found, pulling from neighbor");
    }

    CBlockIndexSP pindexPrev = mi;
    int nHeight = pindexPrev->nHeight + 1;

    if (nBits != GetNextWorkRequired(pindexPrev))
        return ERROR_FL("incorrect proof of work");

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return ERROR_FL("block's timestamp is too early");

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
            return ERROR_FL("contains a non-final transaction");

    // Check that the block chain matches the known block chain up to a checkpoint
    //if (!fTestNet)
    //    if ((nHeight ==  11111 && hash != uint256("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")) ||
    //        (nHeight ==  33333 && hash != uint256("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")) ||
    //        (nHeight ==  68555 && hash != uint256("0x00000000001e1b4903550a0b96e9a9405c8a95f387162e4944e8d9fbe501cd6a")) ||
    //        (nHeight ==  70567 && hash != uint256("0x00000000006a49b14bcf27462068f1264c961f11fa2e0eddd2be0791e1d4124a")) ||
    //        (nHeight ==  74000 && hash != uint256("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")) ||
    //        (nHeight == 105000 && hash != uint256("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")) ||
    //        (nHeight == 118000 && hash != uint256("0x000000000000774a7f8a7a12dc906ddb9e17e75d684f15e00f8767f9e8f36553")) ||
    //        (nHeight == 134444 && hash != uint256("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")) ||
    //        (nHeight == 140700 && hash != uint256("0x000000000000033b512028abb90e1626d8b346fd0ed598ac0a3c371138dce2bd")))
    //        return error("AcceptBlock() : rejected by checkpoint lockin at %d", nHeight);

    //if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK)))
    //    return error("AcceptBlock() : out of disk space");
    //unsigned int nFile = -1;
    //unsigned int nBlockPos = 0;
    //if (!WriteToDisk(nFile, nBlockPos))
    //    return error("AcceptBlock() : WriteToDisk failed");
    //if (!AddToBlockIndex(nFile, nBlockPos))
    //    return error("AcceptBlock() : AddToBlockIndex failed");

    AddToMemoryPool(hash);

    T_LOCALBLOCKADDRESS addr;
    if (!AddToBlockIndex(addr))
        return ERROR_FL("AddToBlockIndex failed");

    if (hashBestChain == hash)
        CRITICAL_BLOCK(cs_vNodes)
        BOOST_FOREACH(CNode* pnode, vNodes)
        //if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 140700))
            pnode->PushInventory(CInv(MSG_BLOCK, hash));

    return true;
}

void ProcessOrphanBlocks(const uint256& hash)
{
    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
            mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
            ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;

            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    uint256 hash = pblock->GetHash();
    INFO_FL("%s %d ", hash.ToPreViewString().c_str(), pblock->nHeight);
    if (mapBlockIndex.count(hash))
        return INFO_FL("already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToPreViewString().c_str());
    if (mapOrphanBlocks.count(hash))
         return INFO_FL("already have block %d %s (orphan)", mapOrphanBlocks[hash]->nHeight, hash.ToPreViewString().c_str());


    if (!pblock->CheckBlock())
        return WARNING_FL("CheckBlock %s FAILED", hash.ToPreViewString().c_str());

    bool hyperblock_ok = true;
    if (pfrom) {
        int ret = pblock->CheckHyperBlockConsistence(pfrom);
        if (ret != 0) {
            /*if (ret == -2 && pblockaddr->isValid()) {
                mapSubsequentBlockAddr.insert(make_pair(pblock->nPrevHID, *pblockaddr));
            }*/
            /*if (pblock->nHeight > pindexBest->nHeight + BLOCK_MATURITY) {
                RequestBlockSpace(pfrom);
            }*/
            hyperblock_ok = false;
            //return WARNING_FL("Block: %s CheckHyperBlockConsistence invalid at height %d, cause: %d\n",
            //    hash.ToPreViewString().c_str(), pblock->nHeight, ret);
        }
    }

    if (!hyperblock_ok || !mapBlockIndex.count(pblock->hashPrevBlock) ) {
        WARNING_FL("%s ORPHAN BLOCK, hyperblock_ok:%d prev=%s\n", hash.ToPreViewString().c_str(),
            hyperblock_ok,
            pblock->hashPrevBlock.ToPreViewString().c_str());

        CBlock* pblock2 = new CBlock(*pblock);
        mapOrphanBlocks.insert(make_pair(hash, pblock2));
        mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

        bool ismining = g_miningCond.IsMining();

        if (!ismining) {
            COrphanBlockDB_Wrapper blockdb;
            blockdb.WriteBlock(*pblock2);
        }

        if (pfrom && ismining)
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
        return true;
    }

    if (g_miningCond.IsSwitching()) {
        return false;
    }

    if (!pblock->AcceptBlock())
        return ERROR_FL("AcceptBlock %s FAILED", hash.ToPreViewString().c_str());

    ProcessOrphanBlocks(hash);

    printf("ProcessBlock: %s ACCEPTED\n", hash.ToPreViewString().c_str());
    return true;
}

bool ProcessBlockFromAcceptedHyperBlock(CBlock* pblock, T_LOCALBLOCKADDRESS* pblockaddr)
{
    ProcessBlock(nullptr, pblock);

    if (pblockaddr && pblockaddr->isValid()) {

        uint256 hash = pblock->GetHash();
        if (!mapBlockIndex.count(hash)) {
            if (mapOrphanBlocks.count(hash)) {
                return true;
            }
            return false;
        }

        CBlockIndexSP pIndex = mapBlockIndex[hash];

        if (pIndex->addr == *pblockaddr) {
            return true;
        }

        if (!pblock->UpdateToBlockIndex(pIndex, *pblockaddr)) {
            return ERROR_FL("UpdateToBlockIndex failed");
        }

        //CBlock blk;
        //if (blk.ReadFromDisk(addr) && blk.GetHash() == hash) {
        //    if (!UpdateToBlockIndex(pIndex, addr)) {
        //        return ERROR_FL("UpdateToBlockIndex failed");
        //    }
        //    RemoveFromMemoryPool();
        //}

        return true;
    }

    return false;
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock, T_LOCALBLOCKADDRESS* pblockaddr)
{
    uint64 hid = LatestHyperBlock::GetHID();
    if (!pblockaddr->isValid()){

        if (pblock->nPrevHID < hid && g_miningCond.IsMining()) {
            WARNING_FL("Received block's hyper block is stale");
            return true;
        }
    }

    if (ProcessBlock(pfrom, pblock)) {
        if (pblockaddr->isValid()) {
            uint256 hash = pblock->GetHash();
            if (!mapBlockIndex.count(hash)) {
                return false;
            }

            CBlockIndexSP pIndex = mapBlockIndex[hash];
            if (pIndex->addr == *pblockaddr) {
                return true;
            }

            if (!pblock->UpdateToBlockIndex(pIndex, *pblockaddr)) {
                return ERROR_FL("UpdateToBlockIndex failed");
            }
        }
        return true;
    }
    return false;
}

bool CheckDiskSpace(uint64 nAdditionalBytes)
{
    uint64 nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for 15MB because database could create another 10MB log file at any time
    if (nFreeBytesAvailable < (uint64)15000000 + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low  ");
        strMiscWarning = strMessage;
        printf("*** %s\n", strMessage.c_str());
        ThreadSafeMessageBox(strMessage, "Hyperchain", wxOK | wxICON_EXCLAMATION);
        CreateThread(Shutdown, NULL);
        return false;
    }
    return true;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if (nFile == -1)
        return NULL;
    FILE* file = fopen(strprintf("%s/blk%04d.dat", GetDataDir().c_str(), nFile).c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    loop
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < 0x7F000000 - MAX_SIZE)
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

extern "C" BOOST_SYMBOL_EXPORT
string GetGenesisBlock(string& payload)
{
    CBlock genesis;
    genesis = g_cryptoCurrency.GetPanGuGenesisBlock();

    CDataStream datastream(SER_BUDDYCONSENSUS);
    datastream << genesis;
    payload = datastream.str();

    datastream.clear();
    datastream << genesis.hashMerkleRoot;
    return datastream.str();
}

void AddGenesisBlockToIndex()
{
    CBlock genesis;
    genesis = g_cryptoCurrency.GetGenesisBlock();

    uint256 hashGenesis = genesis.GetHash();
    assert(hashGenesis == g_cryptoCurrency.GetHashGenesisBlock());

    T_LOCALBLOCKADDRESS addr;
    addr.hid = g_cryptoCurrency.GetHID();
    addr.chainnum = g_cryptoCurrency.GetChainNum();
    addr.id = g_cryptoCurrency.GetLocalID();
    genesis.AddToBlockIndex(addr);
}

bool LoadBlockUnChained()
{
    CBlockDB_Wrapper blockdb("cr");
    if (!blockdb.LoadBlockUnChained())
        return false;
    blockdb.Close();
    return true;
}

bool LoadBlockIndex(bool fAllowNew)
{
    if (fTestNet)
    {
        hashGenesisBlock = uint256("0x00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008");
        //bnProofOfWorkLimit = CBigNum(~uint256(0) >> 28);
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 8);
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
    }

    //
    // Load block index
    //
    CTxDB_Wrapper txdb("cr+");
    if (!txdb.LoadBlockIndex())
        return false;

    //don't call Close directly because CTxDB_Wrapper
    //txdb.Close();

    //
    // Init with genesis block
    //

    if (mapBlockIndex.empty()) {
        if (!fAllowNew)
            return false;

        AddGenesisBlockToIndex();
    }

    return true;
}



void PrintBlockTree()
{
    // precompute tree structure
    map<CBlockIndexSP, vector<CBlockIndexSP> > mapNext;
    for (auto mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndexSP pindex = (*mi).second;
        mapNext[pindex->pprev()].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndexSP> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndexSP pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol - 1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d  %s  %s  tx %d",
            pindex->nHeight,
            block.GetHash().ToString().substr(0, 20).c_str(),
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main timechain first
        vector<CBlockIndexSP>& vNext = mapNext[pindex];
        for (int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext())
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol + i, vNext[i]));
    }
}



//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

map<uint256, CAlert> mapAlerts;
CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;
    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // Longer invalid proof-of-work chain
    //if (pindexBest && bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 144)
    //{
    //    nPriority = 2000;
    //    strStatusBar = strRPC = "WARNING: Displayed transactions may not be correct!  You may need to upgrade, or other nodes may need to upgrade.";
    //}

    // Alerts
    CRITICAL_BLOCK(cs_mapAlerts)
    {
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}

bool CAlert::ProcessAlert()
{
    if (!CheckSignature())
        return false;
    if (!IsInEffect())
        return false;

    CRITICAL_BLOCK(cs_mapAlerts)
    {
        // Cancel previous alerts
        for (map<uint256, CAlert>::iterator mi = mapAlerts.begin(); mi != mapAlerts.end();)
        {
            const CAlert& alert = (*mi).second;
            if (Cancels(alert))
            {
                printf("cancelling alert %d\n", alert.nID);
                mapAlerts.erase(mi++);
            }
            else if (!alert.IsInEffect())
            {
                printf("expiring alert %d\n", alert.nID);
                mapAlerts.erase(mi++);
            }
            else
                mi++;
        }

        // Check if this alert has been cancelled
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.Cancels(*this))
            {
                printf("alert already cancelled by %d\n", alert.nID);
                return false;
            }
        }

        // Add to mapAlerts
        mapAlerts.insert(make_pair(GetHash(), *this));
    }

    printf("accepted alert %d, AppliesToMe()=%d\n", nID, AppliesToMe());
    MainFrameRepaint();
    return true;
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(CTxDB_Wrapper& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:    return mapTransactions.count(inv.hash) || mapOrphanTransactions.count(inv.hash) || txdb.ContainsTx(inv.hash);
    case MSG_BLOCK:
        if (mapBlockIndex.count(inv.hash)) {
            auto pIndex = mapBlockIndex[inv.hash];
            if (pIndex->addr.isValid()) {
                return true;
            }
        }
        if (mapOrphanBlocks.count(inv.hash)) {
            return true;
        }

        if (LatestParaBlock::Count(inv.hash)) {
            return true;
        }

        return false;
    }
    // Don't know what it is, just say we already got one
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };

map<CNode*, time_t> mapPullingBlocksSpaceNodes;
CCriticalSection cs_PullingBlocksSpaceNodes;
void RequestBlockSpace(CNode* pfrom)
{
    time_t now = time(nullptr);
    CRITICAL_BLOCK(cs_PullingBlocksSpaceNodes)
    {
        if (mapPullingBlocksSpaceNodes.count(pfrom) == 0) {
            mapPullingBlocksSpaceNodes.insert({ pfrom, now });
        }
        else {
            if (now - mapPullingBlocksSpaceNodes[pfrom] < 120) {
                return;
            }
            else {
                mapPullingBlocksSpaceNodes[pfrom] = now;
            }
        }
    }
    CBlockIndexSP pindexOnChained = LatestBlockIndexOnChained();

    pfrom->PushGetBlocks(pindexOnChained, uint256(0));

}

const int SentBlock_TimeOut = 30;

void InsertSentBlock(CNode* pfrom, const uint256 &hashBlock, const uint256 &hashPrevBlock)
{
    if (!pfrom->mapBlockSent.count(hashBlock)) {
        auto now = time(nullptr);
        if (pfrom->mapBlockSent.size() > 60) {
            auto it = pfrom->mapBlockSent.begin();
            for (; it != pfrom->mapBlockSent.end(); ) {
                if (std::get<0>(*it) + SentBlock_TimeOut < now) {
                    pfrom->mapBlockSent.erase(it++);
                }
                else {
                    ++it;
                }
            }
        }
        pfrom->mapBlockSent.insert(std::make_pair(hashBlock, std::make_tuple(now, hashPrevBlock)));
    }
    else {
        auto &blkelm = pfrom->mapBlockSent[hashBlock];
        std::get<0>(blkelm) = time(nullptr);
    }
}

void ReplyRGetBlocks(CNode* pfrom, uint256 hashBlock)
{
    int nLimit = 500;
    int nTotalSendBlock = 0;
    int nMaxSendSize = 256 * 1024;
    int nTotalSendSize = 0;

    uint256 hashPrevBlock;
    CBlock block;
    CBlockIndexSP pindex;
    LogBacktrackingFromNode(pfrom->nodeid,"\n\nRespond rgetblocks(cache size: %d): %s from: %s ***********************\n", pfrom->mapBlockSent.size(),
        hashBlock.ToPreViewString().c_str(), pfrom->nodeid.c_str());

    while (1) {
        if (nTotalSendBlock >= nLimit || nTotalSendSize > nMaxSendSize) {
            LogBacktrackingFromNode(pfrom->nodeid, "  rgetblocks limit(%d, %.2f KB) stoppped at: %s\n",
                nTotalSendBlock, (float)nTotalSendSize/1024,
                hashBlock.ToPreViewString().c_str());
            break;
        }

        if (pfrom->mapBlockSent.count(hashBlock)) {
            auto &blkelm = pfrom->mapBlockSent[hashBlock];
            if (std::get<0>(blkelm) + SentBlock_TimeOut > time(nullptr)) {
                hashBlock = std::get<1>(blkelm);
                LogBacktrackingFromNode(pfrom->nodeid, "  rgetblocks %s, already sent, don't send again\n", hashBlock.ToPreViewString().c_str());
                continue;
            }
        }

        if (mapBlockIndex.count(hashBlock)) {

            pindex = mapBlockIndex[hashBlock];

            string hashpreview = hashBlock.ToPreViewString().c_str();

            if (!pindex) {
                mapBlockIndex.erase(hashBlock);
                LogBacktrackingFromNode(pfrom->nodeid, "  rgetblocks stoppped at: %s due to null block index\n", hashpreview.c_str());
                break;
            }

            LogBacktrackingFromNode(pfrom->nodeid, "  rgetblocks will send %s(%s) to node: %s\n", hashpreview.c_str(),
                pindex->addr.tostring().c_str(),
                pfrom->nodeid.c_str());

            CBlock block;
            T_LOCALBLOCKADDRESS addrblock;
            if (GetBlockData(pindex->hashBlock, block, addrblock)) {
                BLOCKTRIPLEADDRESS tripleaddr(addrblock);

                nTotalSendBlock++;
                nTotalSendSize += block.GetSerializeSize(SER_NETWORK) + sizeof(BLOCKTRIPLEADDRESS);
                pfrom->PushMessage("rblock", block, tripleaddr.hid, tripleaddr.chainnum, tripleaddr.id);

                InsertSentBlock(pfrom, hashBlock, block.hashPrevBlock);
                hashBlock = block.hashPrevBlock;
                continue;
            }
            else {
                LogBacktrackingFromNode(pfrom->nodeid, "  rgetblocks no found %s(%s)\n", hashpreview.c_str(),
                    pindex->addr.tostring().c_str());
            }
        }
        else if (LatestParaBlock::Count(hashBlock)) {
            CBlock block;
            BLOCKTRIPLEADDRESS tripleaddr;
            if (!LatestParaBlock::GetBlock(hashBlock, block, tripleaddr)) {
                LogBacktrackingFromNode(pfrom->nodeid, "\n\nRespond regetblocks(read %s failed) from node %s *************************************\n",
                    hashBlock.ToPreViewString().c_str(),
                    pfrom->nodeid.c_str());
            }
            else {

                LogBacktrackingFromNode(pfrom->nodeid, "rgetblocks send %s(tripleaddr: %s) to node: %s\n",
                    hashBlock.ToPreViewString().c_str(),
                    tripleaddr.ToString().c_str(),
                    pfrom->nodeid.c_str());

                nTotalSendBlock++;
                nTotalSendSize += block.GetSerializeSize(SER_NETWORK) + sizeof(BLOCKTRIPLEADDRESS);
                pfrom->PushMessage("rblock", block, tripleaddr.hid, tripleaddr.chainnum, tripleaddr.id);

                InsertSentBlock(pfrom, hashBlock, block.hashPrevBlock);
                hashBlock = block.hashPrevBlock;
                continue;
            }
        }
        LogBacktrackingFromNode(pfrom->nodeid, "  rgetblocks (%d, %.2f KB) stoppped at: %s due to no found\n",
            nTotalSendBlock, (float)nTotalSendSize/1024,
            hashBlock.ToPreViewString().c_str());
        break;
    }
}

bool GetBlockData(const uint256& hashBlock, CBlock& block, T_LOCALBLOCKADDRESS& addrblock)
{
    addrblock = T_LOCALBLOCKADDRESS();

    auto mi = mapBlockIndex[hashBlock];
    if (mi) {
        if (block.ReadFromDisk(mi)) {
            addrblock = mi->addr;
            return true;
        }
    }
    else if (LatestParaBlock::Count(hashBlock)) {
        CBlock block;
        BLOCKTRIPLEADDRESS tripleaddr;
        if (LatestParaBlock::GetBlock(hashBlock, block, tripleaddr)) {
            addrblock = tripleaddr.ToAddr();
            return true;
        }
    }
    else if (mapOrphanBlocks.count(hashBlock)) {
        block = *(mapOrphanBlocks[hashBlock]);
        return true;
    }

    printf("I have not Block: %s\n", hashBlock.ToPreViewString().c_str());
    return false;
}

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    static int nAskedForBlocks = 0;
    static map<unsigned int, vector<unsigned char> > mapReuseKey;
    RandAddSeedPerfmon();
    if (fDebug) {
        printf("%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
        printf("received: %s (%d bytes)\n", strCommand.c_str(), vRecv.size());
    }
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0) {
            // tell version,under udp environment, maybe node hasn't still received the verack message.
            printf("I had its version information,Maybe it has restarted, so update version. (%s)", pfrom->addr.ToString().c_str());
        }

        int64 nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64 nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (pfrom->nVersion >= 106 && !vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (pfrom->nVersion >= 106 && !vRecv.empty())
            vRecv >> pfrom->strSubVer;
        if (pfrom->nVersion >= 209 && !vRecv.empty())
            vRecv >> pfrom->nStartingHeight;

        if (pfrom->nVersion == 0)
            return false;

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        // Be shy and don't send version until we hear
        //if (pfrom->fInbound)
        //    pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr.ip, nTime);

        // Change version
        if (pfrom->nVersion >= 209)
            pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION));
        if (pfrom->nVersion < 209)
            pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (addrLocalHost.IsRoutable() && !fUseProxy)
            {
                CAddress addr(addrLocalHost);
                addr.nTime = GetAdjustedTime();
                pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->nVersion >= 31402 || mapAddresses.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
        }

        // Ask the first connected node for block updates
        if (!pfrom->fClient &&
            (pfrom->nVersion < 32000 || pfrom->nVersion >= 32400) &&
            //(nAskedForBlocks < 1 || vNodes.size() <= 1))
            (nAskedForBlocks < 1 || vNodes.size() <= 1))
        {
            nAskedForBlocks++;
            RequestBlockSpace(pfrom);
        }

        // Relay alerts
        CRITICAL_BLOCK(cs_mapAlerts)
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
            item.second.RelayTo(pfrom);

        pfrom->fSuccessfullyConnected = true;

        printf("version message: version %d, blocks=%d\n", pfrom->nVersion, pfrom->nStartingHeight);
    }
    else if (strCommand == "veragain") {
        pfrom->PushVersion();
        //if (nAskedForBlocks > 0) {
            //RequestBlockSpace(pfrom);
        //}
        //return true;
    }
    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        printf("I have not yet node version info, Maybe myself restarted, please tell me again. (%s)", pfrom->addr.ToString().c_str());
        pfrom->PushMessage("veragain");
        pfrom->nVersion = VERSION;
    }

    else if (strCommand == "verack")
    {
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));
    }
    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < 209)
            return true;
        if (pfrom->nVersion < 31402 && mapAddresses.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
            return ERROR_FL("message addr size() = %d", vAddr.size());

        // Store the new addresses
        CAddrDB addrDB;
        addrDB.TxnBegin();
        int64 nNow = GetAdjustedTime();
        int64 nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            if (fShutdown)
                return true;
            // ignore IPv6 for now, since it isn't implemented anyway
            if (!addr.IsIPv4())
                continue;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            AddAddress(addr, 2 * 60 * 60, &addrDB);
            pfrom->AddAddressKnown(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                CRITICAL_BLOCK(cs_vNodes)
                {
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        RAND_bytes((unsigned char*)&hashSalt, sizeof(hashSalt));
                    uint256 hashRand = hashSalt ^ (((int64)addr.ip) << 32) ^ ((GetTime() + addr.ip) / (24 * 60 * 60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < 31402)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = 2;
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
        }
        addrDB.TxnCommit();  // Save addresses (it's ok if this fails)
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > 50000)
            return ERROR_FL("message inv size() = %d", vInv.size());

        CTxDB_Wrapper txdb;
        BOOST_FOREACH(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);

            bool fAskFor = false;
            bool fPushGetBlocks = false;
            if (!fAlreadyHave) {
                pfrom->AskFor(inv);
                fAskFor = true;
            }
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
                fPushGetBlocks = true;
            }

            if (fDebug) {
                printf("  got inventory: %s  %s, askfor: %s pushPutBlocks: %s\n", inv.ToString().c_str(),
                    fAlreadyHave ? "have" : "new",
                    fAskFor ? "yes" : "no",
                    fPushGetBlocks ? "yes" : "no");
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }

    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > 50000)
            return ERROR_FL("message getdata size() = %d", vInv.size());

        //outputlog(strprintf("Received getdata %d \n", vInv.size()));

        std::set<uint256> setBlockSended; 
        BOOST_FOREACH(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            //outputlog(strprintf("received getdata for: %s\n", inv.ToString().c_str()));

            printf("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK) {
                // Send block from disk
                CBlock block;
                T_LOCALBLOCKADDRESS addrblock;
                if (!setBlockSended.count(inv.hash) && GetBlockData(inv.hash, block, addrblock)) {
                    //outputlog(strprintf("reply block: %d, %s\n", block.nHeight, addrblock.tostring().c_str()));

                    pfrom->PushMessage("block", block, addrblock.hid, addrblock.chainnum, addrblock.id);
                    setBlockSended.insert(inv.hash);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue) {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType()) {
                // Send stream from relay memory
                CRITICAL_BLOCK(cs_mapRelay)
                {
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end())
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                }
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }
    else if (strCommand == "rgetblocks") {
        uint256 hashBlock;
        vRecv >> hashBlock;

        ReplyRGetBlocks(pfrom, hashBlock);
    }
    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndexSP pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext();
        int nLimit = 25; //500 +locator.GetDistanceBack();
        unsigned int nBytes = 0;
        printf("\n\nRespond**************************************\n");
        printf("getblocks %d to %s limit %d from node: %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0, 20).c_str(),
            nLimit,
            pfrom->nodeid.c_str());
        for (; pindex; pindex = pindex->pnext())
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks stopping at %d %s (%u bytes)\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0, 20).c_str(), nBytes);
                break;
            }

            CBlock block;
            if (!block.ReadFromDisk(pindex, true)) {
                continue;
            }

            printf("getblocks send %s(%s) to node: %s\n", pindex->GetBlockHash().ToPreViewString().c_str(),
                pindex->addr.tostring().c_str(),
                pfrom->nodeid.c_str());
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            nBytes += block.GetSerializeSize(SER_NETWORK);
            if (--nLimit <= 0 || nBytes >= SendBufferSize())
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s (%u bytes)\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0, 20).c_str(), nBytes);
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }


    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndexSP pindex;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            auto mi = mapBlockIndex[hashStop];
            if (!mi)
                return true;
            pindex = mi;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext();
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000 + locator.GetDistanceBack();
        printf("getheaders %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0, 20).c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext())
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool fMissingInputs = false;
        if (tx.AcceptToMemoryPool(true, &fMissingInputs))
        {
            SyncWithWallets(tx, NULL, true);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(hashPrev);
                    mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev);
                    ++mi)
                {
                    const CDataStream& vMsg = *((*mi).second);
                    CTransaction tx;
                    CDataStream(vMsg) >> tx;
                    CInv inv(MSG_TX, tx.GetHash());

                    if (tx.AcceptToMemoryPool(true))
                    {
                        printf("   accepted orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
                        SyncWithWallets(tx, NULL, true);
                        RelayMessage(inv, vMsg);
                        mapAlreadyAskedFor.erase(inv);
                        vWorkQueue.push_back(inv.hash);
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vWorkQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            printf("storing orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
            AddOrphanTx(vMsg);
        }
    }

    else if (strCommand == "rblock") {

        CBlock block;
        vRecv >> block;

        BLOCKTRIPLEADDRESS tripleaddr;

        vRecv >> tripleaddr.hid;  
        vRecv >> tripleaddr.chainnum;
        vRecv >> tripleaddr.id;

        T_LOCALBLOCKADDRESS addrblock = tripleaddr.ToAddr();
        auto blkhash = block.GetHash();
        LogBacktracking("rblock: Received block %s from %s(Score:%d), triple address: %s\n", blkhash.ToString().substr(0, 20).c_str(),
            pfrom->nodeid.c_str(), pfrom->nScore, addrblock.tostring().c_str());

        if (ProcessBlock(pfrom, &block)) {
            if (addrblock.isValid()) {
                if (mapBlockIndex.count(blkhash)) {
                    CBlockIndexSP pIndex = mapBlockIndex[blkhash];
                    if (pIndex->addr != addrblock) {
                        block.UpdateToBlockIndex(pIndex, addrblock);
                    }
                }
            }
            pfrom->nScore++;
        }
    }
    else if (strCommand == "block")
    {
        CBlock block;
        vRecv >> block;

        T_LOCALBLOCKADDRESS addrblock;

        vRecv >> addrblock.hid;  
        vRecv >> addrblock.chainnum;
        vRecv >> addrblock.id;

        printf("Received block %s from %s, triple address: %s\n", block.GetHash().ToString().substr(0, 20).c_str(),
            pfrom->nodeid.c_str(), addrblock.tostring().c_str());

        CInv inv(MSG_BLOCK, block.GetHash());
        pfrom->AddInventoryKnown(inv);

        if (ProcessBlock(pfrom, &block, &addrblock))
            mapAlreadyAskedFor.erase(inv);
    }


    else if (strCommand == "getaddr")
    {
        // Nodes rebroadcast an addr every 24 hours
        pfrom->vAddrToSend.clear();
        int64 nSince = GetAdjustedTime() - 3 * 60 * 60; // in the last 3 hours
        CRITICAL_BLOCK(cs_mapAddresses)
        {
            unsigned int nCount = 0;
            BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            {
                const CAddress& addr = item.second;
                if (addr.nTime > nSince)
                    nCount++;
            }
            BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            {
                const CAddress& addr = item.second;
                if (addr.nTime > nSince && GetRand(nCount) < 2500)
                    pfrom->PushAddress(addr);
            }
        }
    }


    else if (strCommand == "checkorder")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        if (!GetBoolArg("-allowreceivebyip"))
        {
            pfrom->PushMessage("reply", hashReply, (int)2, string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr.ip))
            pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr.ip], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr.ip] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        CRITICAL_BLOCK(pfrom->cs_mapRequests)
        {
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else if (strCommand == "ping")
    {
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        if (alert.ProcessAlert())
        {
            // Relay
            pfrom->setKnown.insert(alert.GetHash());
            CRITICAL_BLOCK(cs_vNodes)
                BOOST_FOREACH(CNode* pnode, vNodes)
                alert.RelayTo(pnode);
        }
    }
    else if (strCommand == "checkblock")
    {
        vRecv >> pfrom->nHeightCheckPointBlock;
        vRecv >> pfrom->hashCheckPointBlock;

        printf("received check point block: %d, %s from %s\n",
            pfrom->nHeightCheckPointBlock, pfrom->hashCheckPointBlock.ToPreViewString().c_str(), pfrom->nodeid.c_str());

        g_blockChckPnt.Set(pfrom->nHeightCheckPointBlock, pfrom->hashCheckPointBlock);

    }
    else if (strCommand == "getchkblock")
    {
        printf("getchkblock from %s\n", pfrom->nodeid.c_str());
        CRITICAL_BLOCK_T_MAIN(cs_main)
        {
            CBlockIndexSimplified* pIndex = LatestParaBlock::Get();
            if (!pIndex) {
                return true;
            }

            uint256 hash = pIndex->GetBlockHash();
            pfrom->PushMessage("checkblock", pIndex->nHeight, hash);

            printf("getchkblock reply: %d %s from %s\n", pIndex->nHeight, hash.ToPreViewString().c_str(),
                pfrom->nodeid.c_str());
        }
    }
    else
    {
        // Ignore unknown commands for extensibility
    }

    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


    return true;
}

bool ProcessMessages(CNode* pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty())
        return true;
    //if (fDebug)
    //    printf("ProcessMessages(%u bytes)\n", vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //

    loop
    {
        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
        if (vRecv.end() - pstart < nHeaderSize)
        {
            if (vRecv.size() > nHeaderSize)
            {
                printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            printf("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", pstart - vRecv.begin());
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
        CMessageHeader hdr;
        vRecv >> hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > MAX_SIZE)
        {
            printf("ProcessMessage(%s, %u bytes) : nMessageSize > MAX_SIZE\n", strCommand.c_str(), nMessageSize);
            continue;
        }
        if (nMessageSize > vRecv.size())
        {
            // Rewind and wait for rest of message
            vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
            break;
        }

        // Checksum
        if (vRecv.GetVersion() >= 209)
        {
            uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
            unsigned int nChecksum = 0;
            memcpy(&nChecksum, &hash, sizeof(nChecksum));
            if (nChecksum != hdr.nChecksum)
            {
                printf("ProcessMessage(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
                       strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
                continue;
            }
        }

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try {
            CRITICAL_BLOCK_T_MAIN(cs_main)
            {
                hyperblockMsgs.process();
                fRet = ProcessMessage(pfrom, strCommand, vMsg);
            }

            if (fShutdown)
                return true;
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from underlength message on vRecv
                printf("ProcessMessage(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from overlong size
                printf("ProcessMessage(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessage()");
            }
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessage()");
        }
        catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessage()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
    }

    vRecv.Compact();
    return true;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSend.empty())
            pto->PushMessage("ping");

        // Resend wallet transactions that haven't gotten in a block yet
        ResendWalletTransactions();

        // Address refresh broadcast
        static int64 nLastRebroadcast;
        if (GetTime() - nLastRebroadcast > 24 * 60 * 60)
        {
            nLastRebroadcast = GetTime();
            CRITICAL_BLOCK(cs_vNodes)
            {
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (addrLocalHost.IsRoutable() && !fUseProxy)
                    {
                        CAddress addr(addrLocalHost);
                        addr.nTime = GetAdjustedTime();
                        pnode->PushAddress(addr);
                    }
                }
            }
        }

        // Clear out old addresses periodically so it's not too much work at once
        static int64 nLastClear;
        if (nLastClear == 0)
            nLastClear = GetTime();
        if (GetTime() - nLastClear > 10 * 60 && vNodes.size() >= 3)
        {
            nLastClear = GetTime();
            CRITICAL_BLOCK(cs_mapAddresses)
            {
                CAddrDB addrdb;
                int64 nSince = GetAdjustedTime() - 14 * 24 * 60 * 60;
                for (map<vector<unsigned char>, CAddress>::iterator mi = mapAddresses.begin();
                    mi != mapAddresses.end();)
                {
                    const CAddress& addr = (*mi).second;
                    if (addr.nTime < nSince)
                    {
                        if (mapAddresses.size() < 1000 || GetTime() > nLastClear + 20)
                            break;
                        addrdb.EraseAddress(addr);
                        mapAddresses.erase(mi++);
                    }
                    else
                        mi++;
                }
            }
        }


        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }


        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        CRITICAL_BLOCK(pto->cs_inventory)
        {
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                //if (pto->setInventoryKnown.count(inv))
                //    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        RAND_bytes((unsigned char*)&hashSalt, sizeof(hashSalt));
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                //printf("  setInventoryKnown size: %u  pto: %s\n", pto->setInventoryKnown.size(), pto->nodeid.c_str());
                //if (pto->setInventoryKnown.insert(inv).second)
                {
                    if (fDebug)
                        printf("  send inventory: %s to: %s\n", inv.ToString().c_str(), pto->nodeid.c_str());

                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64 nNow = GetTime() * 1000000;
        CTxDB_Wrapper txdb;
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 20)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            mapAlreadyAskedFor[inv] = nNow;
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

    }
    return true;
}














//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

using CryptoPP::ByteReverse;

static const unsigned int pSHA256InitState[8] =
{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

inline void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    memcpy(pstate, pinit, 32);
    CryptoPP::SHA256::Transform((CryptoPP::word32*)pstate, (CryptoPP::word32*)pinput);
}

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// It operates on big endian data.  Caller does the byte reversing.
// All input buffers are 16-byte aligned.  nNonce is usually preserved
// between calls, but periodically or if nNonce is 0xffff0000 or above,
// the block is rebuilt and nNonce starts over at zero.
//
unsigned int static ScanHash_CryptoPP(char* pmidstate, char* pdata, char* phash1, char* phash, unsigned int& nHashesDone)
{
    unsigned int& nNonce = *(unsigned int*)(pdata + 12);
    for (;;)
    {
        // Crypto++ SHA-256
        // Hash pdata using pmidstate as the starting state into
        // preformatted buffer phash1, then hash phash1 into phash
        nNonce++;
        SHA256Transform(phash1, pdata, pmidstate);
        SHA256Transform(phash, phash1, pSHA256InitState);

        if (((unsigned short*)phash)[14] == 0)
            return nNonce;

        if ((nNonce & 0xffff) == 0)
        {
            nHashesDone = 0xffff + 1;
            return -1;
        }
    }
}

class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f)\n", ptx->GetHash().ToString().substr(0, 10).c_str(), dPriority);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().substr(0, 10).c_str());
    }
};


void ReadTrans(map<uint256, CTransaction>& mapTrans)
{
    string txfilename = mapArgs["-importtx"];

    uint32_t genesisHID;
    uint32_t genesisChainNum;
    uint32_t genesisID;

    using PUBKEY = std::vector<unsigned char>;
    map<PUBKEY, int64> mapPubKeyWallet;

    FILE* fp = std::fopen(txfilename.c_str(), "r");
    if (!fp) {
        throw runtime_error(strprintf("cannot open file: %s\n", txfilename.c_str()));
    }

    int rs = std::fscanf(fp, "Triple address: %u %u %u", &genesisHID, &genesisChainNum, &genesisID);
    cout << strprintf("Got old chain genesis block triple address: %u %u %u\n", genesisHID, genesisChainNum, genesisID);

    int64 nCount = 0;
    for (;; nCount++) {
        if (nCount % 100 == 0) {
            cout << ">";
        }

        int64 nValue = 0;
        char pubkey[512] = {0};

        rs = std::fscanf(fp, "%s : %llu", pubkey, &nValue);
        if (rs == EOF) {
            break;
        }

        PUBKEY vchPubKey = ParseHex(pubkey);
        if (mapPubKeyWallet.count(vchPubKey)) {
            mapPubKeyWallet[vchPubKey] += nValue;
        }
        else {
            mapPubKeyWallet.insert(make_pair(vchPubKey, nValue));
        }
    }

    if (std::ferror(fp)) {
        throw runtime_error(strprintf("I/O error when reading transaction file: %s\n", txfilename.c_str()));
    }
    std::fclose(fp);

    cout << strprintf("\nGot %u transactions\n", mapPubKeyWallet.size());

    for (auto& elm : mapPubKeyWallet) {
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        txNew.vout.resize(1);
        txNew.vout[0].scriptPubKey << elm.first << OP_CHECKSIG;

        txNew.vout[0].nValue = elm.second;

        mapTrans[txNew.GetHash()] = txNew;
    }
}

CBlock* CreateBlockBuiltIn(CReserveKey& reservekey, int& nTxCountInblock)
{
    CBlock* pblock = new CBlock();
    if (!pblock)
        return NULL;

    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

    pblock->vtx.push_back(txNew);

    int64 nFees = 0;
    CRITICAL_BLOCK_T_MAIN(cs_main)
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        uint64 nBlockSize = 1000;
        int nBlockSigOps = 100;

        for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end();) {
            CTransaction& tx = (*mi).second;

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK);
            if (nBlockSize + nTxSize >= (MAX_BLOCK_SIZE - 2048))
                break;
            int nTxSigOps = tx.GetSigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                break;

            // Added
            nTxCountInblock++;
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            nBlockSigOps += nTxSigOps;

            mapTransactions.erase(mi++);
        }
    }
    return pblock;
}

void UpdateBlockBuiltIn(CBlock* pblock)
{
    CRITICAL_BLOCK_T_MAIN(cs_main)
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        pblock->SetHyperBlockInfo();
        CBlockIndex* pindexPrev = pindexBest.get();
        pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->nHeight + 1, 0);

        uint256 nonce;
        nonce = GetRandHash();

        nonce <<= 32;
        nonce >>= 16;

        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
        pblock->nHeight = pindexPrev->nHeight + 1;
        memset(pblock->nReserved, 0, sizeof(pblock->nReserved));

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
        pblock->nBits = 0x2100ffff;// GetNextWorkRequired(pindexPrev);
        pblock->nNonce = nonce.GetUint64(3);
        pblock->nSolution.clear();
    }
}

CBlock* CreateNewBlock(CReserveKey& reservekey)
{
    auto_ptr<CBlock> pblock(new CBlock());
    if (!pblock.get())
        return NULL;

    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

    pblock->vtx.push_back(txNew);

    int64 nFees = 0;
    CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            pblock->SetHyperBlockInfo();
            CBlockIndexSP pindexPrev = pindexBest;
            CTxDB_Wrapper txdb;

            list<COrphan> vOrphan;          // list memory doesn't move
            map<uint256, vector<COrphan*> > mapDependers;
            multimap<double, CTransaction*> mapPriority;
            for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi)
            {
                CTransaction& tx = (*mi).second;
                if (tx.IsCoinBase() || !tx.IsFinal())
                    continue;

                COrphan* porphan = NULL;
                double dPriority = 0;
                BOOST_FOREACH(const CTxIn & txin, tx.vin)
                {
                    CTransaction txPrev;
                    CTxIndex txindex;
                    CBlockIndex idxBlock;
                    if (!txdb.ReadTxIndex(txin.prevout.hash, txindex))
                        continue;

                    bool istxok = false;
                    if (txindex.pos.addr.isValid()) {
                        istxok = txPrev.ReadFromDisk(txdb, txin.prevout, txindex);
                    }
                    else {
                        istxok = SeachTxInUnchainedBlocks(txin.prevout.hash, txPrev, idxBlock);
                    }
                    if (!istxok) {
                        if (!porphan)
                        {
                            // Use list for automatic deletion
                            vOrphan.push_back(COrphan(&tx));
                            porphan = &vOrphan.back();
                        }
                        mapDependers[txin.prevout.hash].push_back(porphan);
                        porphan->setDependsOn.insert(txin.prevout.hash);
                        continue;
                    }
                    int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;

                    // Read block header
                    int nConf = txindex.GetDepthInMainChain();

                    dPriority += (double)nValueIn * nConf;

                    if (fDebug && GetBoolArg("-printpriority"))
                        printf("priority     nValueIn=%-12I64d nConf=%-5d dPriority=%-20.1f\n", nValueIn, nConf, dPriority);
                }

                // Priority is sum(valuein * age) / txsize
                dPriority /= ::GetSerializeSize(tx, SER_NETWORK);

                if (porphan)
                    porphan->dPriority = dPriority;
                else
                    mapPriority.insert(make_pair(-dPriority, &(*mi).second)); 

                if (fDebug && GetBoolArg("-printpriority"))
                {
                    printf("priority %-20.1f %s\n%s", dPriority, tx.GetHash().ToString().substr(0, 10).c_str(), tx.ToString().c_str());
                    if (porphan)
                        porphan->print();
                    printf("\n");
                }
            }

            map<uint256, CTxIndex> mapTestPool;
            uint64 nBlockSize = 1000;
            int nBlockSigOps = 100;
            while (!mapPriority.empty())
            {
                double dPriority = -(*mapPriority.begin()).first;
                CTransaction& tx = *(*mapPriority.begin()).second;
                mapPriority.erase(mapPriority.begin());

                // Size limits
                unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK);
                if (nBlockSize + nTxSize >= MAX_BLOCK_SIZE_GEN)
                    continue;
                int nTxSigOps = tx.GetSigOpCount();
                if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                    continue;

                bool fAllowFree = (nBlockSize + nTxSize < 4000 || CTransaction::AllowFree(dPriority));
                int64 nMinFee = tx.GetMinFee(nBlockSize, fAllowFree, true);

                map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
                if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1), pindexPrev, nFees, false, true, nMinFee))
                    continue;
                swap(mapTestPool, mapTestPoolTmp);

                // Added
                pblock->vtx.push_back(tx);
                nBlockSize += nTxSize;
                nBlockSigOps += nTxSigOps;

                uint256 hash = tx.GetHash();
                if (mapDependers.count(hash))
                {
                    BOOST_FOREACH(COrphan * porphan, mapDependers[hash])
                    {
                        if (!porphan->setDependsOn.empty())
                        {
                            porphan->setDependsOn.erase(hash);
                            if (porphan->setDependsOn.empty())
                                mapPriority.insert(make_pair(-porphan->dPriority, porphan->ptx));
                        }
                    }
                }
            }

            pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->nHeight + 1, nFees);

            uint256 nonce;
            nonce = GetRandHash();
            nonce <<= 32;
            nonce >>= 16;

            pblock->hashPrevBlock = pindexPrev->GetBlockHash();
            pblock->nHeight = pindexPrev->nHeight + 1;
            memset(pblock->nReserved, 0, sizeof(pblock->nReserved));

            pblock->hashMerkleRoot = pblock->BuildMerkleTree();
            pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
            pblock->nBits = GetNextWorkRequired(pindexPrev);
            pblock->nNonce = nonce.GetUint64(3);
            pblock->nSolution.clear();
        }
    }
    /*
    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    */

    return pblock.release();
}


bool CommitChainToConsensus(deque<CBlock>& deqblock, string &requestid, string &errmsg)
{
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();

    vector<string> vecMTRootHash;
    vector<string> vecpayload;
    vector<CUInt128> vecNodeId;

    uint32_t hid = g_cryptoCurrency.GetHID();
    uint16 chainnum = g_cryptoCurrency.GetChainNum();
    uint16 localid = g_cryptoCurrency.GetLocalID();

    if (consensuseng) {
        CDataStream datastream(SER_BUDDYCONSENSUS);
        size_t num = deqblock.size();
        for (size_t i = 0; i < num; ++i) {

            datastream.clear();
            datastream << deqblock[i];

            vecpayload.push_back(datastream.str());

            datastream.clear();
            datastream << deqblock[i].hashMerkleRoot;
            vecMTRootHash.push_back(datastream.str());

            vecNodeId.push_back(deqblock[i].ownerNodeID);
        }

        if (consensuseng->AddChainEx(T_APPTYPE(APPTYPE::paracoin, hid, chainnum, localid), vecMTRootHash, vecpayload, vecNodeId)) {
            printf("Add a paracoin chain to consensus layer: %d\n", vecpayload.size());
        }
        return true;
    }
    else {
        errmsg = "Cannot commit chain to consensus, Consensus engine is stopped\n";
    }
    return false;

}


bool CommitGenesisToConsensus(CBlock *pblock, string &requestid, string &errmsg)
{
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        CDataStream datastream(SER_BUDDYCONSENSUS);
        datastream << *pblock;

        string payload = datastream.str();

        datastream.clear();
        datastream << pblock->hashMerkleRoot;

        if (consensuseng->AddNewBlockEx(T_APPTYPE(APPTYPE::paracoin, 0, 0, 0), datastream.str(), payload, requestid)) {
            printf("Add a paracoin block to consensus layer, requestid: %s\n", requestid.c_str());
        }
        return true;
    }
    else {
        errmsg = "Cannot commit consensus, Consensus engine is stopped\n";
    }
    return false;
}

void IncrementExtraNonce(CBlock* pblock, unsigned int& nExtraNonce)
{
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    pblock->vtx[0].vin[0].scriptSig = CScript() << pblock->nTime << CBigNum(nExtraNonce);
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Prebuild hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            uint256 nNonce;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion = pblock->nVersion;
    tmp.block.hashPrevBlock = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime = pblock->nTime;
    tmp.block.nBits = pblock->nBits;
    tmp.block.nNonce = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    for (int i = 0; i < sizeof(tmp) / 4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hash = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if (hash > hashTarget)
        return false;


    //// debug print
    printf("\nproof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("%s ", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()).c_str());
    printf("generated %s\n\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    CRITICAL_BLOCK_T_MAIN(cs_main)
    {
        if (pblock->hashPrevBlock != hashBestChain)
            return WARNING_FL("generated block is stale");

        if (!pblock->IsLastestHyperBlockMatched())
            return WARNING_FL("generated block's hyper block is stale");

        reservekey.KeepKey();

        CRITICAL_BLOCK(wallet.cs_wallet)
            wallet.mapRequestCount[pblock->GetHash()] = 0;

        if (!ProcessBlock(NULL, pblock))
            return ERROR_FL("ProcessBlock, block not accepted");
    }

    Sleep(2000);
    return true;
}

extern std::function<void(int)> SleepFn;

void PutTxIntoTxPool(map<uint256, CTransaction>& mapTrans)
{
    CTxDB_Wrapper txdb;
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        mapTransactions.clear();
        auto iter = mapTrans.begin();
        for (; iter != mapTrans.end(); ) {

            iter->second.AddToMemoryPoolUnchecked();
            ++iter;
            continue;

            //uint256 hash = iter->first;
            //if (!txdb.ContainsTx(hash)) {
            //    iter->second.AddToMemoryPoolUnchecked();
            //    ++iter;
            //}
            //else {
            //    cout << strprintf("The Transaction has already chained: %s\n", iter->second.vout[0].ToString().c_str());
            //    iter = mapTrans.erase(iter);
            //}
        }
    }
}

void static BuiltInMiner(CWallet* pwallet)
{
    CReserveKey reservekey(pwallet);

    map<uint256, CTransaction> mapTrans;

    try {
        ReadTrans(mapTrans);
    }
    catch (runtime_error* e) {
        ERROR_FL("%s", e->what());
        return;
    }

    //A block contains 7850 transactions;
    PutTxIntoTxPool(mapTrans);

    unsigned int nExtraNonce = 0;
    for (; !fShutdown ;) {

        if (!mapTransactions.size()) {
            break;
        }

        cout << "Create all built-in blocks...\n";

        int nTxCountInblock = 0;

        using SPBLOCK = std::shared_ptr<CBlock>;
        std::map<int, SPBLOCK> mapBlockBuiltIn;

        int i = 0;
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            for (; mapTransactions.size() > 0;) {
                SPBLOCK blk(CreateBlockBuiltIn(reservekey, nTxCountInblock));
                cout << strprintf("%u transactions in the block created, left %u in transaction pool\n",
                    nTxCountInblock, mapTransactions.size());

                mapBlockBuiltIn.insert(std::make_pair(i++, blk));
            }
        }

        size_t nCount = mapBlockBuiltIn.size();
        cout << strprintf("Mining for %u built-in blocks...\n", nCount);
        cout << "Very Important: Please make sure new hyper block created haven't replaced by one from other nodes\n";

        while (!g_miningCond.EvaluateIsAllowed(false)) {
            SleepFn(2);
            if (fShutdown)
                return;
            if (!fGenerateBitcoins)
                return;
        }

        CRITICAL_BLOCK_T_MAIN(cs_main)
        {
            if (pindexBest->nHeight > 0) {
                SwitchChainTo(pindexGenesisBlock);
                cout << strprintf("Chain best block: height:%u, hash:%s  PrevHid:%u PreHHash: %s\n",
                    pindexBest->nHeight,
                    pindexBest->GetBlockHash().ToPreViewString().c_str(),
                    pindexGenesisBlock->nPrevHID,
                    pindexBest->hashPrevHyperBlock.ToPreViewString().c_str());
            }

            if (pindexBest->nHeight != 0) {
                cout << "cannot switch to genesis block,program will exit\n";
                exit(-1);
            }
        }

        for (i = 0; i < nCount && !fShutdown; i++) {

            auto spBlk = mapBlockBuiltIn[i];
            UpdateBlockBuiltIn(spBlk.get());
            IncrementExtraNonce(spBlk.get(), nExtraNonce);

            cout << strprintf("Mining for new block: height:%u, PrevHid:%u PreHHash: %s\n",
                spBlk->nHeight,
                spBlk->nPrevHID,
                spBlk->hashPrevHyperBlock.ToPreViewString().c_str());

            progpow::search_result r;
            while (DoMining(*spBlk.get(), r)) {

                CCriticalBlockT<pcstName> criticalblock(cs_main, __FILE__, __LINE__);
                if (spBlk.get()->hashPrevBlock != hashBestChain || !spBlk.get()->IsLastestHyperBlockMatched()) {

                    if (spBlk.get()->hashPrevBlock != hashBestChain) {
                        cout << "\tgenerated block is stale,try again...\n";
                    }
                    else {
                        cout << "\tgenerated block's hyper block is stale,try again...\n";
                    }

                    CBlockIndexSP pIndex = LatestBlockIndexOnChained();
                    cout << strprintf("Switch best chain to height %u\n", pIndex->nHeight);
                    if (!SwitchChainTo(pIndex)) {
                        cout << strprintf("Failed to Switch best chain to height %u, program will exit\n", pIndex->nHeight);
                        exit(-1);
                    }

                    i = pIndex->nHeight - 1;
                    break;
                }

                if (!ProcessBlock(NULL, spBlk.get())) {
                    cout << "\tProcessBlock, block not accepted,try again...\n";
                    i--;
                    break;
                }

                reservekey.KeepKey();

                break;
            }
        }
    }

    g_isBuiltInBlocksReady = true;
    cout << "BuiltInMiner thread exited, submitting built-in blocks \n";
}

void static ThreadBitcoinMiner(void* parg);


void static BitcoinMiner(CWallet *pwallet)
{
    printf("ParacoinMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;


    while (fGenerateBitcoins)
    {
        if (AffinityBugWorkaround(ThreadBitcoinMiner))
            return;
        if (fShutdown)
            return;

        string reason;
        while (!g_miningCond.EvaluateIsAllowed()) {
            if (g_miningCond.IsSwitching())
                Sleep(100);
            else
                SleepFn(2);

            if (fShutdown)
                return;
            if (!fGenerateBitcoins)
                return;
        }

        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;

        auto_ptr<CBlock> pblock(CreateNewBlock(reservekey));
        if (!pblock.get())
            return;
        IncrementExtraNonce(pblock.get(), nExtraNonce);

        printf("Running ParacoinMiner with %d transactions in block\n", pblock->vtx.size());


        CBigNum bnNew;
        bnNew.SetCompact(pblock->nBits);
        uint256 hashTarget = bnNew.getuint256();

        ethash::hash256 target;
        std::reverse_copy(hashTarget.begin(), hashTarget.end(), target.bytes);

        ethash::hash256 header_hash = pblock->GetHeaderHash();

        uint64_t start_nonce = pblock->nNonce;
        uint32_t epoch = ethash::get_epoch_number(pblock->nHeight);
        ethash_epoch_context epoch_ctx = ethash::get_global_epoch_context(epoch);

       for(;;) {
            uint64_t nMaxTries = 1000000;

            int64 nStart = GetTime();
            auto r = progpow::search_light(epoch_ctx, pblock->nHeight, header_hash, target, start_nonce, nMaxTries,
                [&nStart, &nTransactionsUpdatedLast]() {
                    if (fShutdown || !g_cryptoCurrency.AllowMining() ) {
                        return true;
                    }
                    if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 20) {
                        return true;
                    }
                    return false;
                });
            if (r.solution_found) {
                pblock->nNonce = r.nonce;

                pblock->nSolution.resize(sizeof(r.mix_hash.bytes));
                memcpy(pblock->nSolution.data(), r.mix_hash.bytes, sizeof(r.mix_hash.bytes));

                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                CheckWork(pblock.get(), *pwalletMain, reservekey);
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
                break;
            }
            else {
                if (fShutdown)
                    return;
                if (!fGenerateBitcoins)
                    return;
                if (fLimitProcessors && vnThreadsRunning[3] > nLimitProcessors)
                    return;
                break;
            }
        }
    }
}

void static ThreadBitcoinMiner(void* parg)
{
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        vnThreadsRunning[3]++;
        if(mapArgs.count("-importtx"))
            BuiltInMiner(pwallet);
        else
            BitcoinMiner(pwallet);
        vnThreadsRunning[3]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[3]--;
        PrintException(&e, "ThreadParacoinMiner()");
    }
    catch (...) {
        vnThreadsRunning[3]--;
        PrintException(NULL, "ThreadParacoinMiner()");
    }
    UIThreadCall(boost::bind(CalledSetStatusBar, "", 0));
    nHPSTimerStart = 0;
    if (vnThreadsRunning[3] == 0)
        dHashesPerSec = 0;
    printf("ThreadParacoinMiner exiting, %d threads remaining\n", vnThreadsRunning[3]);
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    if (fGenerateBitcoins != fGenerate)
    {
        fGenerateBitcoins = fGenerate;
        WriteSetting("fGenerateBitcoins", fGenerateBitcoins);
        MainFrameRepaint();
    }
    if (fGenerateBitcoins)
    {
        int nProcessors = boost::thread::hardware_concurrency();
        printf("%d processors\n", nProcessors);
        if (nProcessors < 1)
            nProcessors = 1;
        if (fLimitProcessors && nProcessors > nLimitProcessors)
            nProcessors = nLimitProcessors;
        int nAddThreads = nProcessors - vnThreadsRunning[3];

        //printf("Starting %d ParacoinMiner threads\n", nAddThreads);
        printf("Starting ParacoinMiner thread\n");
        //for (int i = 0; i < nAddThreads; i++)
        {
            if (!CreateThread(ThreadBitcoinMiner, pwallet))
                printf("Error: CreateThread(ThreadParacoinMiner) failed\n");
            Sleep(10);
        }
    }
}

void FreeGlobalMemeory()
{
    mapBlockIndex.clear();

    mapTransactions.clear();

    mapOrphanBlocksByPrev.clear();
    for (auto mi = mapOrphanBlocks.begin(); mi != mapOrphanBlocks.end(); ++mi) {
        delete mi->second;
    }
    mapOrphanBlocks.clear();

    mapOrphanTransactionsByPrev.clear();
    for (auto mi = mapOrphanTransactions.begin(); mi != mapOrphanTransactions.end(); ++mi) {
        delete mi->second;
    }
    mapOrphanTransactions.clear();

    mapBlocks.clear();
}

void ReInitSystemRunningEnv()
{
    fExit = false;
    fShutdown = false;

    hashBestChain = 0;
    hashGenesisBlock = 0;
    pindexGenesisBlock = nullptr;
    pindexBest = nullptr;

    FreeGlobalMemeory();

    if (dbenv.get()) {
        dbenv->close(0);
    }

    dbenv.reset(new DbEnv(0));
}


void LatestParaBlock::Load()
{
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    uint64 maxHID = hyperchainspace->GetMaxBlockID();

    _pindexLatestRoot = nullptr;
    LoadLatestBlock();

    vector<T_PAYLOADADDR> vecPA;
    T_SHA256 thhash;
    uint32_t genesisHID = g_cryptoCurrency.GetHID();

    const uint16 nMaturity = 16;
    uint32_t bestHID = genesisHID;  

    CBlockTripleAddressDB btadb("cr+");
    btadb.LoadBlockTripleAddress();

    std::set<uint32_t> setHID;
    btadb.ReadHID(setHID);

    uint64_t totalnum = maxHID >= bestHID ? (maxHID - bestHID + 1) : 0;
    uint64_t progress = 0;
    T_APPTYPE app(APPTYPE::paracoin, genesisHID, g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID());

    cout << "Paracoin: scanning "<< totalnum <<" Hyperblocks on disk: " << endl;

    bool is_informal_network = false;
    if (mapArgs.count("-model")) {
        if (mapArgs["-model"] == "informal") {
            is_informal_network = true;
        }
    }

    std::set<uint64_t> setMyHIDInDB;
    hyperchainspace->GetLocalHIDs(bestHID, setMyHIDInDB);
    auto iter = setMyHIDInDB.begin();
    for (; iter != setMyHIDInDB.end() && *iter < maxHID; ++iter) {

        uint64_t cuurprogress = (*iter - bestHID + 1) * 100 / totalnum;
        if (progress < cuurprogress) {
            if (progress % 2 == 0) {
                cout << ">";
            }
            progress = cuurprogress;
        }

        if (setHID.find(*iter) != setHID.end())
            continue;

        if (is_informal_network  && (*iter > 22008 && *iter <= 48601)) {
            continue;
        }

        vecPA.clear();
        if (hyperchainspace->GetLocalBlocksByHID(*iter, app, thhash, vecPA)) {
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {
                CBlock block;
                if (!ResolveBlock(block, pa->payload.c_str(), pa->payload.size())) {
                    continue;
                }
                uint256 hashBlock = block.GetHash();
                _mapBlockAddressOnDisk.insert(btadb, hashBlock, BLOCKTRIPLEADDRESS(pa->addr));
            }
        }
        btadb.WriteHID(*iter);
    }

    btadb.Close();
    cout << " Paracoin blocks scanned"  << endl;
}

void LatestParaBlock::CompareAndUpdate(const vector<BLOCKTRIPLEADDRESS>& vecAddrIn, const vector<CBlock>& vecBlockIn, bool isLatest)
{
    CBlockTripleAddressDB btadb;

    uint32 hid = LatestHyperBlock::GetHID();
    size_t len = vecBlockIn.size();

    for (size_t i = 0; i < len; i++) {
        uint256 hashBlock = vecBlockIn[i].GetHash();
        if (!_mapBlockAddressOnDisk.contain(hashBlock)) {
            _mapBlockAddressOnDisk.insert(btadb, hashBlock, vecAddrIn[i]);
        }

        if (_mapBlockIndexLatest.count(hashBlock)) {
            _mapBlockIndexLatest[hashBlock]->addr = vecAddrIn[i].ToAddr();
            continue;
        }
    }
    if (len > 0) {
        btadb.WriteHID(vecAddrIn[0].hid);
    }
    btadb.Close();

    if (isLatest) {
        for (size_t i = 0; i < len; i++) {
            const uint256& hashPrev = vecBlockIn[i].hashPrevBlock;
            if ( _pindexLatest->GetBlockHash() == hashPrev) {
                SetBestIndex(AddBlockIndex(vecAddrIn[i].ToAddr(), vecBlockIn[i]));
            }
            else {
                _pindexLatestRoot = InsertBlockIndex(hashPrev);
                SetBestIndex(AddBlockIndex(vecAddrIn[i].ToAddr(), vecBlockIn[i]));
            }
        }
    }
}


string LatestParaBlock::GetMemoryInfo()
{
    return strprintf("LatestParaBlock's mapBlockAddressOnDisk size: %u\n"
        "LatestParaBlock's mapBlockIndexLatest size: %u\n",
        _mapBlockAddressOnDisk.size(), _mapBlockIndexLatest.size());
}


bool LatestParaBlock::Count(const uint256& hastblock)
{
    return _mapBlockAddressOnDisk.contain(hastblock) ||
        (_mapBlockIndexLatest.count(hastblock) && hastblock != GetBackSearchHash());
}

void LatestParaBlock::AddBlockTripleAddress(const uint256& hastblock, const BLOCKTRIPLEADDRESS& tripleaddr)
{
    _mapBlockAddressOnDisk.insert(hastblock);
}

void LatestParaBlock::Switch()
{
    if (!_pindexLatest || !_pindexLatestRoot) {
        return;
    }

    int64 nStartTime = GetTime();
    int nCount = 0;

    CTxDB_Wrapper txdb;
    CWalletDB_Wrapper walletdb(pwalletMain->strWalletFile);
    CBlockDB_Wrapper blkdb;
    COrphanBlockDB_Wrapper orphanblkdb;

    CBlockIndexSimplified* pIndex = _pindexLatestRoot;
    for (;pIndex; pIndex = pIndex->pnext) {

        uint256 hash = *pIndex->phashBlock;
        bool isInOrphanPool = false;
        CBlock block;
        if (!block.ReadFromDisk(pIndex)) {
            if (mapOrphanBlocks.count(hash)) {
                block = *mapOrphanBlocks[hash];
                isInOrphanPool = true;
            }
            else {

                COrphanBlockDB_Wrapper db;
                if (!db.ReadBlock(hash, block)) {
                    ERROR_FL("Switch Failed for ReadFromDisk and ReadBlock: %d, %s, %s", pIndex->nHeight,
                        pIndex->addr.tostring().c_str(),
                        pIndex->GetBlockHash().ToPreViewString().c_str());

                    _pindexLatestRoot = pIndex;
                    return;
                }
                else {
                    db.EraseBlock(hash);
                }
            }
        }


        bool isAccepted = block.AcceptBlock();
        if (!isAccepted) {
            ERROR_FL("Block is not accepted: %s(%d)", block.GetHash().ToPreViewString().c_str(), block.nHeight);
            return;
        }

        if (isAccepted && isInOrphanPool) {
            delete mapOrphanBlocks[hash];
            mapOrphanBlocks.erase(hash);
            mapOrphanBlocksByPrev.erase(hash);
        }

        auto pIndexPool = mapBlockIndex[hash];
        if (pIndexPool) {
            block.UpdateToBlockIndex(pIndexPool, pIndex->addr);
        }

        if (GetTime() - nStartTime > 200 || nCount++ > 600 || !pIndex->pnext) {
            if (mapBlockIndex.count(hash)) {
                CTxDB_Wrapper txdb;
                block.SetBestChain(txdb, pIndexPool);
            }
            else {
                block.AddToBlockIndex(pIndex->addr);
            }
            _pindexLatestRoot = pIndex;

            break;
        }
    }
}

bool LatestParaBlock::IsLackingBlock(std::function<void(const BackTrackingProgress &)> notiprogress)
{
    if (!_pindexLatest && !_pindexLatestRoot) {
        Load();
        return true;
    }

    CSpentTime spentt;
    uint256 hashPrev = _pindexLatestRoot->GetBlockHash();
    while (!fShutdown) {

        if (spentt.Elapse() > 10 * 60 * 1000) {
            hyperblockMsgs.process();
            return true;
        }

        BackTrackingProgress progress;

        progress.nLatestBlockHeight = _pindexLatest->nHeight;
        progress.strLatestBlockTripleAddr = _pindexLatest->addr.tostring().c_str();
        progress.nBackTrackingBlockHeight = GetBackSearchHeight();
        progress.strBackTrackingBlockHash = GetBackSearchHash().ToPreViewString().c_str();

        notiprogress(progress);

        if (mapBlockIndex.count(hashPrev)) {
            CBlockIndexSimplified* p = _pindexLatestRoot;
            while (p) {
                if (p != _pindexLatest) {
                    p = p->pnext;
                    continue;
                }
                else {
                    _pindexLatestRoot->addr = mapBlockIndex[hashPrev]->addr;
                    return false;
                }
            }

             LogBacktracking("Warning: Cannot reach _pindexLatest from _pindexLatestRoot, so backtracking again !!!");

            _pindexLatestRoot = _pindexLatest;
            return true;
        }

        if (_mapBlockIndexLatest.count(hashPrev)) {
            CBlockIndexSimplified * pindex = _mapBlockIndexLatest[hashPrev];
            if (pindex->pprev && pindex->pprev->pprev) {
                _pindexLatestRoot = pindex->pprev;
                _pindexLatestRoot->pnext = pindex;
                hashPrev = _pindexLatestRoot->GetBlockHash();
                continue;
            }
        }

        if (mapOrphanBlocks.count(hashPrev)) {

            CBlock* pblock = mapOrphanBlocks[hashPrev];

            _pindexLatestRoot = InsertBlockIndex(pblock->hashPrevBlock);

            T_LOCALBLOCKADDRESS addr;
            AddBlockIndex(addr, *pblock);

            while (mapOrphanBlocks.count(pblock->hashPrevBlock)) {
                pblock = mapOrphanBlocks[pblock->hashPrevBlock];
                _pindexLatestRoot = InsertBlockIndex(pblock->hashPrevBlock);
                AddBlockIndex(addr, *pblock);
            }

            hashPrev = pblock->hashPrevBlock;
            continue;
        }

        if (_mapBlockAddressOnDisk.contain(hashPrev)) {
            T_LOCALBLOCKADDRESS addr = _mapBlockAddressOnDisk[hashPrev].ToAddr();

            CBlock block;
            BLOCKTRIPLEADDRESS tripleaddr;
            if (!GetBlock(hashPrev, block, tripleaddr)) {
                break;
            }

            _pindexLatestRoot = InsertBlockIndex(block.hashPrevBlock);
            AddBlockIndex(addr, block);

            hashPrev = block.hashPrevBlock;
            continue;
        }

        bool isFound = false;
        CBlock block;

        if (mapBlocks.contain(hashPrev)) {
            block = mapBlocks[hashPrev];
            isFound = true;
        }
        else {
            COrphanBlockDB_Wrapper db;
            if (db.ReadBlock(hashPrev, block)) {
                isFound = true;
            }
        }

        if (isFound) {
            _pindexLatestRoot = InsertBlockIndex(block.hashPrevBlock);

            T_LOCALBLOCKADDRESS addr;
            AddBlockIndex(addr, block);

            hashPrev = block.hashPrevBlock;
            continue;
        }

        break;
    }

    PullingPrevBlocks();
    return true;
}

bool LatestParaBlock::IsOnChain()
{
    if (!_pindexLatest) {
        return false;
    }

    uint32_t nLatestHeight = _pindexLatest->nHeight;
    if (nLatestHeight > pindexBest->nHeight) {
        return false;
    }

    CBlockIndexSP p = pindexBest;
    while (p && p->nHeight > nLatestHeight) {
        p = p->pprev();
    }

    if (p && p->GetBlockHash() == _pindexLatest->GetBlockHash()) {
        auto iter = _mapBlockIndexLatest.begin();
        for (;iter!=_mapBlockIndexLatest.end();) {

            if (_pindexLatest->pprev == iter->second) {
                _pindexLatestRoot = iter->second;
                _pindexLatestRoot->pprev = nullptr;
                iter++;
                continue;
            }

            if (_pindexLatest == iter->second) {
                iter++;
                continue;
            }

            _mapBlockIndexLatest.erase(iter++);
        }

        return true;
    }
    return false;
}

bool LatestParaBlock::GetBlock(const uint256 & hashblock, CBlock & block, BLOCKTRIPLEADDRESS & tripleaddr)
{
    uint256 hashFromDisk;
    if (_mapBlockAddressOnDisk.contain(hashblock)) {
        T_LOCALBLOCKADDRESS addr = _mapBlockAddressOnDisk[hashblock].ToAddr();

        if (!block.ReadFromDisk(addr)) {

            _mapBlockAddressOnDisk.erase(hashblock);

            return false;
        }

        hashFromDisk = block.GetHash();
        if (hashFromDisk != hashblock) {
            _mapBlockAddressOnDisk.erase(hashblock);
            _mapBlockAddressOnDisk.insert(hashFromDisk, addr);

            return false;
        }

        tripleaddr = addr;
        return true;
    }

    return false;
}


bool LatestParaBlock::LoadLatestBlock()
{
    vector<T_PAYLOADADDR> vecPA;
    T_SHA256 thhash;

    uint64 genesishid = g_cryptoCurrency.GetHID();
    T_APPTYPE app(APPTYPE::paracoin, genesishid, g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID());

    _mapBlockIndexLatest.clear();

    CBlock block;
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    T_LOCALBLOCKADDRESS genesisaddr;
    genesisaddr.set(genesishid, g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID());

    std::set<uint64_t> setMyHIDInDB;
    hyperchainspace->GetLocalHIDs(genesishid, setMyHIDInDB);

    T_LOCALBLOCKADDRESS latestblockaddr;

    if (setMyHIDInDB.empty()) {
        setMyHIDInDB.insert(genesishid);
    }

    bool is_informal_network = false;
    if (mapArgs.count("-model")) {
        if (mapArgs["-model"] == "informal") {
            is_informal_network = true;
        }
    }
    bool isOk = false;
    auto iter = setMyHIDInDB.rbegin();
    for (; iter != setMyHIDInDB.rend(); ++iter) {

        if (is_informal_network && (*iter > 22008 && *iter <= 48601)) {
            continue;
        }
        else if (*iter == genesishid) {
            string payload;
            hyperchainspace->GetLocalBlockPayload(genesisaddr, payload);
            if (!ResolveBlock(block, payload.c_str(), payload.size())) {
                break;
            }
            latestblockaddr = genesisaddr;
            isOk = true;
            break;
        }
        else if (hyperchainspace->GetLocalBlocksByHID(*iter, app, thhash, vecPA)) {
            auto pa = vecPA.rbegin();
            for (; pa != vecPA.rend(); ++pa) {
                if (!ResolveBlock(block, pa->payload.c_str(), pa->payload.size())) {
                    break;
                }
                latestblockaddr = pa->addr;
                isOk = true;
                break;
            }

            if (isOk) {
                break;
            }
        }
    }

    if (!isOk) {
        block = g_cryptoCurrency.GetGenesisBlock();
        latestblockaddr.set(g_cryptoCurrency.GetHID(),
            g_cryptoCurrency.GetChainNum(),
            g_cryptoCurrency.GetLocalID());
    }

    uint256 hashBlock = block.GetHash();
    if (!_pindexLatestRoot) {
        _pindexLatestRoot = InsertBlockIndex(block.hashPrevBlock);
        SetBestIndex(AddBlockIndex(latestblockaddr, block));
    }
    else if (*_pindexLatestRoot->phashBlock == hashBlock) {
        _pindexLatestRoot = InsertBlockIndex(block.hashPrevBlock);
        AddBlockIndex(latestblockaddr, block);
    }
    if (!_pindexLatestRoot) {
        _pindexLatestRoot = _pindexLatest;
    }

    return _mapBlockIndexLatest.size();
}

CBlockIndexSimplified* LatestParaBlock::AddBlockIndex(const T_LOCALBLOCKADDRESS & addrIn, const CBlock & block)
{
    uint256 hashBlock = block.GetHash();
    CBlockIndexSimplified* pIndex = InsertBlockIndex(hashBlock);
    pIndex->Set(addrIn, block);

    if (block.hashPrevBlock == 0) {
        return pIndex;
    }

    CBlockIndexSimplified* pIndexPrev = _mapBlockIndexLatest[block.hashPrevBlock];
    pIndexPrev->pnext = pIndex;
    pIndex->pprev = pIndexPrev;
    return pIndex;
}

CBlockIndexSimplified* LatestParaBlock::InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    std::map<uint256, CBlockIndexSimplified*>::iterator mi = _mapBlockIndexLatest.find(hash);
    if (mi != _mapBlockIndexLatest.end())
        return (*mi).second;

    // Create new
    CBlockIndexSimplified* pindexNew = new CBlockIndexSimplified();
    if (!pindexNew)
        throw runtime_error("LatestParaBlock : new CBlockIndex failed");

    mi = _mapBlockIndexLatest.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

static uint256 hashStartPulling = 0;
static uint64 tmStartPulling = 0;
static CNode* pullingNode = nullptr;

CNode* ChoosePullingNode()
{
    list<CNode*> listPullingNodes;
    for (auto& node : vNodes) {
        if (node->nHeightCheckPointBlock >= LatestParaBlock::GetBackSearchHeight()) {
            listPullingNodes.push_back(node);
        }
    }

    if (listPullingNodes.size() <= 0) {
        return nullptr;
    }

    listPullingNodes.sort([](const CNode *a, const CNode *b) {
                return a->nScore > b->nScore;
        });

    CNode *pulling = *listPullingNodes.begin();
    LogBacktracking("Choose highest score node: %s to pull block, score:%d", pulling->nodeid.c_str(), pulling->nScore);

    return pulling;
}


void LatestParaBlock::PullingPrevBlocks()
{
    uint256 currBackHash = LatestParaBlock::GetBackSearchHash();

    if (hashStartPulling == currBackHash) {
        if (tmStartPulling + 15 > GetTime()) {
            return;
        }
    }
    else if (tmStartPulling + 10 > GetTime()) {
        return;
    }

    int nRequestingNodes = 0;
    CRITICAL_BLOCK(cs_vNodes)
    {
        pullingNode = ChoosePullingNode();
        if (pullingNode) {
            pullingNode->PushGetBlocksReversely(currBackHash);
        }
    }

    tmStartPulling = GetTime();
    hashStartPulling = currBackHash;
}

CBlockBloomFilter::CBlockBloomFilter() : _filter()
{
}

//////////////////////////////////////////////////////////////////////////
//CBlockCacheLocator

bool CBlockCacheLocator::contain(const uint256& hashBlock)
{
    if (!_filterBlock.contain(hashBlock))
        return false;

    if (_mapBlock.count(hashBlock)) {
        return true;
    }

    CBlockDB_Wrapper blockdb;
    CBlock blk;
    if (blockdb.ReadBlock(hashBlock, blk)) {
        return true;
    }
    return false;
}

bool CBlockCacheLocator::insert(const uint256& hashBlock, const CBlock& blk)
{
    CBlockDB_Wrapper blockdb;
    blockdb.TxnBegin();
    blockdb.WriteBlock(hashBlock, blk);
    if (!blockdb.TxnCommit())
        return ERROR_FL("%s : TxnCommit failed", __FUNCTION__);

    if (_mapBlock.size() > _capacity) {
        _mapBlock.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlock[hashBlock] = blk;

    insert(hashBlock);
    return true;
}

void CBlockCacheLocator::clear()
{
    _filterBlock.clear();
    _mapBlock.clear();
    _mapTmJoined.clear();
}

bool CBlockCacheLocator::erase(const uint256& hashBlock)
{
    return true;

    //CBlockDB_Wrapper blockdb;
    //blockdb.TxnBegin();
    //blockdb.EraseBlock(hashBlock);
    //if (!blockdb.TxnCommit())
    //    return ERROR_FL("%s : TxnCommit failed", __FUNCTION__);

    //_mapBlock.erase(hashBlock);
    //std::remove_if(_mapTmJoined.begin(), _mapTmJoined.end(), [&hashBlock](const auto& x) { return x.second == hashBlock; });

    //return true;
}

const CBlock& CBlockCacheLocator::operator[](const uint256& hashBlock)
{
    if (_mapBlock.count(hashBlock)) {
        return _mapBlock[hashBlock];
    }

    CBlockDB_Wrapper blockdb;
    CBlock blk;
    if (!blockdb.ReadBlock(hashBlock, blk)) {
        throw runtime_error(strprintf("Failed to Read block: %s", hashBlock.ToPreViewString().c_str()));
    }

    if (_mapBlock.size() > _capacity) {
        _mapBlock.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlock[hashBlock] = blk;
    return _mapBlock[hashBlock];
}




/////////////////////////////////////////////////////////////////////////////////////////
//CBlockDiskLocator

bool CBlockDiskLocator::contain(const uint256& hashBlock)
{
    if (_setRemoved.count(hashBlock)) {
        return false;
    }

    if (!_filterBlock.contain(hashBlock))
        return false;

    CBlockTripleAddressDB btadb;
    BLOCKTRIPLEADDRESS addr;
    if (btadb.ReadBlockTripleAddress(hashBlock, addr)) {
        return true;
    }
    return false;
}

bool CBlockDiskLocator::insert(CBlockTripleAddressDB& btadb, const uint256& hashBlock, const BLOCKTRIPLEADDRESS& addr)
{
    if (!contain(hashBlock)) {
        _sizeInserted++;
    }

    btadb.WriteBlockTripleAddress(hashBlock, addr);

    if (_mapBlockTripleAddr.size() > _capacity) {
        _mapBlockTripleAddr.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlockTripleAddr[hashBlock] = addr;

    insert(hashBlock);
    return true;
}

bool CBlockDiskLocator::insert(const uint256& hashBlock, const BLOCKTRIPLEADDRESS& addr)
{
    CBlockTripleAddressDB btadb;
    return insert(btadb,hashBlock,addr);
}

void CBlockDiskLocator::clear()
{
    _filterBlock.clear();
    _mapBlockTripleAddr.clear();
    _mapTmJoined.clear();
    _setRemoved.clear();
}

bool CBlockDiskLocator::erase(const uint256& hashBlock)
{
    if (!_filterBlock.contain(hashBlock)) {
        return true;
    }

    _setRemoved.insert(hashBlock);

    CBlockTripleAddressDB btadb;
    btadb.EraseBlockTripleAddress(hashBlock);

    return true;
}

const BLOCKTRIPLEADDRESS& CBlockDiskLocator::operator[](const uint256& hashBlock)
{
    if (_mapBlockTripleAddr.count(hashBlock)) {
        return _mapBlockTripleAddr[hashBlock];
    }

    CBlockTripleAddressDB blockdb;
    BLOCKTRIPLEADDRESS addr;
    if (!blockdb.ReadBlockTripleAddress(hashBlock, addr)) {
        throw runtime_error(strprintf("Failed to Read block's triple address: %s", hashBlock.ToPreViewString().c_str()));
    }

    if (_mapBlockTripleAddr.size() > _capacity) {
        _mapBlockTripleAddr.erase(_mapTmJoined.begin()->second);
        _mapTmJoined.erase(_mapTmJoined.begin());
    }

    _mapTmJoined[GetTime()] = hashBlock;
    _mapBlockTripleAddr[hashBlock] = addr;
    return _mapBlockTripleAddr[hashBlock];
}


CSpentTime::CSpentTime()
{
    _StartTimePoint = std::chrono::system_clock::now();
}

uint64 CSpentTime::Elapse()
{
    auto tdiff = std::chrono::system_clock::now() - _StartTimePoint;
    return std::chrono::duration_cast<std::chrono::milliseconds>(tdiff).count();
}

void CSpentTime::Reset()
{
    _StartTimePoint = std::chrono::system_clock::now();
}


#ifdef WIN32

BOOL APIENTRY DllMain(HANDLE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#endif