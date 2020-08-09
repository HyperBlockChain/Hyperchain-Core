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
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef PARABLOCK_H
#define PARABLOCK_H

#include "headers/inter_public.h"
#include "uint256.h"
#include "bignum.h"
#include "script.h"
#include "db.h"
#include "serialize.h"

#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"


#include "ethash/ethash.h"
#include "ethash/progpow.hpp"
#include "ethash/keccak.h"

#include <string>
#include <vector>
#include <memory>


static const unsigned int MAX_BLOCK_SIZE = 1000000;
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE / 2;
static const int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;
static const int64 COIN = 100000000;
static const int64 CENT = 1000000;
static const int64 MIN_TX_FEE = 50000;
static const int64 MIN_RELAY_TX_FEE = 10000;
static const int64 MAX_MONEY = 210000000 * COIN;
inline bool MoneyRange(int64 nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

static const int COINBASE_MATURITY = 20;//1500, 20 is for debug; 



static const int BLOCK_MATURITY = 10;

// Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp.
static const int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

class CTransaction;
class CBlockIndexSimplified;
class CNode;


extern int nBestHeight;
extern unsigned char pchMessageStart[4];
extern CBlockIndexSP pindexBest;


extern bool IsInitialBlockDownload();
extern FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode);
extern FILE* AppendBlockFile(unsigned int& nFileRet);
extern bool CheckProofOfWork(uint256 hash, unsigned int nBits);

class CDiskTxPos
{
public:
    T_LOCALBLOCKADDRESS addr;
    //unsigned int nFile;
    //unsigned int nBlockPos;       

    unsigned int nTxPos = 0;        

    uint32_t nHeight = 0;           


    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(const T_LOCALBLOCKADDRESS& addrIn, unsigned int nTxPosIn, unsigned int height) :
        addr(addrIn), nTxPos(nTxPosIn), nHeight(height)
    {
    }
    CDiskTxPos(unsigned int nTxPosIn) : nTxPos(nTxPosIn) {}


    IMPLEMENT_SERIALIZE(

        uint32_t* hid = (uint32_t*)(&addr.hid);
    READWRITE(*hid);

    READWRITE(addr.chainnum);
    READWRITE(addr.id);
    READWRITE(addr.ns);
    READWRITE(nTxPos);
    READWRITE(nHeight);
    //READWRITE(FLATDATA(*this));
    )
        void SetNull() { nTxPos = 0; nHeight = 0; }
    bool IsNull() const { return (nTxPos == 0); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.addr == b.addr &&
            a.nTxPos == b.nTxPos && a.nHeight == b.nHeight);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        if (IsNull())
            return strprintf("null");
        else
            return strprintf("(addr=%s, nTxPos=%d height=%d)", addr.tostring().c_str(), nTxPos, nHeight);
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};

class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = -1; }
    bool IsNull() const { return (ptx == NULL && n == -1); }
};

class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE(READWRITE(FLATDATA(*this)); )
        void SetNull() { hash = 0; n = -1; }
    bool IsNull() const { return (hash == 0 && n == -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        return strprintf("COutPoint(%s, %d)", hash.ToString().substr(0, 10).c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

//
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the
// output's public key.
//
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;

    CTxIn()
    {
        nSequence = UINT_MAX;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn = CScript(), unsigned int nSequenceIn = UINT_MAX)
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn = CScript(), unsigned int nSequenceIn = UINT_MAX)
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
    READWRITE(scriptSig);
    READWRITE(nSequence);
    )

        bool IsFinal() const
    {
        return (nSequence == UINT_MAX);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout == b.prevout &&
            a.scriptSig == b.scriptSig &&
            a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        std::string str;
        str += strprintf("CTxIn(");
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0, 24).c_str());
        if (nSequence != UINT_MAX)
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

//
// An output of a transaction.  It contains the public key that the next input
// must be able to sign with to claim it.
//
class CTxOut
{
public:
    int64 nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64 nValueIn, CScript scriptPubKeyIn)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
    READWRITE(scriptPubKey);
    )

        void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull()
    {
        return (nValue == -1);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue == b.nValue &&
            a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        if (scriptPubKey.size() < 6)
            return "CTxOut(error)";

        return strprintf("CTxOut(nValue=%" PRI64d ".%08" PRI64d ", scriptPubKey=%s)", nValue / COIN, nValue % COIN, scriptPubKey.ToString().substr(0, 30).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

//
// The basic transaction that is broadcasted on the network and contained in
// blocks.  A transaction can contain multiple inputs and outputs.
//

class CTransaction
{
public:
    int nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    unsigned int nLockTime;


    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
    nVersion = this->nVersion;
    READWRITE(vin);
    READWRITE(vout);
    READWRITE(nLockTime);
    )

        void SetNull()
    {
        nVersion = 1;
        vin.clear();
        vout.clear();
        nLockTime = 0;
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    

    

    

    

    


    bool IsFinal(int nBlockHeight = 0, int64 nBlockTime = 0) const
    {
        // Time based nLockTime implemented in 0.1.6
        if (nLockTime == 0)
            return true;
        if (nBlockHeight == 0)
            nBlockHeight = nBestHeight;
        if (nBlockTime == 0)
            nBlockTime = GetAdjustedTime();
        if ((int64)nLockTime < (nLockTime < LOCKTIME_THRESHOLD ? (int64)nBlockHeight : nBlockTime))
            return true;
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (!txin.IsFinal())
                return false;
        return true;
    }

    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = UINT_MAX;
        for (int i = 0; i < vin.size(); i++) {
            if (vin[i].nSequence != old.vin[i].nSequence) {
                if (vin[i].nSequence <= nLowest) {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest) {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    int GetSigOpCount() const
    {
        int n = 0;
        BOOST_FOREACH(const CTxIn& txin, vin)
            n += txin.scriptSig.GetSigOpCount();
        BOOST_FOREACH(const CTxOut& txout, vout)
            n += txout.scriptPubKey.GetSigOpCount();
        return n;
    }

    bool IsStandard() const
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (!txin.scriptSig.IsPushOnly())
                return ERROR_FL("nonstandard txin: %s", txin.scriptSig.ToString().c_str());
        BOOST_FOREACH(const CTxOut& txout, vout)
            if (!::IsStandard(txout.scriptPubKey))
                return ERROR_FL("nonstandard txout: %s", txout.scriptPubKey.ToString().c_str());
        return true;
    }

    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            nValueOut += txout.nValue;
            if (!MoneyRange(txout.nValue) || !MoneyRange(nValueOut))
                throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
        }
        return nValueOut;
    }

    static bool AllowFree(double dPriority)
    {
        // Large (in bytes) low-priority (new, small-coin) transactions
        // need a fee.
        return dPriority > COIN * 144 / 250;
    }

    int64 GetMinFee(unsigned int nBlockSize = 1, bool fAllowFree = true, bool fForRelay = false) const
    {
        // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
        int64 nBaseFee = fForRelay ? MIN_RELAY_TX_FEE : MIN_TX_FEE;

        unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK);
        unsigned int nNewBlockSize = nBlockSize + nBytes;
        int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

        if (fAllowFree) {
            if (nBlockSize == 1) {
                // Transactions under 10K are free
                // (about 4500bc if made of 50bc inputs)
                if (nBytes < 10000)
                    nMinFee = 0;
            }
            else {
                // Free transaction area
                if (nNewBlockSize < 27000)
                    nMinFee = 0;
            }
        }

        // To limit dust spam, require MIN_TX_FEE/MIN_RELAY_TX_FEE if any output is less than 0.01
        if (nMinFee < nBaseFee)
            BOOST_FOREACH(const CTxOut& txout, vout)
            if (txout.nValue < CENT)
                nMinFee = nBaseFee;

        // Raise the price as the block approaches full
        if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN / 2) {
            if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
                return MAX_MONEY;
            nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
        }

        if (!MoneyRange(nMinFee))
            nMinFee = MAX_MONEY;
        return nMinFee;
    }

    //bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    //{
    //    CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
    //    if (!filein)
    //        return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

    //    // Read transaction
    //    if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
    //        return error("CTransaction::ReadFromDisk() : fseek failed");
    //    filein >> *this;

    //    // Return file pointer
    //    if (pfileRet)
    //    {
    //        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
    //            return error("CTransaction::ReadFromDisk() : second fseek failed");
    //        *pfileRet = filein.release();
    //    }
    //    return true;
    //}

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion == b.nVersion &&
            a.vin == b.vin &&
            a.vout == b.vout &&
            a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    std::string ToString() const;

    void print() const
    {
        printf("%s", ToString().c_str());
    }


    bool ReadFromDisk(CDiskTxPos pos);
    bool ReadFromDisk(CTxDB_Wrapper& txdb, COutPoint prevout, CTxIndex& txindexRet);
    bool ReadFromDisk(CTxDB_Wrapper& txdb, COutPoint prevout);
    bool ReadFromDisk(COutPoint prevout);
    bool DisconnectInputs(CTxDB_Wrapper& txdb);
    bool ConnectInputs(CTxDB_Wrapper& txdb, std::map<uint256, CTxIndex>& mapTestPool, CDiskTxPos posThisTx,
        CBlockIndexSP pindexBlock, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee = 0);
    bool ClientConnectInputs();
    bool CheckTransaction() const;
    bool AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs = true, bool* pfMissingInputs = NULL);
    bool AcceptToMemoryPool(bool fCheckInputs = true, bool* pfMissingInputs = NULL);

    bool AddToMemoryPoolUnchecked();
public:
    bool RemoveFromMemoryPool();
};


//
// A transaction with a merkle branch linking it to the block chain
//
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable char fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }


    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )

    int SetMerkleBranch(const CBlock* pblock = NULL);
    int GetDepthInMainChain(int& nHeightRet) const;
    int GetDepthInMainChain() const { int nHeight; return GetDepthInMainChain(nHeight); }
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    bool IsInMainChain(CTxDB_Wrapper& txdb) const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(CTxDB_Wrapper& txdb, bool fCheckInputs = true);
    bool AcceptToMemoryPool();
};


//
// A txdb record that contains the disk location of a transaction and the
// locations of transactions that spend its outputs.  vSpent is really only
// used as a flag, but having the location is very helpful for debugging.
//
class CTxIndex
{
public:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        return (a.pos == b.pos &&
            a.vSpent == b.vSpent);
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
    int GetDepthInMainChain() const;
};

//
// Nodes collect new transactions into a block, hash them into a hash tree,
// and scan through nonce values to make the block's hash satisfy proof-of-work
// requirements.  When they solve the proof-of-work, they broadcast the block
// to everyone and the block is added to the block chain.  The first transaction
// in the block is a special one that creates a new coin owned by the creator
// of the block.
//
// Blocks are appended to blk0001.dat files on disk.  Their location on disk
// is indexed by CBlockIndex objects in memory.
//
class CBlock
{
public:
    // header
    int nVersion;
    uint256 hashPrevBlock; 

    uint256 hashMerkleRoot;

    uint32_t nHeight;
    uint32_t nReserved[7];
    uint32_t nTime;
    uint32_t nBits;
    uint64 nNonce;

    uint32_t nPrevHID;
    uint256 hashPrevHyperBlock;
    uint256 hashExternData = 0;         


    // network and disk
    std::vector<CTransaction> vtx;

    

    std::vector<unsigned char> nSolution;  // Equihash solution.

    // memory only
    CUInt128 ownerNodeID = CUInt128(true);
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlock& srcblock)
    {
        Set(srcblock);
    }

    CBlock& operator=(const CBlock& srcblock)
    {
        Set(srcblock);
        return *this;
    }


    void Set(const CBlock& srcblock)
    {
        nVersion = srcblock.nVersion;
        hashPrevBlock = srcblock.hashPrevBlock;
        hashMerkleRoot = srcblock.hashMerkleRoot;

        nHeight = srcblock.nHeight;
        memcpy(nReserved, srcblock.nReserved, sizeof(nReserved));
        nTime = srcblock.nTime;
        nBits = srcblock.nBits;
        nNonce = srcblock.nNonce;

        nPrevHID = srcblock.nPrevHID;
        hashPrevHyperBlock = srcblock.hashPrevHyperBlock;
        hashExternData = srcblock.hashExternData;

        vtx = srcblock.vtx;

        nSolution = srcblock.nSolution;

        ownerNodeID = srcblock.ownerNodeID;
        vMerkleTree = srcblock.vMerkleTree;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nHeight);
        for (size_t i = 0; i < (sizeof(nReserved) / sizeof(nReserved[0])); i++) {
            READWRITE(nReserved[i]);
        }
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        READWRITE(nPrevHID);
        READWRITE(hashPrevHyperBlock);
        READWRITE(hashExternData);

        // ConnectBlock depends on vtx being last so it can calculate offset
        if (!(nType & (SER_GETHASH | SER_BLOCKHEADERONLY)))
            READWRITE(vtx);
        else if (fRead)
            const_cast<CBlock*>(this)->vtx.clear();

        READWRITE(nSolution);
        if (nType & (SER_NETWORK | SER_DISK)) {
            READWRITE(ownerNodeID.Lower64());
            READWRITE(ownerNodeID.High64());
        }
    )

    void SetNull()
    {
        nVersion = 1;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;

        nHeight = 0;
        memset(nReserved, 0, sizeof(nReserved));
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nSolution.clear();

        nPrevHID = 0;
        hashPrevHyperBlock = 0;

        vtx.clear();
        vMerkleTree.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    void SetHyperBlockInfo();

    uint256 GetHash() const;

    ethash::hash256 GetHeaderHash() const;

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }

    int GetSigOpCount() const
    {
        int n = 0;
        BOOST_FOREACH(const CTransaction& tx, vtx)
            n += tx.GetSigOpCount();
        return n;
    }

    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        BOOST_FOREACH(const CTransaction& tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
            for (int i = 0; i < nSize; i += 2) {
                int i2 = std::min(i + 1, nSize - 1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j + i]), END(vMerkleTree[j + i]),
                    BEGIN(vMerkleTree[j + i2]), END(vMerkleTree[j + i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        std::vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
            int i = std::min(nIndex ^ 1, nSize - 1);
            vMerkleBranch.push_back(vMerkleTree[j + i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        BOOST_FOREACH(const uint256& otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }

    bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = AppendBlockFile(nFileRet);
        if (!fileout)
            return ERROR_FL("CBlock::WriteToDisk() : AppendBlockFile failed");

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(pchMessageStart) << nSize;

        // Write block
        nBlockPosRet = ftell(fileout);
        if (nBlockPosRet == -1)
            return ERROR_FL("CBlock::WriteToDisk() : ftell failed");
        fileout << *this;

        // Flush stdio buffers and commit to disk before returning
        fflush(fileout);
        if (!IsInitialBlockDownload() || (nBestHeight + 1) % 500 == 0) {
#ifdef __WXMSW__
            _commit(_fileno(fileout));
#else
            fsync(fileno(fileout));
#endif
        }

        return true;
    }

    

    //bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true)
    //{
    //    SetNull();

    //    // Open history file to read
    //    CAutoFile filein = OpenBlockFile(nFile, nBlockPos, "rb");
    //    if (!filein)
    //        return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
    //    if (!fReadTransactions)
    //        filein.nType |= SER_BLOCKHEADERONLY;

    //    // Read block
    //    filein >> *this;

    //    // Check the header
    //    if (!CheckProofOfWork(GetHash(), nBits))
    //        return error("CBlock::ReadFromDisk() : errors in block header");

    //    return true;
    //}

    bool ReadFromDisk(const CTxIndex& txidx, bool fReadTransactions = true);

    bool ReadFromDisk(const T_LOCALBLOCKADDRESS& addr, bool fReadTransactions = true)
    {
        SetNull();

        

        CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

        string payload;
        if (!hyperchainspace->GetLocalBlockPayload(addr, payload)) {
            return ERROR_FL("block(%s) isn't found in my local storage", addr.tostring().c_str());
        }

        try {
            CAutoBuffer autobuff(std::move(payload));
            

            //if (!fReadTransactions)
            //    autobuff.nType |= SER_BLOCKHEADERONLY;

            autobuff >> *this;
        }
        catch (std::ios_base::failure& e) {
            return ERROR_FL("%s", e.what());
        }

        // Check the header
        if (!CheckProofOfWork(GetHash(), nBits))
            return ERROR_FL("errors in block header");

        return true;
    }

    string ToString() const
    {
        string strResult = strprintf("\nBlock height: %u\n"
            "\tversion: %d\n"
            "\tprevHID: %u\n"
            "\tprevHHash: %s\n"
            "\thashBlock: %s ******\n"
            "\thashPrevBlock: %s\n"
            "\thashMerkleRoot: %s\n"
            "\tnTime: %u\n"
            "\tnBits: %08x\n"
            "\tnNonce: %" PRIu64 "\n"
            "\tvtx: %d\n",
            nHeight,
            nVersion,
            nPrevHID,
            hashPrevHyperBlock.ToString().c_str(),
            GetHash().ToString().c_str(),
            hashPrevBlock.ToString().c_str(),
            hashMerkleRoot.ToString().c_str(),
            nTime, nBits, nNonce,
            vtx.size());

        for (int i = 0; i < vtx.size(); i++) {
            strResult += "\t";
            strResult += vtx[i].ToString();
        }
        strResult += "\tvMerkleTree: ";
        for (int i = 0; i < vMerkleTree.size(); i++)
            strResult += vMerkleTree[i].ToString().substr(0, 10);

        strResult += "\n";

        return strResult;
    }

    void print() const
    {
        printf(ToString().c_str());
    }


    bool DisconnectBlock(CTxDB_Wrapper& txdb, CBlockIndexSP pindex);
    bool ConnectBlock(CTxDB_Wrapper& txdb, CBlockIndexSP pindex);
    bool ReadFromDisk(const CBlockIndexSP pindex, bool fReadTransactions = true);
    bool ReadFromDisk(const CBlockIndexSimplified* pindex);
    bool SetBestChain(CTxDB_Wrapper& txdb, CBlockIndexSP pindexNew);

    

    bool AddToBlockIndex(const T_LOCALBLOCKADDRESS& addr);
    bool UpdateToBlockIndex(CBlockIndexSP pIndex, const T_LOCALBLOCKADDRESS& addr);

    bool IsMine() const;

    

    int CheckHyperBlockConsistence(CNode* pfrom) const;
    bool CheckExternalData() const;
    bool IsLastestHyperBlockMatched() const;
    bool CheckBlock() const;
    void GetBlock(const T_LOCALBLOCKADDRESS& addr) const;

    bool AcceptBlock();

    bool AddToMemoryPool();
    bool RemoveFromMemoryPool();
    bool ReadFromMemoryPool(uint256 nBlockHash);

    bool CheckTrans();
    bool CheckProgPow() const;

};



//
// The block chain is a tree shaped structure starting with the
// genesis block at the root, with each block potentially having multiple
// candidates to be the next block.  pprev and pnext link a path through the
// main/longest chain.  A blockindex may have multiple pprev pointing back
// to it, but pnext will only point forward to the longest branch, or will
// be null if the block is not part of the longest chain.
//

class CBlockIndex : public std::enable_shared_from_this<CBlockIndex>
{
public:
    uint256 hashBlock = 0;  

    uint256 hashPrev = 0;
    uint256 hashNext = 0;
    //unsigned int nFile;     

    //unsigned int nBlockPos; 

    int nHeight;
    CBigNum bnChainWork;    


    T_LOCALBLOCKADDRESS addr; 


    // block header
    int nVersion;
    uint256 hashMerkleRoot;

    unsigned int nTime;
    unsigned int nBits;
    uint64 nNonce;

    std::vector<unsigned char> nSolution;

    uint32 nPrevHID;
    uint256 hashPrevHyperBlock;

    uint256 hashExternData = 0;                 

    CUInt128 ownerNodeID = CUInt128(true);

    CBlockIndex()
    {
        nHeight = 0;
        bnChainWork = 0;

        nVersion = 0;
        hashMerkleRoot = 0;

        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nSolution.clear();
        nPrevHID = 0;
        hashPrevHyperBlock = 0;

    }

    CBlockIndex(const T_LOCALBLOCKADDRESS& addrIn, const CBlock& block)
    {
        bnChainWork = 0;

        Set(addrIn, block);
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        hashPrev = block.hashPrevBlock;
        nHeight = block.nHeight;
        bnChainWork = 0;

        nVersion = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;

        nTime = block.nTime;
        nBits = block.nBits;
        nNonce = block.nNonce;
        nSolution = block.nSolution;
        nPrevHID = block.nPrevHID;
        hashPrevHyperBlock = block.hashPrevHyperBlock;
        hashExternData = block.hashExternData;
        ownerNodeID = block.ownerNodeID;
    }

    void Set(const T_LOCALBLOCKADDRESS& addrIn, const CBlock& block)
    {
        hashPrev = block.hashPrevBlock;
        nHeight = block.nHeight;
        addr = addrIn;

        nVersion = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;

        nTime = block.nTime;
        nBits = block.nBits;
        nNonce = block.nNonce;
        nSolution = block.nSolution;
        nPrevHID = block.nPrevHID;
        hashPrevHyperBlock = block.hashPrevHyperBlock;
        hashExternData = block.hashExternData;
        ownerNodeID = block.ownerNodeID;
    }

    CBlock GetBlockHeader() const
    {
        CBlock block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrev;

        block.hashMerkleRoot = hashMerkleRoot;

        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        block.nSolution = nSolution;
        block.nPrevHID = nPrevHID;
        block.hashPrevHyperBlock = hashPrevHyperBlock;
        block.hashExternData = hashExternData;
        block.ownerNodeID = ownerNodeID;

        return block;
    }

    CBlockIndexSP pprev() const;
    CBlockIndexSP pnext() const;

    uint256 GetBlockHash() const
    {
        return hashBlock;
    }

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }

    CBigNum GetBlockWork() const
    {
        CBigNum bnTarget;
        bnTarget.SetCompact(nBits);
        if (bnTarget <= 0)
            return 0;
        return (CBigNum(1) << 256) / (bnTarget + 1);
    }

    bool IsInMainChain() const;
    bool CheckIndex() const
    {
        return CheckProofOfWork(GetBlockHash(), nBits);
    }

    enum { nMedianTimeSpan = 11 };

    int64 GetMedianTimePast() const;
    int64 GetMedianTime() const;

    std::string ToString() const
    {
        return strprintf("CBlockIndex: \n"
            "\tHeight=%d"
            "\tAddr=%s\n"
            "\tPrevHID: %d\n"
            "\thashPrevHyperBlock=%s\n"
            "\tnBit=%08x"
            "\tnTime=%d\n"
            "\tnNonce=%" PRI64u "\n"
            "\tmerkle=%s\n"
            "\thashBlock=%s ******\n"
            "\thashPrevBlock=%s\n"
            "\thashNextBlock=%s\n",
            nHeight,
            addr.tostring().c_str(),
            nPrevHID, hashPrevHyperBlock.ToString().c_str(),
            nBits, nTime, nNonce,
            hashMerkleRoot.ToString().c_str(),
            (hashBlock.ToString().c_str()),
            hashPrev.ToString().c_str(),
            hashNext.ToString().c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }

    bool operator<(const CBlockIndex &st) const
    {
        return (addr < st.addr);
    }
    bool operator>=(const CBlockIndex &st) const
    {
        return (addr >= st.addr);
    }

    using key_type = uint256;
    key_type NextKey() const
    {
        return hashNext;
    }

    uint32 Height()
    {
        return nHeight;
    }

};

template <class Ty>
class shared_ptr_proxy : public std::shared_ptr<Ty>
{
public:
    using baseclass = std::shared_ptr<Ty>;
    using baseclass::baseclass;

    friend bool operator==(const shared_ptr_proxy& lhs, std::nullptr_t rhs) noexcept
    {
        if (lhs.get() == nullptr)
            return true;

        return false;
    }

    friend bool operator!=(const shared_ptr_proxy& lhs, std::nullptr_t rhs) noexcept
    {
        return !(lhs==rhs);
    }

    friend bool operator==(const shared_ptr_proxy& lhs, const shared_ptr_proxy& rhs) noexcept
    {
        if (lhs.get() == rhs.get())
            return true;

        if (lhs != nullptr && rhs == nullptr) {
            return false;
        }

        if (lhs == nullptr && rhs != nullptr) {
            return false;
        }

        if (lhs->nHeight != rhs->nHeight) {
            return false;
        }

        if (lhs->GetBlockHash() != rhs->GetBlockHash()) {
            return false;
        }
        return true;
    }

    friend bool operator!=(const shared_ptr_proxy& lhs, const shared_ptr_proxy& rhs) noexcept
    {
        return !(lhs == rhs);
    }
};

template<class _Ty, class... _Types>
inline shared_ptr_proxy<_Ty> make_shared_proxy(_Types&&... _Args)
{
    // make a shared_ptr
    const auto _Rx = new _Ty(std::forward<_Types>(_Args)...);

    shared_ptr_proxy<_Ty> _Ret;
    _Ret.reset(_Rx);
    return (_Ret);
}
using CBlockIndexSP = shared_ptr_proxy<CBlockIndex>;

#endif
