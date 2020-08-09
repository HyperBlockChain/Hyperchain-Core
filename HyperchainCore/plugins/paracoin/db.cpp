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

#include "headers.h"
#include "db.h"
#include "net.h"
#include "util.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <algorithm>
using namespace std;
using namespace boost;


unsigned int nWalletDBUpdated;
uint64 nAccountingEntryNumber = 0;



//
// CDB
//

static CCriticalSection cs_db;
static bool fDbEnvInit = false;
DbEnv* dbenv= new DbEnv(0);
static map<string, int> mapFileUseCount;
static map<string, Db*> mapDb;

thread_local int tls_db_opened_count = 0;
thread_local CTxDB *tls_txdb_instance = nullptr;

extern CBlockCacheLocator mapBlocks;


extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");
extern bool SwitchChainTo(CBlockIndexSP pindexBlock);

class CDBInit
{
public:
    CDBInit()
    {
    }
    ~CDBInit()
    {
        if (fDbEnvInit)
        {
            dbenv->close(0);
            delete dbenv;
            dbenv = nullptr;
            fDbEnvInit = false;
        }
    }
}
instance_of_cdbinit;


CDB::CDB(const char* pszFile, const char* pszMode) : pdb(NULL)
{
    int ret;
    if (pszFile == NULL)
        return;

    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    bool fCreate = strchr(pszMode, 'c');
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    CRITICAL_BLOCK(cs_db)
    {
        if (!fDbEnvInit)
        {
            if (fShutdown)
                return;
            string strDataDir = GetDataDir();
            string strLogDir = strDataDir + "/database";
            filesystem::create_directory(strLogDir.c_str());
            string strErrorFile = strDataDir + "/db.log";
            printf("dbenv.open strLogDir=%s strErrorFile=%s\n", strLogDir.c_str(), strErrorFile.c_str());

            dbenv->set_lg_dir(strLogDir.c_str());
            dbenv->set_lg_max(10000000);
            dbenv->set_lk_max_locks(10000);
            dbenv->set_lk_max_objects(10000);
            dbenv->set_errfile(fopen(strErrorFile.c_str(), "a")); /// debug
            dbenv->set_flags(DB_AUTO_COMMIT, 1);
            ret = dbenv->open(strDataDir.c_str(),
                             DB_CREATE     |
                             DB_INIT_LOCK  |
                             DB_INIT_LOG   |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN   |
                             DB_THREAD     |
                             DB_RECOVER,
                             S_IRUSR | S_IWUSR);
            if (ret > 0)
                throw runtime_error(strprintf("CDB() : error %d opening database environment", ret));
            fDbEnvInit = true;
        }

        strFile = pszFile;
        ++mapFileUseCount[strFile];
        pdb = mapDb[strFile];
        if (pdb == NULL)
        {
            pdb = new Db(dbenv, 0);

            ret = pdb->open(NULL,      // Txn pointer
                            pszFile,   // Filename
                            "main",    // Logical db name
                            DB_BTREE,  // Database type
                            nFlags,    // Flags
                            0);

            if (ret > 0)
            {
                delete pdb;
                pdb = NULL;
                CRITICAL_BLOCK(cs_db)
                    --mapFileUseCount[strFile];
                strFile = "";
                throw runtime_error(strprintf("CDB() : can't open database file %s, error %d", pszFile, ret));
            }

            if (fCreate && !Exists(string("version")))
            {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(VERSION);
                fReadOnly = fTmp;
            }

            mapDb[strFile] = pdb;
        }
    }
}

void CDB::Close()
{
    if (!pdb)
        return;
    if (!vTxn.empty())
        vTxn.front()->abort();
    vTxn.clear();
    pdb = NULL;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;
    if (strFile == "addr.dat")
        nMinutes = 2;
    if (strFile == "blkindex.dat" && IsInitialBlockDownload() && nBestHeight % 500 != 0)
        nMinutes = 1;
    dbenv->txn_checkpoint(0, nMinutes, 0);

    CRITICAL_BLOCK(cs_db)
        --mapFileUseCount[strFile];
}

void static CloseDb(const string& strFile)
{
    CRITICAL_BLOCK(cs_db)
    {
        if (mapDb[strFile] != NULL)
        {
            // Close the database handle
            Db* pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

void DBFlush(bool fShutdown)
{
    // Flush log data to the actual data file
    //  on all files that are not in use
    printf("DBFlush(%s)%s\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started");
    if (!fDbEnvInit)
        return;
    CRITICAL_BLOCK(cs_db)
    {
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            printf("%s refcount=%d\n", strFile.c_str(), nRefCount);
            if (nRefCount == 0)
            {
                // Move log data to the dat file
                CloseDb(strFile);
                dbenv->txn_checkpoint(0, 0, 0);
                printf("%s flush\n", strFile.c_str());
                dbenv->lsn_reset(strFile.c_str(), 0);
                mapFileUseCount.erase(mi++);
            }
            else
                mi++;
        }
        if (fShutdown)
        {
            char** listp;
            if (mapFileUseCount.empty())
                dbenv->log_archive(&listp, DB_ARCH_REMOVE);
            dbenv->close(0);
            delete dbenv;
            dbenv = nullptr;
            fDbEnvInit = false;
        }
    }
}






//
// CTxDB
//

bool CTxDB::ReadTxIndex(const uint256& hash, CTxIndex& txindex)
{
    assert(!fClient);
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(const uint256& hash, const CTxIndex& txindex)
{
    assert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    assert(!fClient);

    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    assert(!fClient);
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(const uint256& hash)
{
    assert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadOwnerTxes(const uint160& hash160, int nMinHeight, vector<CTransaction>& vtx)
{
    assert(!fClient);
    vtx.clear();

    // Get cursor
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;

    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << string("owner") << hash160 << CDiskTxPos();
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            return false;
        }

        // Unserialize
        string strType;
        uint160 hashItem;
        CDiskTxPos pos;
        ssKey >> strType >> hashItem >> pos;
        int nItemHeight;
        ssValue >> nItemHeight;

        // Read transaction
        if (strType != "owner" || hashItem != hash160)
            break;
        if (nItemHeight >= nMinHeight)
        {
            vtx.resize(vtx.size()+1);
            if (!vtx.back().ReadFromDisk(pos))
            {
                pcursor->close();
                return false;
            }
        }
    }

    pcursor->close();
    return true;
}

bool CTxDB::ReadDiskTx(const uint256& hash, CTransaction& tx, CTxIndex& txindex)
{
    assert(!fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(const uint256& hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint& outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint& outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadBlockIndex(const uint256& hash, CDiskBlockIndex& blockindex)
{
    return Read(make_pair(string("blockindex"), hash), blockindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::EraseBlockIndex(uint256 hash)
{
    return Erase(make_pair(string("blockindex"), hash));
}

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}



bool CTxDB::ReadAddrMaxChain(T_LOCALBLOCKADDRESS& addrMax)
{
    string strAddrMax;
    bool ret =Read(string("addrMaxChain"), strAddrMax);
    if (ret) {
        addrMax.fromstring(strAddrMax);
    }
    return ret;
}



bool CTxDB::WriteAddrMaxChain(const T_LOCALBLOCKADDRESS& addrMax)
{
    string str = addrMax.tostring();
    return Write(string("addrMaxChain"), str);
}



bool CTxDB::ReadBestInvalidWork(CBigNum& bnBestInvalidWork)
{
    return Read(string("bnBestInvalidWork"), bnBestInvalidWork);
}

bool CTxDB::WriteBestInvalidWork(CBigNum bnBestInvalidWork)
{
    return Write(string("bnBestInvalidWork"), bnBestInvalidWork);
}

static CBlockIndexSP InsertBlockIndex(uint256 hash, int nHeight)
{
    if (hash == 0)
        return NULL;

    // Return existing
    auto mi = mapBlockIndex.fromcache(hash);
    if (mi)
        return mi;

    // Create new
    CBlockIndexSP pindexNew = std::make_shared<CBlockIndex>();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    pindexNew->nHeight = nHeight;
    auto miter = mapBlockIndex.insert(make_pair(hash, pindexNew),false).first;
    pindexNew->hashBlock = ((*miter).first);

    return miter->second;
}

bool CTxDB::CheckBestBlockIndex(CBlockIndexSP pIndex)
{
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    if (pIndex && hyperchainspace) {
        

        uint64 nPullingHID = 0;
        for (; pIndex;) {

            uint64 nHID = pIndex->nPrevHID;
            T_HYPERBLOCK h;
            if (!hyperchainspace->getHyperBlock(nHID, h)) {
                WARNING_FL("Lack of hyper block: %d, Please pull from remote nodes", nHID);

                RSyncRemotePullHyperBlock(nHID);
                pIndex = pIndex->pprev();
                continue;
            }
            T_SHA256 hash = h.GetHashSelf();

            

            if (pIndex->nPrevHID != nHID ||
                pIndex->hashPrevHyperBlock != uint256S(hash.toHexString())) {
                pIndex = pIndex->pprev();
                continue;
            }

            if (pIndex->addr.isValid()) {
                string payload;
                if (!hyperchainspace->GetLocalBlockPayload(pIndex->addr, payload)) {
                    

                    WARNING_FL("Lack of block : %s contained by hyper block: %d, Please pull from remote nodes",
                        pIndex->addr.tostring().c_str(), pIndex->addr.hid);
                    RSyncRemotePullHyperBlock(pIndex->addr.hid);
                    pIndex = pIndex->pprev();
                    continue;
                }
                CBlock tailblock;
                if (!ResolveBlock(tailblock, payload.c_str(), payload.length())) {
                    ERROR_FL("Failed to resolve paracoin block: %s", pIndex->addr.tostring().c_str());
                    pIndex = pIndex->pprev();
                    continue;
                }
                if (tailblock.GetHash() != pIndex->GetBlockHash()) {
                    

                    uint256 hash = pIndex->GetBlockHash();
                    pIndex = pIndex->pprev();

                    auto iter = mapBlockIndex[hash];
                    if (iter) {
                        mapBlockIndex.erase(hash);
                    }

                    

                    //EraseBlockIndex(hash);
                    continue;
                }
                

                break;
            }
            else {
                pIndex = pIndex->pprev();
            }
        }

        pindexBest = pIndex;
        if (!pindexBest) {
            pindexBest = pindexGenesisBlock;
        }
        hashBestChain = pindexBest->GetBlockHash();
        nBestHeight = pindexBest->nHeight;
        bnBestChainWork = pindexBest->bnChainWork;

        printf("CheckBestBlockIndex(): hashBestChain=%s  height=%d\n", hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight);
    }
    return true;
}

CBlockIndexSP CTxDB::ConstructBlockIndex(CDiskBlockIndex& diskindex)
{
    CBlockIndexSP pindexNew = InsertBlockIndex(diskindex.GetBlockHash(), diskindex.nHeight);
    //pindexNew->pprev = InsertBlockIndex(diskindex.hashPrev, diskindex.nHeight - 1);
    //pindexNew->pnext = InsertBlockIndex(diskindex.hashNext, diskindex.nHeight + 1);
    pindexNew->hashPrev = diskindex.hashPrev;
    pindexNew->hashNext = diskindex.hashNext;
    

    pindexNew->addr = diskindex.addr;
    pindexNew->nVersion = diskindex.nVersion;
    pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
    pindexNew->nTime = diskindex.nTime;
    pindexNew->nBits = diskindex.nBits;
    pindexNew->nNonce = diskindex.nNonce;
    pindexNew->nSolution = diskindex.nSolution;
    pindexNew->ownerNodeID = diskindex.ownerNodeID;
    pindexNew->nPrevHID = diskindex.nPrevHID;
    pindexNew->hashExternData = diskindex.hashExternData;
    pindexNew->hashPrevHyperBlock = diskindex.hashPrevHyperBlock;
    pindexNew->bnChainWork = diskindex.bnChainWork;
    return pindexNew;
}

bool CTxDB::LoadBlockIndex()
{
    // Get database cursor
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;

    // Load mapBlockIndex
    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("blockindex"), uint256(0));
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
            return false;

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType == "blockindex")
        {
            CDiskBlockIndex diskindex;
            ssValue >> diskindex;

            // Construct block index object
            CBlockIndexSP pindexNew = ConstructBlockIndex(diskindex);

            // Watch for genesis block
            if (pindexGenesisBlock == NULL && diskindex.GetBlockHash() == hashGenesisBlock)
                pindexGenesisBlock = pindexNew;

            if (!pindexNew->CheckIndex())
                return ERROR_FL("CheckIndex failed at %d", pindexNew->nHeight);
        }
        else
        {
            break;
        }
    }
    pcursor->close();

    // Calculate bnChainWork
    vector<pair<int, CBlockIndexSP> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndexSP)& item, mapBlockIndex)
    {
        CBlockIndexSP pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndexSP)& item, vSortedByHeight)
    {
        CBlockIndexSP pindex = item.second;
        auto spprev = pindex->pprev();
        pindex->bnChainWork = (spprev ? spprev->bnChainWork : 0) + pindex->GetBlockWork();
    }


    

    // Load hashBestChain pointer to end of best chain
    if (!ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == NULL) {
            return true;
        }
        hashBestChain = pindexGenesisBlock->GetBlockHash();
    }
    if (!mapBlockIndex.count(hashBestChain)) {
        ERROR_FL("hashBestChain not found in the block index");
        hashBestChain = hashGenesisBlock;
    }

    pindexBest = mapBlockIndex[hashBestChain];

    

    //auto maxindex = std::max_element(mapBlockIndex.begin(), mapBlockIndex.end());
    cout << "Paracoin: verifying best block...\n";
    CheckBestBlockIndex(pindexBest);

    

    if (!ReadAddrMaxChain(addrMaxChain)) {
        addrMaxChain = pindexBest ? pindexBest->addr : T_LOCALBLOCKADDRESS();
    }

    // Load bnBestInvalidWork, OK if it doesn't exist
    

    ReadBestInvalidWork(bnBestInvalidWork);

    cout << "Paracoin: verifying blocks in the best chain...\n";

    

    int nCurrHeight = nBestHeight - 1;
    CBlockIndexSP pindexFork = nullptr;
    CBlockIndexSP pindex = pindexBest->pprev();
    CBlockIndexSP pprevindex;
    if(pindex)
        pprevindex = pindex->pprev();
    for (; pindex && pprevindex; pindex = pprevindex, pprevindex = pindex->pprev(), nCurrHeight--) {

        if (pindex->nTime == 0 || pindex->nSolution.size() == 0) {
            printf("LoadBlockIndex() : *** error block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pprevindex;
            continue;
        }

        if (pindex->nHeight < nBestHeight - 1500 && !mapArgs.count("-checkblocks"))
            break;

        if (!pindex->addr.isValid() && !mapBlocks.contain(pindex->GetBlockHash())) {
            continue;
        }

        CBlock block;
        if (!block.ReadFromDisk(pindex)) {
            printf("LoadBlockIndex() : *** cannot read block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pprevindex;
            continue;
        }

        if (!block.CheckBlock()) {
            printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pprevindex;
        }
    }

    if (pindex && !pindex->pprev() && nCurrHeight > 0) {
        cout << "LoadBlockIndex(): block index is bad, To rebuild, please remove blkindex.dat and restart the program\n";
        return false;

        //pindexBest = pindexGenesisBlock;
        //while (pindexBest && pindexBest->pnext) {
        //    pindexBest = pindexBest->pnext;
        //}
        //CheckBestBlockIndex(pindexBest);
    }

    if (pindexFork) {
        // Reorg back to the fork
        printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
        if (!SwitchChainTo(pindexFork)) {
            return ERROR_FL("block.ReadFromDisk failed");
        }
    }

    return true;
}

//
//CBlockDB
//



bool CBlockDB::LoadBlockUnChained()
{
    mapBlocks.clear();
    bool ret = Load("block", [](CDataStream& ssKey, CDataStream& ssValue) -> bool {

        CBlock block;
        ssValue >> block;

        uint256 hash;
        ssKey >> hash;
        assert(hash == block.GetHash());

        mapBlocks.insert(hash);
        return true;
    });
    return ret;
}




bool CBlockDB::LoadBlockUnChained(const uint256& hash, std::function<bool(CDataStream&, CDataStream&)> f)
{
    return Load("block",hash, f);
}

bool CBlockDB::ReadBlock(const uint256& hash, CBlock& block)
{
    return Read(make_pair(string("block"), hash), block);
}

bool CBlockDB::WriteBlock(const CBlock& block)
{
    return Write(make_pair(string("block"), block.GetHash()), block);
}

bool CBlockDB::WriteBlock(const uint256& hash, const CBlock& block)
{
    return Write(make_pair(string("block"), hash), block);
}

bool CBlockDB::EraseBlock(uint256 hash)
{
    return Erase(make_pair(string("block"), hash));
}

//
//CTxDB
//
bool CTxDB::ReadSP(const uint256& hash, CBlockIndexSP &blockindex)
{
    CDiskBlockIndex diskindex;
    if (!ReadBlockIndex(hash, diskindex)) {
        return false;
    }

    //Construct block index object
    blockindex = ConstructBlockIndex(diskindex);

    return true;
}

bool CTxDB::WriteSP(const CBlockIndex* blockindex)
{
    CBlockIndex idx = *blockindex;
    CDiskBlockIndex diskindex(&idx);
    return WriteBlockIndex(diskindex);
}

//
//CBlockTripleAddressDB
//
bool CBlockTripleAddressDB::LoadBlockTripleAddress()
{
    Load("triaddr", [](CDataStream& ssKey, CDataStream& ssValue) -> bool {

        BLOCKTRIPLEADDRESS blocktripleaddr;
        ssValue >> blocktripleaddr;
        uint256 hash;
        ssKey >> hash;
        LatestParaBlock::AddBlockTripleAddress(hash, blocktripleaddr);
        return true;
    });
    return true;
}

bool CBlockTripleAddressDB::ReadHID(std::set<uint32_t>& setHID)
{
    Load("hid", [&setHID](CDataStream& ssKey, CDataStream& ssValue) -> bool {

        uint32 hid;
        ssValue >> hid;
        setHID.insert(hid);
        return true;
    });

    return true;
}

bool CBlockTripleAddressDB::WriteHID(uint32 hid)
{
    return Write(make_pair(string("hid"), hid), hid);
}

bool CBlockTripleAddressDB::ReadBlockTripleAddress(const uint256& hash, BLOCKTRIPLEADDRESS& addr)
{
    return Read(make_pair(string("triaddr"), hash), addr);
}

bool CBlockTripleAddressDB::WriteBlockTripleAddress(const uint256& hash, const BLOCKTRIPLEADDRESS& addr)
{
    return Write(make_pair(string("triaddr"), hash), addr);
}

bool CBlockTripleAddressDB::EraseBlockTripleAddress(const uint256& hash)
{
    return Erase(make_pair(string("triaddr"), hash));
}


//
// CAddrDB
//

bool CAddrDB::WriteAddress(const CAddress& addr)
{
    return Write(make_pair(string("addr"), addr.GetKey()), addr);
}

bool CAddrDB::EraseAddress(const CAddress& addr)
{
    return Erase(make_pair(string("addr"), addr.GetKey()));
}

bool CAddrDB::LoadAddresses()
{
    CRITICAL_BLOCK(cs_mapAddresses)
    {
        // Load user provided addresses
        CAutoFile filein = fopen((GetDataDir() + "/addr.txt").c_str(), "rt");
        if (filein)
        {
            try
            {
                char psz[1000];
                while (fgets(psz, sizeof(psz), filein))
                {
                    CAddress addr(psz, false, NODE_NETWORK);
                    addr.nTime = 0; // so it won't relay unless successfully connected
                    if (addr.IsValid())
                        AddAddress(addr);
                }
            }
            catch (...) { }
        }

        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        loop
        {
            // Read next record
            CDataStream ssKey;
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;

            // Unserialize
            string strType;
            ssKey >> strType;
            if (strType == "addr")
            {
                CAddress addr;
                ssValue >> addr;
                mapAddresses.insert(make_pair(addr.GetKey(), addr));
            }
        }
        pcursor->close();

        printf("Loaded %d addresses\n", mapAddresses.size());
    }

    return true;
}

bool LoadAddresses()
{
    return CAddrDB("cr+").LoadAddresses();
}




//
// CWalletDB
//

bool CWalletDB::WriteName(const string& strAddress, const string& strName)
{
    nWalletDBUpdated++;
    return Write(make_pair(string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    nWalletDBUpdated++;
    return Erase(make_pair(string("name"), strAddress));
}

bool CWalletDB::ReadAccount(const string& strAccount, CAccount& account)
{
    account.SetNull();
    return Read(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccount(const string& strAccount, const CAccount& account)
{
    return Write(make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccountingEntry(const CAccountingEntry& acentry)
{
    return Write(boost::make_tuple(string("acentry"), acentry.strAccount, ++nAccountingEntryNumber), acentry);
}

int64 CWalletDB::GetAccountCreditDebit(const string& strAccount)
{
    list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    int64 nCreditDebit = 0;
    BOOST_FOREACH (const CAccountingEntry& entry, entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void CWalletDB::ListAccountCreditDebit(const string& strAccount, list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error("CWalletDB::ListAccountCreditDebit() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << boost::make_tuple(string("acentry"), (fAllAccounts? string("") : strAccount), uint64(0));
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error("CWalletDB::ListAccountCreditDebit() : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "acentry")
            break;
        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        entries.push_back(acentry);
    }

    pcursor->close();
}


int CWalletDB::LoadWallet(CWallet* pwallet)
{
    pwallet->vchDefaultKey.clear();
    pwallet->setKeyPool.clear();
    int nFileVersion = 0;
    vector<uint256> vWalletUpgrade;

    // Modify defaults
#ifndef __WXMSW__
    // Tray icon sometimes disappears on 9.10 karmic koala 64-bit, leaving no way to access the program
    fMinimizeToTray = false;
    fMinimizeOnClose = false;
#endif

    //// todo: shouldn't we catch exceptions and try to recover and continue?
    CRITICAL_BLOCK(pwallet->cs_wallet)
    {
        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return DB_CORRUPT;

        loop
        {
            // Read next record
            CDataStream ssKey;
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return DB_CORRUPT;

            // Unserialize
            // Taking advantage of the fact that pair serialization
            // is just the two items serialized one after the other
            string strType;
            ssKey >> strType;
            if (strType == "name")
            {
                string strAddress;
                ssKey >> strAddress;
                ssValue >> pwallet->mapAddressBook[strAddress];
            }
            else if (strType == "tx")
            {
                uint256 hash;
                ssKey >> hash;
                CWalletTx& wtx = pwallet->mapWallet[hash];
                ssValue >> wtx;
                wtx.pwallet = pwallet;

                if (wtx.GetHash() != hash)
                    printf("Error in wallet.dat, hash mismatch\n");

                // Undo serialize changes in 31600
                if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
                {
                    if (!ssValue.empty())
                    {
                        char fTmp;
                        char fUnused;
                        ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                        printf("LoadWallet() upgrading tx ver=%d %d '%s' %s\n", wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount.c_str(), hash.ToString().c_str());
                        wtx.fTimeReceivedIsTxTime = fTmp;
                    }
                    else
                    {
                        printf("LoadWallet() repairing tx ver=%d %s\n", wtx.fTimeReceivedIsTxTime, hash.ToString().c_str());
                        wtx.fTimeReceivedIsTxTime = 0;
                    }
                    vWalletUpgrade.push_back(hash);
                }

                //// debug print
                //printf("LoadWallet  %s\n", wtx.GetHash().ToString().c_str());
                //printf(" %12I64d  %s  %s  %s\n",
                //    wtx.vout[0].nValue,
                //    DateTimeStrFormat("%x %H:%M:%S", wtx.GetBlockTime()).c_str(),
                //    wtx.hashBlock.ToString().substr(0,20).c_str(),
                //    wtx.mapValue["message"].c_str());
            }
            else if (strType == "acentry")
            {
                string strAccount;
                ssKey >> strAccount;
                uint64 nNumber;
                ssKey >> nNumber;
                if (nNumber > nAccountingEntryNumber)
                    nAccountingEntryNumber = nNumber;
            }
            else if (strType == "key" || strType == "wkey")
            {
                

                vector<unsigned char> vchPubKey;
                ssKey >> vchPubKey;
                CKey key;
                if (strType == "key")
                {
                    CPrivKey pkey;
                    ssValue >> pkey;
                    key.SetPrivKey(pkey);
                }
                else
                {
                    CWalletKey wkey;
                    ssValue >> wkey;
                    key.SetPrivKey(wkey.vchPrivKey);
                }
                if (!pwallet->LoadKey(key))
                    return DB_CORRUPT;
            }
            else if (strType == "mkey")
            {
                unsigned int nID;
                ssKey >> nID;
                CMasterKey kMasterKey;
                ssValue >> kMasterKey;
                if(pwallet->mapMasterKeys.count(nID) != 0)
                    return DB_CORRUPT;
                pwallet->mapMasterKeys[nID] = kMasterKey;
                if (pwallet->nMasterKeyMaxID < nID)
                    pwallet->nMasterKeyMaxID = nID;
            }
            else if (strType == "ckey")
            {
                vector<unsigned char> vchPubKey;
                ssKey >> vchPubKey;
                vector<unsigned char> vchPrivKey;
                ssValue >> vchPrivKey;
                if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
                    return DB_CORRUPT;
            }
            else if (strType == "defaultkey")
            {
                ssValue >> pwallet->vchDefaultKey;
            }
            else if (strType == "pool")
            {
                

                int64 nIndex;
                ssKey >> nIndex;
                pwallet->setKeyPool.insert(nIndex);
            }
            else if (strType == "version")
            {
                ssValue >> nFileVersion;
                if (nFileVersion == 10300)
                    nFileVersion = 300;
            }
            else if (strType == "setting")
            {
                string strKey;
                ssKey >> strKey;

                // Options
#ifndef GUI
                if (strKey == "fGenerateBitcoins")  ssValue >> fGenerateBitcoins;
#endif
                if (strKey == "nTransactionFee")    ssValue >> nTransactionFee;
                if (strKey == "fLimitProcessors")   ssValue >> fLimitProcessors;
                if (strKey == "nLimitProcessors")   ssValue >> nLimitProcessors;
                if (strKey == "fMinimizeToTray")    ssValue >> fMinimizeToTray;
                if (strKey == "fMinimizeOnClose")   ssValue >> fMinimizeOnClose;
                if (strKey == "fUseProxy")          ssValue >> fUseProxy;
                if (strKey == "addrProxy")          ssValue >> addrProxy;
                if (fHaveUPnP && strKey == "fUseUPnP")           ssValue >> fUseUPnP;
            }
            else if (strType == "minversion")
            {
                int nMinVersion = 0;
                ssValue >> nMinVersion;
                if (nMinVersion > VERSION)
                    return DB_TOO_NEW;
            }
        }
        pcursor->close();
    }

    BOOST_FOREACH(uint256 hash, vWalletUpgrade)
        WriteTx(hash, pwallet->mapWallet[hash]);

    printf("nFileVersion = %d\n", nFileVersion);
    printf("fGenerateBitcoins = %d\n", fGenerateBitcoins);
    printf("nTransactionFee = %" PRI64d "\n", nTransactionFee);
    printf("fMinimizeToTray = %d\n", fMinimizeToTray);
    printf("fMinimizeOnClose = %d\n", fMinimizeOnClose);
    printf("fUseProxy = %d\n", fUseProxy);
    printf("addrProxy = %s\n", addrProxy.ToString().c_str());
    if (fHaveUPnP)
        printf("fUseUPnP = %d\n", fUseUPnP);


    // Upgrade
    if (nFileVersion < VERSION)
    {
        // Get rid of old debug.log file in current directory
        if (nFileVersion <= 105 && !pszSetDataDir[0])
            unlink("debug.log");

        WriteVersion(VERSION);
    }


    return DB_LOAD_OK;
}

void ThreadFlushWalletDB(void* parg)
{
    const string& strFile = ((const string*)parg)[0];
    static bool fOneThread;
    if (fOneThread)
        return;
    fOneThread = true;
    if (mapArgs.count("-noflushwallet"))
        return;

    unsigned int nLastSeen = nWalletDBUpdated;
    unsigned int nLastFlushed = nWalletDBUpdated;
    int64 nLastWalletUpdate = GetTime();
    while (!fShutdown)
    {
        Sleep(500);

        if (nLastSeen != nWalletDBUpdated)
        {
            nLastSeen = nWalletDBUpdated;
            nLastWalletUpdate = GetTime();
        }

        if (nLastFlushed != nWalletDBUpdated && GetTime() - nLastWalletUpdate >= 2)
        {
            TRY_CRITICAL_BLOCK(cs_db)
            {
                // Don't do this if any databases are in use
                int nRefCount = 0;
                map<string, int>::iterator mi = mapFileUseCount.begin();
                while (mi != mapFileUseCount.end())
                {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0 && !fShutdown)
                {
                    map<string, int>::iterator mi = mapFileUseCount.find(strFile);
                    if (mi != mapFileUseCount.end())
                    {
                        printf("%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
                        printf("Flushing wallet.dat\n");
                        nLastFlushed = nWalletDBUpdated;
                        int64 nStart = GetTimeMillis();

                        // Flush wallet.dat so it's self contained
                        CloseDb(strFile);
                        dbenv->txn_checkpoint(0, 0, 0);
                        dbenv->lsn_reset(strFile.c_str(), 0);

                        mapFileUseCount.erase(mi++);
                        printf("Flushed wallet.dat %" PRI64d "ms\n", GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

bool BackupWallet(const CWallet& wallet, const string& strDest)
{
    if (!wallet.fFileBacked)
        return false;
    while (!fShutdown)
    {
        CRITICAL_BLOCK(cs_db)
        {
            if (!mapFileUseCount.count(wallet.strWalletFile) || mapFileUseCount[wallet.strWalletFile] == 0)
            {
                // Flush log data to the dat file
                CloseDb(wallet.strWalletFile);
                dbenv->txn_checkpoint(0, 0, 0);
                dbenv->lsn_reset(wallet.strWalletFile.c_str(), 0);
                mapFileUseCount.erase(wallet.strWalletFile);

                // Copy wallet.dat
                filesystem::path pathSrc(GetDataDir() + "/" + wallet.strWalletFile);
                filesystem::path pathDest(strDest);
                if (filesystem::is_directory(pathDest))
                    pathDest = pathDest / wallet.strWalletFile;
#if BOOST_VERSION >= 104000
                filesystem::copy_file(pathSrc, pathDest, filesystem::copy_option::overwrite_if_exists);
#else
                filesystem::copy_file(pathSrc, pathDest);
#endif
                printf("copied wallet.dat to %s\n", pathDest.string().c_str());

                return true;
            }
        }
        Sleep(100);
    }
    return false;
}
