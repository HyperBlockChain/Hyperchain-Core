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
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_DB_H
#define BITCOIN_DB_H

#include "headers/inter_public.h"
#include "key.h"
#include "block.h"

#include <map>
#include <string>
#include <vector>

#include <db_cxx.h>

class CTxIndex;
class CDiskBlockIndex;
class CDiskTxPos;
class COutPoint;
class CAddress;
class CWalletTx;
class CWallet;
class CAccount;
class CAccountingEntry;
class CBlockLocator;
class CBlock;
class CBlockIndex;
class BLOCKTRIPLEADDRESS;
template<class T>
class shared_ptr_proxy;


extern unsigned int nWalletDBUpdated;
extern DbEnv* dbenv;


extern void DBFlush(bool fShutdown);
void ThreadFlushWalletDB(void* parg);
bool BackupWallet(const CWallet& wallet, const std::string& strDest);

#if !defined CBlockIndexSP
using CBlockIndexSP = shared_ptr_proxy<CBlockIndex>;
#endif


class CDB
{
protected:
    Db* pdb;
    std::string strFile;
    std::vector<DbTxn*> vTxn;
    bool fReadOnly;

    explicit CDB(const char* pszFile, const char* pszMode="r+");
    ~CDB() { Close(); }
public:
    void Close();
private:
    CDB(const CDB&);
    void operator=(const CDB&);

protected:

    bool Load(const std::string& key, const uint256& hash, std::function<bool(CDataStream&, CDataStream&)> f)
    {
        // Get database cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        // Load mapBlockIndex
        unsigned int fFlags = DB_SET_RANGE;
        for (; !fShutdown;) {
            // Read next record
            CDataStream ssKey;
            if (fFlags == DB_SET_RANGE)
                ssKey << make_pair(key, hash);
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
            fFlags = DB_NEXT;
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;

            // Unserialize
            string strType;
            uint256 hash;
            ssKey >> strType;

            if (strType == key) {
                if (!f(ssKey, ssValue)) break;
            }
            else {
                break;
            }
        }
        pcursor->close();

        return true;
    }

    bool Load(const std::string& key, std::function<bool(CDataStream&, CDataStream&)> f)
    {
        return Load(key, uint256(0), f);
    }

    template<typename K, typename T>
    bool Read(const K& key, T& value)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Read
        Dbt datValue;
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pdb->get(GetTxn(), &datKey, &datValue, 0);
        memset(datKey.get_data(), 0, datKey.get_size());
        if (datValue.get_data() == NULL)
            return false;

        // Unserialize value
        CDataStream ssValue((char*)datValue.get_data(), (char*)datValue.get_data() + datValue.get_size(), SER_DISK);
        ssValue >> value;

        // Clear and free memory
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datValue.get_data());
        return (ret == 0);
    }

    template<typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite=true)
    {
        if (!pdb)
            return false;
        if (fReadOnly)
            assert(!"Write called on database in read-only mode");

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Value
        CDataStream ssValue(SER_DISK);
        ssValue.reserve(10000);
        ssValue << value;
        Dbt datValue(&ssValue[0], ssValue.size());

        // Write
        int ret = pdb->put(GetTxn(), &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

        // Clear memory in case it was a private key
        memset(datKey.get_data(), 0, datKey.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        return (ret == 0);
    }

    template<typename K>
    bool Erase(const K& key)
    {
        if (!pdb)
            return false;
        if (fReadOnly)
            assert(!"Erase called on database in read-only mode");

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Erase
        int ret = pdb->del(GetTxn(), &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0 || ret == DB_NOTFOUND);
    }

    template<typename K>
    bool Exists(const K& key)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Exists
        int ret = pdb->exists(GetTxn(), &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0);
    }

    Dbc* GetCursor()
    {
        if (!pdb)
            return NULL;
        Dbc* pcursor = NULL;
        int ret = pdb->cursor(NULL, &pcursor, 0);
        if (ret != 0)
            return NULL;
        return pcursor;
    }

    int ReadAtCursor(Dbc* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags=DB_NEXT)
    {
        // Read at cursor
        Dbt datKey;
        if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datKey.set_data(&ssKey[0]);
            datKey.set_size(ssKey.size());
        }
        Dbt datValue;
        if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datValue.set_data(&ssValue[0]);
            datValue.set_size(ssValue.size());
        }
        datKey.set_flags(DB_DBT_MALLOC);
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pcursor->get(&datKey, &datValue, fFlags);
        if (ret != 0)
            return ret;
        else if (datKey.get_data() == NULL || datValue.get_data() == NULL)
            return 99999;

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char*)datKey.get_data(), datKey.get_size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datValue.get_data(), datValue.get_size());

        // Clear and free memory
        memset(datKey.get_data(), 0, datKey.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datKey.get_data());
        free(datValue.get_data());
        return 0;
    }

    DbTxn* GetTxn()
    {
        if (!vTxn.empty())
            return vTxn.back();
        else
            return NULL;
    }

public:
    bool TxnBegin()
    {
        if (!pdb)
            return false;
        DbTxn* ptxn = NULL;
        int ret = dbenv->txn_begin(GetTxn(), &ptxn, DB_TXN_NOSYNC);
        if (!ptxn || ret != 0)
            return false;
        vTxn.push_back(ptxn);
        return true;
    }

    bool TxnCommit()
    {
        if (!pdb)
            return false;
        if (vTxn.empty())
            return false;
        int ret = vTxn.back()->commit(0);
        vTxn.pop_back();
        return (ret == 0);
    }

    bool TxnAbort()
    {
        if (!pdb)
            return false;
        if (vTxn.empty())
            return false;
        int ret = vTxn.back()->abort();
        vTxn.pop_back();
        return (ret == 0);
    }

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(std::string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(std::string("version"), nVersion);
    }
};






class CTxDB_Wrapper;
class CTxDB : public CDB
{
public:
    friend class CTxDB_Wrapper;

private:
    CTxDB(const char* pszMode = "r+") : CDB("blkindex.dat", pszMode) { }
    CTxDB(const CTxDB&);
    void operator=(const CTxDB&);

 public:
    bool ReadTxIndex(const uint256& hash, CTxIndex& txindex);
    bool UpdateTxIndex(const uint256& hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(const uint256& hash);
    bool ReadOwnerTxes(const uint160& hash160, int nHeight, std::vector<CTransaction>& vtx);
    bool ReadDiskTx(const uint256& hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(const uint256& hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint& outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint& outpoint, CTransaction& tx);

    bool ReadBlockIndex(const uint256& hash, CDiskBlockIndex& blockindex);
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool EraseBlockIndex(uint256 hash);
    bool ReadHashBestChain(uint256& hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);
    

    bool ReadAddrMaxChain(T_LOCALBLOCKADDRESS& addrMax);
    bool WriteAddrMaxChain(const T_LOCALBLOCKADDRESS& addrMax);

    bool ReadBestInvalidWork(CBigNum& bnBestInvalidWork);
    bool WriteBestInvalidWork(CBigNum bnBestInvalidWork);
    bool LoadBlockIndex();


    bool ReadSP(const uint256& hash, CBlockIndexSP &blockindex);
    bool WriteSP(const CBlockIndex *blockindex);

protected:
    CBlockIndexSP ConstructBlockIndex(CDiskBlockIndex& diskindex);

private:
    bool CheckBestBlockIndex(CBlockIndexSP pIndex);
};

extern thread_local int tls_db_opened_count;
extern thread_local CTxDB *tls_txdb_instance;

class CTxDB_Wrapper
{
public:
    CTxDB_Wrapper(const char* pszMode = "r+")
    {
        if (tls_db_opened_count > 0) {
            _dbptr = tls_txdb_instance;
            tls_db_opened_count++;
        }
        else {
            _dbptr = new CTxDB(pszMode);
            tls_db_opened_count = 1;
            tls_txdb_instance = _dbptr;
        }
    }

    ~CTxDB_Wrapper()
    {
        tls_db_opened_count--;
        if (tls_db_opened_count == 0 && tls_txdb_instance) {
            delete tls_txdb_instance;
            tls_txdb_instance = nullptr;
        }
    }

    inline bool TxnBegin() { return _dbptr->TxnBegin(); }
    inline bool TxnCommit() { return _dbptr->TxnCommit(); }
    inline bool TxnAbort() { return _dbptr->TxnAbort(); }
    inline bool ReadVersion(int& nVersion) { return _dbptr->ReadVersion(nVersion); }
    inline bool WriteVersion(int nVersion) { return _dbptr->WriteVersion(nVersion); }
    inline void Close() { _dbptr->Close(); }

    inline bool ReadTxIndex(const uint256& hash, CTxIndex& txindex) { return _dbptr->ReadTxIndex(hash, txindex); }
    inline bool UpdateTxIndex(const uint256& hash, const CTxIndex& txindex) { return _dbptr->UpdateTxIndex(hash, txindex); }
    inline bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight) { return _dbptr->AddTxIndex(tx, pos, nHeight); }
    inline bool EraseTxIndex(const CTransaction& tx) { return _dbptr->EraseTxIndex(tx); }
    inline bool ContainsTx(const uint256& hash) { return _dbptr->ContainsTx(hash); }
    inline bool ReadOwnerTxes(uint160& hash160, int nHeight, std::vector<CTransaction>& vtx) { return _dbptr->ReadOwnerTxes(hash160, nHeight, vtx); }
    inline bool ReadDiskTx(uint256& hash, CTransaction& tx, CTxIndex& txindex) { return _dbptr->ReadDiskTx(hash, tx, txindex); }
    inline bool ReadDiskTx(uint256& hash, CTransaction& tx) { return _dbptr->ReadDiskTx(hash, tx); }
    inline bool ReadDiskTx(COutPoint& outpoint, CTransaction& tx, CTxIndex& txindex) {
        return  _dbptr->ReadDiskTx(outpoint, tx, txindex);
    }
    inline bool ReadDiskTx(COutPoint& outpoint, CTransaction& tx) { return _dbptr->ReadDiskTx(outpoint, tx); }

    inline bool ReadBlockIndex(const uint256& hash, CDiskBlockIndex& blockindex) { return _dbptr->ReadBlockIndex(hash, blockindex); }
    inline bool WriteBlockIndex(const CDiskBlockIndex& blockindex) { return _dbptr->WriteBlockIndex(blockindex); }
    inline bool EraseBlockIndex(uint256& hash) { return _dbptr->EraseBlockIndex(hash); }
    inline bool ReadHashBestChain(uint256& hashBestChain) { return _dbptr->ReadHashBestChain(hashBestChain); }
    inline bool WriteHashBestChain(uint256& hashBestChain) { return _dbptr->WriteHashBestChain(hashBestChain); }
    

    inline bool ReadAddrMaxChain(T_LOCALBLOCKADDRESS& addrMax) { return _dbptr->ReadAddrMaxChain(addrMax); }
    inline bool WriteAddrMaxChain(const T_LOCALBLOCKADDRESS& addrMax) { return _dbptr->WriteAddrMaxChain(addrMax); }

    inline bool ReadBestInvalidWork(CBigNum& bnBestInvalidWork) { return _dbptr->ReadBestInvalidWork(bnBestInvalidWork); }
    inline bool WriteBestInvalidWork(CBigNum bnBestInvalidWork) { return _dbptr->WriteBestInvalidWork(bnBestInvalidWork); }
    inline bool LoadBlockIndex() { return _dbptr->LoadBlockIndex(); }


    inline bool ReadSP(const uint256& hash, CBlockIndexSP &blockindex) { return _dbptr->ReadSP(hash, blockindex); }
    inline bool WriteSP(const CBlockIndex *blockindex) { return _dbptr->WriteSP(blockindex); }

private:
    CTxDB* _dbptr = nullptr;
};


class CBlockDB : public CDB
{
public:
    CBlockDB(const char* pszMode = "r+", const char* filename = "block.dat") : CDB(filename, pszMode) { }
private:
    CBlockDB(const CBlockDB&);
    void operator=(const CBlockDB&);
public:
    bool LoadBlockUnChained();
    bool LoadBlockUnChained(const uint256& hash, std::function<bool(CDataStream&, CDataStream&)> f);
    bool ReadBlock(const uint256& hash, CBlock& block);
    bool WriteBlock(const CBlock& block);
    bool WriteBlock(const uint256& hash, const CBlock& block);
    bool EraseBlock(uint256 hash);
};

class COrphanBlockDB : public CBlockDB
{
public:
    COrphanBlockDB(const char* pszMode = "cr+") : CBlockDB(pszMode, "orphanblock.dat") { }
private:
    COrphanBlockDB(const COrphanBlockDB&);
    void operator=(const COrphanBlockDB&);
};


class CBlockTripleAddressDB : public CDB
{
public:
    CBlockTripleAddressDB(const char* pszMode = "r+") : CDB("blocktripleaddress.dat", pszMode) { }
private:
    CBlockTripleAddressDB(const CBlockTripleAddressDB&);
    void operator=(const CBlockTripleAddressDB&);
public:
    bool LoadBlockTripleAddress();

    bool ReadHID(std::set<uint32_t>& setHID);
    bool WriteHID(uint32 hid);

    bool ReadBlockTripleAddress(const uint256& hash, BLOCKTRIPLEADDRESS& addr);
    bool WriteBlockTripleAddress(const uint256& hash, const BLOCKTRIPLEADDRESS& addr);
    bool EraseBlockTripleAddress(const uint256& hash);
};


class CAddrDB : public CDB
{
public:
    CAddrDB(const char* pszMode="r+") : CDB("addr.dat", pszMode) { }
private:
    CAddrDB(const CAddrDB&);
    void operator=(const CAddrDB&);
public:
    bool WriteAddress(const CAddress& addr);
    bool EraseAddress(const CAddress& addr);
    bool LoadAddresses();
};

bool LoadAddresses();



class CKeyPool
{
public:
    int64 nTime;
    std::vector<unsigned char> vchPubKey;

    CKeyPool()
    {
        nTime = GetTime();
    }

    CKeyPool(const std::vector<unsigned char>& vchPubKeyIn)
    {
        nTime = GetTime();
        vchPubKey = vchPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    )
};




enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
};

class CWalletDB : public CDB
{
public:
    CWalletDB(std::string strFilename, const char* pszMode="r+") : CDB(strFilename.c_str(), pszMode)
    {
    }
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);
public:
    bool ReadName(const std::string& strAddress, std::string& strName)
    {
        strName = "";
        return Read(std::make_pair(std::string("name"), strAddress), strName);
    }

    bool WriteName(const std::string& strAddress, const std::string& strName);

    bool EraseName(const std::string& strAddress);

    bool ReadTx(uint256 hash, CWalletTx& wtx)
    {
        return Read(std::make_pair(std::string("tx"), hash), wtx);
    }

    bool WriteTx(uint256 hash, const CWalletTx& wtx)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("tx"), hash), wtx);
    }

    bool EraseTx(uint256 hash)
    {
        nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("tx"), hash));
    }

    bool ReadKey(const std::vector<unsigned char>& vchPubKey, CPrivKey& vchPrivKey)
    {
        vchPrivKey.clear();
        return Read(std::make_pair(std::string("key"), vchPubKey), vchPrivKey);
    }

    bool WriteKey(const std::vector<unsigned char>& vchPubKey, const CPrivKey& vchPrivKey)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("key"), vchPubKey), vchPrivKey, false);
    }

    bool WriteCryptedKey(const std::vector<unsigned char>& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, bool fEraseUnencryptedKey = true)
    {
        nWalletDBUpdated++;
        if (!Write(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false))
            return false;
        if (fEraseUnencryptedKey)
        {
            Erase(std::make_pair(std::string("key"), vchPubKey));
            Erase(std::make_pair(std::string("wkey"), vchPubKey));
        }
        return true;
    }

    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
    }

    bool WriteBestBlock(const CBlockLocator& locator)
    {
        nWalletDBUpdated++;
        return Write(std::string("bestblock"), locator);
    }

    bool ReadBestBlock(CBlockLocator& locator)
    {
        return Read(std::string("bestblock"), locator);
    }

    bool ReadDefaultKey(std::vector<unsigned char>& vchPubKey)
    {
        vchPubKey.clear();
        return Read(std::string("defaultkey"), vchPubKey);
    }

    bool WriteDefaultKey(const std::vector<unsigned char>& vchPubKey)
    {
        nWalletDBUpdated++;
        return Write(std::string("defaultkey"), vchPubKey);
    }

    bool ReadPool(int64 nPool, CKeyPool& keypool)
    {
        return Read(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool WritePool(int64 nPool, const CKeyPool& keypool)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool ErasePool(int64 nPool)
    {
        nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("pool"), nPool));
    }

    template<typename T>
    bool ReadSetting(const std::string& strKey, T& value)
    {
        return Read(std::make_pair(std::string("setting"), strKey), value);
    }

    template<typename T>
    bool WriteSetting(const std::string& strKey, const T& value)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("setting"), strKey), value);
    }

    bool ReadAccount(const std::string& strAccount, CAccount& account);
    bool WriteAccount(const std::string& strAccount, const CAccount& account);
    bool WriteAccountingEntry(const CAccountingEntry& acentry);
    int64 GetAccountCreditDebit(const std::string& strAccount);
    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries);

    int LoadWallet(CWallet* pwallet);
};

#endif
